#pragma once

#include <source_location>
#include <string_view>

#include <hpack/hpack.hpp>
#include <moko3/moko3.hpp>

#include <map>
#include <set>

#include "hidi/h2protocol.hpp"
#include "hidi/utils/deadline.hpp"
#include "hidi/http_body_bytes.hpp"
#include "hidi/asio/ssl_context.hpp"
#include "hidi/asio/awaiters.hpp"
#include "hidi/h2client.hpp"
#include "hidi/h2connection.hpp"
#include "hidi/h2server.hpp"
#include "hidi/asio/asio_executor.hpp"
#include "fuzzer.hpp"

#include <kelcoro/task.hpp>

#include "servers/echo_server.hpp"

using namespace std::chrono_literals;

namespace hidi {

inline constexpr auto DEFAULT_CONN_TIMEOUT = std::chrono::seconds(10);

// TLS контекст сервера с тестовым сертификатом (tests/test_server.crt)
server_ssl_context_ptr test_server_ssl_ctx();

struct h2test_frame {
  frame_header hdr = {};
  http_body_bytes data = {};

  // parses frame. First 9 bytes are header, all other - data
  static h2test_frame from_bytes(std::span<const byte_t> bytes) {
    h2test_frame f;
    f.hdr = frame_header::parse({bytes.data(), FRAME_HEADER_LEN});
    f.data.assign(bytes.begin() + FRAME_HEADER_LEN, bytes.end());
    return f;
  }
};

enum struct ping_e { RESPONSE = 1, ERROR = 2 };

enum struct window_e { RETURN = 0, SKIP = 1 };

using setting_id_e = settings_identifier_e;

struct header {
  std::string name;
  std::string value;
  bool indexed = true;

  bool operator==(const header& h) const noexcept {
    return name == h.name && value == h.value;
  }
  bool operator==(const http_header_t& h) const noexcept {
    return name == h.name() && value == h.value();
  }
};

inline deadline_t testdeadline(duration_t d) {
  // TODO if debugger preset - never
  return deadline_after(d);
}

// represents received HEADER + DATA frame
struct hdrs_and_data {
  uint32_t streamid = 0;    // streamid for both HEADERS and DATA frame
  bool end_stream = false;  // if END_STREAM flag was setted
  std::vector<header> headers = {};
  http_body_bytes body = {};
  std::optional<std::vector<header>> trailers = std::nullopt;

  std::string_view find_hdr(std::string_view name) {
    auto it = std::find_if(headers.begin(), headers.end(), [name](auto& v) { return v.name == name; });
    if (it != headers.end())
      return it->value;

    return {};
  }

  bool is_hdr_indexed(std::string_view name) {
    auto it = std::find_if(headers.begin(), headers.end(), [name](auto& v) { return v.name == name; });
    REQUIRE(it != headers.end());
    return it->indexed;
  }

  std::string_view body_strview() const noexcept {
    return std::string_view((const char*)body.data(), body.size());
  }
};

inline http_body_bytes body_from_sv(std::string_view view) {
  const byte_t* b = (const byte_t*)view.data();
  return http_body_bytes(b, b + view.size());
}

struct test_h2connection {
 private:
  h2connection_ptr con = nullptr;
  bool is_client_con = false;
  // local SETTINGS_MAX_FRAME_SIZE
  uint32_t m_maxFrameSize = FRAME_LEN_MAX;
  // local SETTINGS_HEADER_TABLE_SIZE
  std::optional<uint32_t> m_headerTabSize;
  // local SETTINGS_MAX_CONCURRENT_STREAMS
  uint32_t m_maxConcurrentStreams = 0x7fffffff;
  // принятые, но ещё не возвращённые через WINDOW_UPDATE байты (см. next_frame, answer_window_update)
  uint32_t m_unackedConnection = 0;
  std::unordered_map<stream_id_t, uint32_t> m_unackedStreams;
  // окно соединения, которое мы дали пиру (send_window_size_increment). DATA сверх него - ошибка пира
  int64_t m_connectionWindow = INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL;

 public:
  bool is_client() const noexcept {
    return is_client_con;
  }

  bool is_server() const noexcept {
    return !is_client_con;
  }

  test_h2connection() = default;
  test_h2connection(h2connection_ptr con, bool client) noexcept;

  test_h2connection(test_h2connection&& other) noexcept
      : con(std::exchange(other.con, nullptr)),
        is_client_con(other.is_client_con),
        m_maxFrameSize(other.m_maxFrameSize),
        m_headerTabSize(other.m_headerTabSize),
        m_maxConcurrentStreams(other.m_maxConcurrentStreams),
        m_unackedConnection(other.m_unackedConnection),
        m_unackedStreams(std::move(other.m_unackedStreams)),
        m_connectionWindow(other.m_connectionWindow) {
  }
  test_h2connection& operator=(test_h2connection&& other) noexcept {
    std::destroy_at(this);
    std::construct_at(this, std::move(other));
    return *this;
  }
  ~test_h2connection() {
    close();
  }

  dd::task<void> receive_client_magic(std::source_location = std::source_location::current());
  dd::task<void> send_client_magic();

  // ignores frame correctness, allowing to send incorrect frames for tests
  dd::task<void> send_frame(h2test_frame);
  dd::task<void> send_raw_frame(std::vector<byte_t>);
  // ignores any logic like control flow, window update, ping answer etc
  dd::task<h2test_frame> receive_frame(deadline_t, std::source_location = std::source_location::current());

  // если bool answer_window_update == true, то на пришедшие DATA отвечает WINDOW_UPDATE чтобы не сокращать
  // своё окно (и для соединения и для стрима). Как настоящие клиенты, окно возвращается по половине
  // начального, а не на каждый кадр: иначе при общем окне соединения пир дробит DATA на кадры по несколько
  // байт
  dd::task<h2test_frame> next_frame(deadline_t, ping_e, window_e = window_e::RETURN,
                                    std::source_location = std::source_location::current(),
                                    bool answer_window_update = false);

  // handles SETTINGS_HEADER_TABLE_SIZE, sets m_encoder and m_decoder into correct state
  dd::task<void> receive_and_check_settings(std::map<setting_id_e, uint32_t> expected,
                                            std::set<setting_id_e> unexpected,
                                            deadline_t = deadline_after(5s),
                                            std::source_location = std::source_location::current());

  // gets and validates settings frame, returns them.
  // handles only SETTINGS_HEADER_TABLE_SIZE, sets m_encoder and m_decoder into correct state
  dd::task<h2test_frame> receive_settings(deadline_t = deadline_after(5s),
                                          std::source_location = std::source_location::current());
  dd::task<void> receive_settings_ack(deadline_t = deadline_after(5s),
                                      std::source_location = std::source_location::current());
  dd::task<void> send_settings_ack();
  // sends default SETTINGS frame
  dd::task<void> send_settings();

  // waits ping request (not ACK ping frame), ignores WINDOW_UPDATE
  dd::task<uint64_t> receive_ping(deadline_t deadline = deadline_after(5s),
                                  std::source_location = std::source_location::current());
  // sends PING frame with request pong (ACK == false)
  dd::task<void> send_ping(uint64_t opaque_data);
  // sends PING frame answer (ACK == true)
  dd::task<void> send_pong(uint64_t opaque_data);

  // отправляет PING и ждёт ACK с тем же значением. Пир обрабатывает кадры по порядку, поэтому после возврата
  // всё отправленное ранее гарантировано обработано пиром. WINDOW_UPDATE пропускается, на PING-запросы шлётся
  // ответ,
  // любой другой кадр (HEADERS, DATA и т.д.) означает неправильное использование функции и завершает тест
  dd::task<void> sync(deadline_t deadline = deadline_after(5s),
                      std::source_location = std::source_location::current());

  dd::task<void> receive_goaway(stream_id_t last_streamid, errc_e error_code, ping_e ping,
                                deadline_t deadline = deadline_after(5s),
                                std::source_location = std::source_location::current());
  dd::task<void> send_goaway(stream_id_t last_streamid, errc_e error, std::string_view debug = {});

  dd::task<void> receive_rst_stream(stream_id_t streamid, errc_e, deadline_t = deadline_after(5s),
                                    std::source_location = std::source_location::current());
  dd::task<void> send_rst_stream(stream_id_t streamid, errc_e);

  dd::task<void> send_headers(stream_id_t streamid, std::vector<header> headers, bool endstream);

  // sends HEADERS frame and if `body` present - DATA frame. Sends END_STREAM only if `endstream` == true
  dd::task<void> send_req(stream_id_t streamid, std::vector<header> headers, http_body_bytes body = {},
                          bool endstream = true);
  // sends HEADERS frame and if `body` present - DATA frame. Sends END_STREAM only if `endstream` == true
  // ignores controlw flow rules, sends DATA always as one frame
  dd::task<void> send_rsp(stream_id_t streamid, std::vector<header> headers, http_body_bytes body = {},
                          bool endstream = true);

  // receives HEADERS frame and, if required, DATA frame.
  // do not support many DATA frame/parallel requests etc
  // returns streamid, if marked `end_stream`, decoded headers, untouched body bytes
  dd::task<hdrs_and_data> receive_req(deadline_t deadline = deadline_after(5s),
                                      std::source_location = std::source_location::current());

  // ждёт пока `count` запросов не придут и не будут полностью собраны
  dd::task<std::unordered_map<stream_id_t, hdrs_and_data>> receive_streams(
      size_t count, deadline_t deadline = deadline_after(5s),
      std::source_location loc = std::source_location::current());

  // same as `receive_req`, name different for better code readability
  dd::task<hdrs_and_data> receive_rsp(deadline_t deadline = deadline_after(5s),
                                      std::source_location loc = std::source_location::current()) {
    REQUIRE(is_client());
    return receive_req(deadline, loc);
  }

  dd::task<void> send_data(stream_id_t streamid, std::string_view body, bool end_stream);
  // sends HEADERS frame with raw `headers` bytes, does not check `headers` correctness
  // if `split` is true headers will be splitted into random count of CONTINUATION frames
  dd::task<void> send_raw_hdr(stream_id_t streamid, std::span<const byte_t> headers, bool end_stream = true,
                              bool split = false);
  dd::task<void> send_raw_continuation(stream_id_t streamid, std::span<byte_t> headers, bool end_headers);

  // caller must send header (or encoder dyntab will be invalid)
  std::vector<byte_t> encode_headers(std::vector<header> hdrs);

  // receives data, handles DATA padding etc.
  // Note: hdr.length may be not equal to data.size(). data.size() - actual data, hdr.length includes padding
  // for control flow
  dd::task<h2test_frame> receive_data(stream_id_t streamid, deadline_t deadline = deadline_after(5s));

  dd::task<void> send_window_size_increment(stream_id_t streamid, uint32_t wind_incr);

  dd::task<void> wait_connection_dropped(deadline_t deadline = deadline_after(5s),
                                         std::source_location = std::source_location::current());

  void close();

  // makes sense only before sending SETTINGS frame, sets SETTINGS_MAX_CONCURRENT_STREAMS
  void set_max_concurrent_streams(uint32_t count) noexcept {
    m_maxConcurrentStreams = count;
  }

  // makes sense only before sending SETTINGS frame, sets SETTINGS_MAX_FRAME_SIZE
  void set_max_frame_size(uint32_t size) noexcept {
    m_maxFrameSize = size;
  }
  uint32_t get_max_frame_size() const noexcept {
    return m_maxFrameSize;
  }

  // makes sense only before sending SETTINGS frame, sets SETTINGS_HEADER_TABLE_SIZE
  void set_header_table_size(uint32_t size) {
    con->decoder.dyntab.set_user_protocol_max_size(size);
    m_headerTabSize = size;
  }

  h2connection_ptr get_inner_connection() const noexcept {
    return con;
  }
};

// connects to `addr`, returns tls connection after tls handshake if `io` is tls
inline dd::task<test_h2connection> fake_client_connection(
    any_io_context_ref io, endpoint addr, deadline_t deadline = deadline_after(DEFAULT_CONN_TIMEOUT),
    std::source_location = std::source_location::current()) {
  auto c = co_await io.create_connection_client({addr}, deadline);
  // для TLS это handshake, для TCP ничего не делает
  io_error_code ec;
  co_await c->handshake(ec, /*is_client=*/true);
  REQUIRE(!ec);
  co_return test_h2connection(new h2connection(std::move(c), *&io), /*client=*/true);
}

inline internet_address localhost() noexcept {
  return internet_address(asio::ip::address_v4::loopback(), 0);
}

// precondition: `client` is not connected
// returns fake server
// connects `client` into fake server and returns BEFORE http2 connection establishment
// and AFTER tls handshake
inline dd::task<test_h2connection> fake_server_session(any_io_context_ref io, server_endpoint addr,
                                                       h2client& client,
                                                       deadline_t deadline = deadline_after(10s)) {
  any_timer timer = io.create_timer();
  timer.set_callback([](bool canceled) {
    if (canceled)
      return;
    std::cout << "fake server session cannot be established, deadline reached!" << std::endl;
    std::abort();
  });
  timer.arm(deadline.tp);
  any_acceptor a = io.create_acceptor(addr.addr, addr.reuse_address);
  a.listen();
  io_error_code ec;
  client.try_connect(a.get_local_endpoint(), deadline).start_and_detach();
  any_connection_t tcpcon = co_await a.accept(ec);
  REQUIRE(!ec);
  // для TLS это handshake, для TCP ничего не делает
  co_await tcpcon->handshake(ec, /*is_client=*/false);
  REQUIRE(!ec);
  h2connection_ptr con = new h2connection(std::move(tcpcon), *&io);
  co_return test_h2connection(std::move(con), /*client*/ false);
}

inline dd::task<void> emulate_server_connection(test_h2connection& conn) {
  REQUIRE(conn.is_server());

  co_await conn.receive_client_magic();

  (void)co_await conn.receive_settings();
  co_await conn.send_settings();

  co_await conn.receive_settings_ack();
  co_await conn.send_settings_ack();
}

inline dd::task<void> emulate_client_connection(test_h2connection& conn) {
  REQUIRE(conn.is_client());
  co_await conn.send_client_magic();

  co_await conn.send_settings();
  (void)co_await conn.receive_settings();

  co_await conn.send_settings_ack();
  co_await conn.receive_settings_ack();
}

inline std::string source_location_msg_str(std::source_location loc) {
  return std::format("{}:{}:{}", loc.file_name(), loc.line(), loc.column());
}

inline void on_timeout_test_failure(std::source_location loc) {
  REQUIRE(false);
  // std::format("deadline expired in {}", source_location_msg_str(loc)));
}

// ioctx used only for yield
template <std::invocable PRED, typename ON_TIMEOUT = decltype(&on_timeout_test_failure)>
dd::task<void> wait_until(PRED pred, any_io_context_ref ctx, deadline_t deadline = deadline_after(5s),
                          std::source_location loc = std::source_location::current(),
                          ON_TIMEOUT on_timeout = &on_timeout_test_failure) {
  for (;;) {
    if constexpr (dd::co_awaitable<std::invoke_result_t<PRED>>) {
      if (co_await pred())
        co_return;
    } else {
      if (pred())
        co_return;
    }
    if (deadline.is_reached()) [[unlikely]] {
      on_timeout(loc);
      co_return;
    }
    co_await yield_on_ioctx(ctx);
  }
}

inline dd::job run_test(std::string_view testname, dd::task<void> test, bool& ended, std::exception_ptr& e) {
  on_scope_exit {
    ended = true;
  };
  try {
    co_await test;
  } catch (...) {
    e = std::current_exception();
  }
}

template <auto* Foo>
void server_test_impl(std::string_view name, moko3::section_info* section, server_ssl_context_ptr ssl,
                      bool buffer_writes) {
  echo_server server(h2server_options{},
                     make_asio_tls_io_context(ssl, tcp_connection_options{.buffer_writes = buffer_writes}));
  internet_address addr(asio::ip::address_v4::loopback(), /*port_num=*/0);
  addr = server.listen({.addr = addr, .reuse_address = true});
  bool test_ended = false;
  std::exception_ptr ex;
  (void)run_test(name, Foo(server, addr, *&server.ioctx(), section, /*is_tls_server=*/!!ssl), test_ended, ex);
  deadline_t deadline = deadline_after(moko3::get_testbox().test_timeout(name));
  fuzzing::fuzzer fuz(moko3::get_testbox().randg());
  fuz.run_until(deadline, test_ended, server.ioctx());
  if (ex)
    std::rethrow_exception(std::move(ex));
}

// как SERVER_TEST, но со своим сервером (НЕ эхо сервером)
template <typename Server>
void run_custom_server_test(moko3::section_info* _section, std::string_view name, h2server_options opts,
                            dd::task<void> (*body)(Server&, internet_address, any_io_context_ref)) {
  auto run = [&](server_ssl_context_ptr ssl, bool buffer_writes) {
    Server server(opts, make_asio_tls_io_context(std::move(ssl),
                                                 tcp_connection_options{.buffer_writes = buffer_writes}));
    internet_address addr(asio::ip::address_v4::loopback(), 0);
    addr = server.listen({.addr = addr, .reuse_address = true});
    bool ended = false;
    std::exception_ptr ex;
    (void)run_test(name, body(server, addr, *&server.ioctx()), ended, ex);
    fuzzing::fuzzer fuz(moko3::get_testbox().randg());
    fuz.run_until(deadline_after(moko3::get_testbox().test_timeout(name)), ended, server.ioctx());
    if (ex)
      std::rethrow_exception(std::move(ex));
  };
  SECTION("NO TLS") {
    SECTION("direct writes") {
      run(nullptr, false);
    }
    SECTION("buffered writes") {
      run(nullptr, true);
    }
  }
  SECTION("TLS") {
    SECTION("direct writes") {
      run(test_server_ssl_ctx(), false);
    }
    SECTION("buffered writes") {
      run(test_server_ssl_ctx(), true);
    }
  }
}

// клиент и фейковый сервер работают на одном io_context. Тест получает io контекст сервера: на нём
// fake_server_session создаёт acceptor (для TLS ему нужен серверный TLS контекст)
template <auto* Foo>
void client_test_impl(std::string_view name, moko3::section_info* toplvl_section, bool tls,
                      bool buffer_writes) {
  asio::io_context rawio;
  tcp_connection_options tcpopts{.buffer_writes = buffer_writes};
  any_io_context serverio = tls ? make_asio_tls_io_context(rawio, test_server_ssl_ctx(), tcpopts)
                                : make_asio_io_context(rawio, tcpopts);
  hidi::h2client client(endpoint(asio::ip::address_v4::loopback()), h2client_options{},
                        tls ? make_asio_tls_io_context(rawio, make_ssl_context_for_client({}), tcpopts)
                            : make_asio_io_context(rawio, tcpopts));
  bool test_ended = false;
  std::exception_ptr ex;
  (void)run_test(name, Foo(client, *&serverio, toplvl_section), test_ended, ex);
  deadline_t deadline = deadline_after(moko3::get_testbox().test_timeout(name));
  fuzzing::fuzzer fuz(moko3::get_testbox().randg());
  fuz.run_until(deadline, test_ended, client.ioctx());
  if (ex)
    std::rethrow_exception(std::move(ex));
}

template <auto* Foo>
void transport_test_impl(std::string_view name, moko3::section_info* section) {
  asio::io_context rawio;
  bool test_ended = false;
  std::exception_ptr ex;
  (void)run_test(name, Foo(rawio, section), test_ended, ex);
  deadline_t deadline = deadline_after(moko3::get_testbox().test_timeout(name));
  fuzzing::fuzzer fuz(moko3::get_testbox().randg());
  fuz.run_until(deadline, test_ended, rawio);
  if (ex)
    std::rethrow_exception(std::move(ex));
}

#define UNIQUE_TEST_NAME LOGIC_GUARDS_CONCAT(_test, __LINE__, __LINE__)

// after this macro expected function scope, which will use `server`, `addr`, `ioctx`
// and return dd::task<void>
// тест прогоняется без TLS и с TLS (код может использовать is_tls_server), каждый вариант дважды: с
// tcp_connection_options::buffer_writes и без
#define SERVER_TEST(NAME)                                                                                  \
  ::dd::task<void> UNIQUE_TEST_NAME(::hidi::echo_server& server, ::hidi::internet_address addr,            \
                                    ::hidi::any_io_context_ref ioctx, ::moko3::section_info* _section,     \
                                    bool is_tls_server);                                                   \
  TEST(NAME) {                                                                                             \
    SECTION("NO TLS", 0) {                                                                                 \
      SECTION("direct writes", 2) {                                                                        \
        ::hidi::server_test_impl<&UNIQUE_TEST_NAME>(NAME, _section, nullptr, false);                       \
      }                                                                                                    \
      SECTION("buffered writes", 3) {                                                                      \
        ::hidi::server_test_impl<&UNIQUE_TEST_NAME>(NAME, _section, nullptr, true);                        \
      }                                                                                                    \
    }                                                                                                      \
    SECTION("TLS", 1) {                                                                                    \
      SECTION("direct writes", 4) {                                                                        \
        ::hidi::server_test_impl<&UNIQUE_TEST_NAME>(NAME, _section, ::hidi::test_server_ssl_ctx(), false); \
      }                                                                                                    \
      SECTION("buffered writes", 5) {                                                                      \
        ::hidi::server_test_impl<&UNIQUE_TEST_NAME>(NAME, _section, ::hidi::test_server_ssl_ctx(), true);  \
      }                                                                                                    \
    }                                                                                                      \
  }                                                                                                        \
  ::dd::task<void> UNIQUE_TEST_NAME(::hidi::echo_server& server, ::hidi::internet_address addr,            \
                                    ::hidi::any_io_context_ref ioctx, ::moko3::section_info* _section,     \
                                    bool is_tls_server)

// after this macro expected function scope, which will use `client`, `ioctx`
// and return dd::task<void>
// тест прогоняется без TLS и с TLS, каждый вариант дважды: с tcp_connection_options::buffer_writes и без
#define CLIENT_TEST(NAME)                                                                       \
  ::dd::task<void> UNIQUE_TEST_NAME(::hidi::h2client& client, ::hidi::any_io_context_ref ioctx, \
                                    ::moko3::section_info* _section);                           \
  TEST(NAME) {                                                                                  \
    SECTION("NO TLS", 0) {                                                                      \
      SECTION("direct writes", 2) {                                                             \
        ::hidi::client_test_impl<&UNIQUE_TEST_NAME>(NAME, _section, false, false);              \
      }                                                                                         \
      SECTION("buffered writes", 3) {                                                           \
        ::hidi::client_test_impl<&UNIQUE_TEST_NAME>(NAME, _section, false, true);               \
      }                                                                                         \
    }                                                                                           \
    SECTION("TLS", 1) {                                                                         \
      SECTION("direct writes", 4) {                                                             \
        ::hidi::client_test_impl<&UNIQUE_TEST_NAME>(NAME, _section, true, false);               \
      }                                                                                         \
      SECTION("buffered writes", 5) {                                                           \
        ::hidi::client_test_impl<&UNIQUE_TEST_NAME>(NAME, _section, true, true);                \
      }                                                                                         \
    }                                                                                           \
  }                                                                                             \
  ::dd::task<void> UNIQUE_TEST_NAME(::hidi::h2client& client, ::hidi::any_io_context_ref ioctx, \
                                    ::moko3::section_info* _section)

// тест транспортного уровня (без HTTP/2). После макроса ожидается тело функции, возвращающей
// dd::task<void>, ему доступен `rawio` (asio::io_context), на котором создаются any_io_context, сокеты и т.д.
#define TRANSPORT_TEST(NAME)                                                                            \
  ::dd::task<void> UNIQUE_TEST_NAME(::boost::asio::io_context& rawio, ::moko3::section_info* _section); \
  TEST(NAME) {                                                                                          \
    ::hidi::transport_test_impl<&UNIQUE_TEST_NAME>(NAME, _section);                                     \
  }                                                                                                     \
  ::dd::task<void> UNIQUE_TEST_NAME(::boost::asio::io_context& rawio, ::moko3::section_info* _section)

}  // namespace hidi
