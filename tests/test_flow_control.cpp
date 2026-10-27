
#include "test_connection.hpp"
#include <moko3/moko3.hpp>

using namespace hidi;
using namespace std::chrono_literals;

// свой сервер, так как дефолтный - эхо
struct connect_capable_server : h2server {
  using h2server::h2server;
  dd::task<http_response> handle_request(http_request, request_context) override {
    co_return http_response{.status = 200};
  }
};

static dd::task<void> extended_connect_ordering_body(internet_address addr, any_io_context_ref ioctx);

TEST("extended_connect_protocol_header_ordering") {
  connect_capable_server server(h2server_options{}, make_asio_io_context());
  internet_address addr(asio::ip::address_v4::loopback(), 0);
  addr = server.listen({.addr = addr, .reuse_address = true});
  bool ended = false;
  std::exception_ptr ex;
  (void)run_test("extended_connect_protocol_header_ordering",
                 extended_connect_ordering_body(addr, *&server.ioctx()), ended, ex);
  deadline_t deadline =
      deadline_after(moko3::get_testbox().test_timeout("extended_connect_protocol_header_ordering"));
  fuzzing::fuzzer fuz(moko3::get_testbox().randg());
  fuz.run_until(deadline, ended, server.ioctx());
  if (ex)
    std::rethrow_exception(std::move(ex));
}

dd::task<void> extended_connect_ordering_body(internet_address addr, any_io_context_ref ioctx) {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  // :protocol посередине псевдохедеров
  std::vector<header> hdrs{{":method", "CONNECT"},
                           {":protocol", "websocket"},
                           {":scheme", "https"},
                           {":authority", addr.address().to_string()},
                           {":path", "/ws"}};
  auto raw = client.encode_headers(hdrs);
  // send_raw_hdr для сохранения порядка хедеров
  co_await client.send_raw_hdr(1, raw, /*end_stream=*/true);

  auto rsp = co_await client.receive_rsp(testdeadline(5s));
  REQUIRE(rsp.find_hdr(":status") == "200");
}

// Тело запроса больше окна. Писатель ждёт, пока окно не увеличится, и продолжает отправку после каждого
// события, которое его увеличивает (без WINDOW_UPDATE / SETTINGS он не должен просыпаться и писать)
CLIENT_TEST("blocked request body resumes when window grows") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  constexpr uint32_t WINDOW = INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL;
  constexpr uint32_t EXTRA = 100;
  http_request req;
  req.method = http_method_e::PUT;
  req.path = "/";
  req.authority = client.get_remote().to_string();
  req.body.data.resize(WINDOW + EXTRA);
  auto h = client.send_request(std::move(req), deadline_after(10s)).start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  for (;;) {
    h2test_frame f = co_await server.receive_frame(deadline_after(5s));
    if (f.hdr.type != frame_e::HEADERS)
      continue;
    hpack::ignore_headers_block(server.get_inner_connection()->decoder, f.data);
    break;
  }
  size_t received = 0;
  while (received < WINDOW)
    received += (co_await server.receive_data(1)).hdr.length;
  REQUIRE(received == WINDOW);
  // окна стрима и соединения исчерпаны
  co_await server.sync();

  SECTION("stream, then connection WINDOW_UPDATE") {
    co_await server.send_window_size_increment(1, EXTRA);
    co_await server.sync();
    co_await server.send_window_size_increment(0, EXTRA);
  }
  SECTION("connection, then stream WINDOW_UPDATE") {
    co_await server.send_window_size_increment(0, EXTRA);
    co_await server.sync();
    co_await server.send_window_size_increment(1, EXTRA);
  }
  SECTION("SETTINGS_INITIAL_WINDOW_SIZE") {
    co_await server.send_window_size_increment(0, EXTRA);
    co_await server.sync();
    settings_t settings;
    settings.initial_stream_window_size += EXTRA;
    std::vector<byte_t> bytes;
    settings_frame::form(settings, std::back_inserter(bytes));
    co_await server.send_raw_frame(std::move(bytes));
    co_await server.receive_settings_ack();
  }
  bool end_stream = false;
  while (!end_stream) {
    h2test_frame f = co_await server.receive_data(1);
    received += f.hdr.length;
    end_stream = f.hdr.flags & flags::END_STREAM;
  }
  REQUIRE(received == WINDOW + EXTRA);
  std::vector<header> ok{{":status", "200"}};
  co_await server.send_rsp(1, ok);
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(h.promise().result_or_rethrow().status == 200);
}

static streaming_body_t empty_body(request_context) {
  co_return;
}

// потоковый обработчик, который начинает читать тело только по команде теста
struct slow_reader_server : h2server {
  using h2server::h2server;
  bool start_reading = false;
  size_t read_bytes = 0;

  bool answer_before_data(const http_request&) const noexcept override {
    return true;
  }
  dd::task<std::pair<http_response, bistream_body_maker_t>> handle_request_stream(http_request,
                                                                                  memory_queue_ptr q,
                                                                                  request_context) override {
    while (!start_reading)
      co_await yield_on_ioctx(*&ioctx());
    for (;;) {
      bytes_t chunk = co_await q->next_chunk();
      if (chunk.empty())
        break;
      read_bytes += chunk.size();
    }
    co_return {http_response{.status = 200}, &empty_body};
  }
  dd::task<http_response> handle_request(http_request, request_context) override {
    co_return http_response{.status = 200};
  }
};

// окно стрима минимально возможное, чтобы его легко было исчерпать
constexpr inline uint32_t SLOW_READER_WINDOW = 65'535;

static dd::task<test_h2connection> start_streaming_request(internet_address addr, any_io_context_ref ioctx) {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);
  std::vector<header> hdrs{
      {":method", "POST"},
      {":path", "/"},
      {":scheme", "http"},
      {":authority", addr.address().to_string()},
  };
  co_await client.send_headers(1, std::move(hdrs), /*endstream=*/false);
  // исчерпывает окно стрима
  co_await client.send_data(1, std::string(SLOW_READER_WINDOW, 'a'), /*end_stream=*/false);
  co_return client;
}

static dd::task<void> unread_body_limited_body(slow_reader_server& server, internet_address addr,
                                               any_io_context_ref ioctx) {
  auto client = co_await start_streaming_request(addr, ioctx);
  // обработчик не читает, поэтому окно не возвращено и лишний байт нарушает его
  co_await client.send_data(1, "b", /*end_stream=*/true);
  co_await client.receive_rst_stream(1, errc_e::FLOW_CONTROL_ERROR);
  REQUIRE(server.read_bytes == 0);
  // иначе обработчик ждёт вечно и сервер не остановится
  server.start_reading = true;
}

static dd::task<void> read_returns_window_body(slow_reader_server& server, internet_address addr,
                                               any_io_context_ref ioctx) {
  auto client = co_await start_streaming_request(addr, ioctx);
  server.start_reading = true;
  for (;;) {
    h2test_frame f = co_await client.receive_frame(deadline_after(5s));
    if (f.hdr.type == frame_e::WINDOW_UPDATE && f.hdr.streamid == 1)
      break;
  }
  co_await client.send_data(1, "b", /*end_stream=*/true);
  auto rsp = co_await client.receive_rsp();
  REQUIRE(rsp.find_hdr(":status") == "200");
  REQUIRE(server.read_bytes == SLOW_READER_WINDOW + 1);
}

static void run_slow_reader_test(std::string_view name,
                                 dd::task<void> (*body)(slow_reader_server&, internet_address,
                                                        any_io_context_ref)) {
  slow_reader_server server(h2server_options{.stream_window_size = SLOW_READER_WINDOW},
                            make_asio_io_context());
  internet_address addr(asio::ip::address_v4::loopback(), 0);
  addr = server.listen({.addr = addr, .reuse_address = true});
  bool ended = false;
  std::exception_ptr ex;
  (void)run_test(name, body(server, addr, *&server.ioctx()), ended, ex);
  fuzzing::fuzzer fuz(moko3::get_testbox().randg());
  fuz.run_until(deadline_after(moko3::get_testbox().test_timeout(name)), ended, server.ioctx());
  if (ex)
    std::rethrow_exception(std::move(ex));
}

// непрочитанное потоковое тело не может превысить окно стрима: окно возвращается только по мере чтения
TEST("unread streaming body is limited by stream window") {
  run_slow_reader_test("unread streaming body is limited by stream window", &unread_body_limited_body);
}

TEST("reading streaming body returns stream window") {
  run_slow_reader_test("reading streaming body returns stream window", &read_returns_window_body);
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
