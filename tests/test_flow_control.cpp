
#include "test_connection.hpp"
#include <moko3/moko3.hpp>

using namespace hidi;
using namespace std::chrono_literals;

// как SERVER_TEST, но со своим сервером (НЕ эхо сервером)
template <typename Server>
static void run_custom_server_test(moko3::section_info* _section, std::string_view name,
                                   h2server_options opts,
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

// свой сервер, так как дефолтный - эхо
struct connect_capable_server : h2server {
  using h2server::h2server;
  dd::task<http_response> handle_request(http_request, request_context) override {
    co_return http_response{.status = 200};
  }
};

static dd::task<void> extended_connect_ordering_body(connect_capable_server&, internet_address addr,
                                                     any_io_context_ref ioctx);

TEST("extended_connect_protocol_header_ordering") {
  run_custom_server_test(_section, "extended_connect_protocol_header_ordering", h2server_options{},
                         &extended_connect_ordering_body);
}

dd::task<void> extended_connect_ordering_body(connect_capable_server&, internet_address addr,
                                              any_io_context_ref ioctx) {
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

static h2server_options slow_reader_options() {
  return h2server_options{.stream_window_size = SLOW_READER_WINDOW};
}

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

// непрочитанное потоковое тело не может превысить окно стрима: окно возвращается только по мере чтения
TEST("unread streaming body is limited by stream window") {
  run_custom_server_test(_section, "unread streaming body is limited by stream window", slow_reader_options(),
                         &unread_body_limited_body);
}

TEST("reading streaming body returns stream window") {
  run_custom_server_test(_section, "reading streaming body returns stream window", slow_reader_options(),
                         &read_returns_window_body);
}

static std::vector<header> post_headers(internet_address addr) {
  return {
      {":method", "POST"},
      {":path", "/"},
      {":scheme", "http"},
      {":authority", addr.address().to_string()},
  };
}

// принимает DATA ответа на `streamid`, пока не наберётся `bytes` байт (или до END_STREAM). Проверяет, что все
// байты равны `expected`. HEADERS ответа декодируются, чтобы декодер оставался синхронизирован
static dd::task<size_t> receive_response_data(test_h2connection& client, stream_id_t streamid, size_t bytes,
                                              byte_t expected, bool& end_stream) {
  size_t received = 0;
  end_stream = false;
  while (received < bytes && !end_stream) {
    h2test_frame f = co_await client.next_frame(deadline_after(5s), ping_e::RESPONSE, window_e::SKIP);
    REQUIRE(f.hdr.streamid == streamid);
    if (f.hdr.type == frame_e::HEADERS) {
      hpack::ignore_headers_block(client.get_inner_connection()->decoder, f.data);
      continue;
    }
    REQUIRE(f.hdr.type == frame_e::DATA);
    REQUIRE(std::ranges::all_of(f.data, [&](byte_t b) { return b == expected; }));
    received += f.data.size();
    end_stream = f.hdr.flags & flags::END_STREAM;
  }
  co_return received;
}

// Потоковый обработчик отвечает, не читая тело запроса (оно ему не нужно), и отпускает memory_queue. Клиент
// продолжает загружать тело, пока ответ ещё отправляется
struct ignore_body_server : h2server {
  using h2server::h2server;
  static constexpr size_t RESPONSE_SIZE = 100'000;

  bool answer_before_data(const http_request&) const noexcept override {
    return true;
  }
  static streaming_body_t response_body(request_context) {
    bytes_t body(RESPONSE_SIZE, byte_t('r'));
    co_yield std::span<const byte_t>(body);
  }
  dd::task<std::pair<http_response, bistream_body_maker_t>> handle_request_stream(http_request,
                                                                                  memory_queue_ptr,
                                                                                  request_context) override {
    co_return {http_response{.status = 200}, &response_body};
  }
  dd::task<http_response> handle_request(http_request, request_context) override {
    co_return http_response{.status = 200};
  }
};

static dd::task<void> ignored_body_upload(ignore_body_server&, internet_address addr,
                                          any_io_context_ref ioctx) {
  auto client = co_await fake_client_connection(ioctx, addr);
  // окно стримов клиента 65'535 по умолчанию, ответ в него не помещается
  co_await emulate_client_connection(client);
  co_await client.send_window_size_increment(0, 1 << 30);
  co_await client.send_headers(1, post_headers(addr), /*endstream=*/false);
  bool end_stream;
  size_t received = co_await receive_response_data(client, 1, SLOW_READER_WINDOW, byte_t('r'), end_stream);
  REQUIRE(received == SLOW_READER_WINDOW);
  // сервер ждёт окна посреди ответа. Тело запроса никто не читает, поэтому сервер возвращает окно при приёме:
  // загрузка больше окна стрима не останавливается и не нарушает его
  constexpr size_t PART = SLOW_READER_WINDOW - 1'000;
  for (int i = 0; i < 4; ++i) {
    co_await client.send_data(1, std::string(PART, 'a'), /*end_stream=*/false);
    for (;;) {
      h2test_frame f = co_await client.next_frame(deadline_after(5s), ping_e::RESPONSE, window_e::RETURN);
      REQUIRE(f.hdr.type == frame_e::WINDOW_UPDATE);
      if (f.hdr.streamid == 1)
        break;
    }
  }
  // принятое тело запроса не должно попасть в ответ
  co_await client.send_window_size_increment(1, ignore_body_server::RESPONSE_SIZE);
  received +=
      co_await receive_response_data(client, 1, ignore_body_server::RESPONSE_SIZE, byte_t('r'), end_stream);
  REQUIRE(end_stream);
  REQUIRE(received == ignore_body_server::RESPONSE_SIZE);
}

TEST("streaming handler may ignore request body while response is sent") {
  run_custom_server_test(_section, "streaming handler may ignore request body while response is sent",
                         slow_reader_options(), &ignored_body_upload);
}

// Ответ не зависит от тела запроса (например туннель в другой сервис закрылся) и заканчивается раньше, чем
// клиент дослал тело. Отдельный читатель тела должен получить оборванный EOF, а не ждать вечно
struct independent_reader_server : h2server {
  using h2server::h2server;
  bool reader_ended = false;
  bool reader_aborted = false;

  bool answer_before_data(const http_request&) const noexcept override {
    return true;
  }
  static streaming_body_t response_body(request_context) {
    bytes_t body(10, byte_t('r'));
    co_yield std::span<const byte_t>(body);
  }
  dd::job read_body(memory_queue_ptr q) {
    while (!q->last_chunk_received())
      (void)co_await q->next_chunk();
    reader_aborted = q->aborted();
    reader_ended = true;
  }
  dd::task<std::pair<http_response, bistream_body_maker_t>> handle_request_stream(http_request,
                                                                                  memory_queue_ptr q,
                                                                                  request_context) override {
    (void)read_body(std::move(q));
    co_return {http_response{.status = 200}, &response_body};
  }
  dd::task<http_response> handle_request(http_request, request_context) override {
    co_return http_response{.status = 200};
  }
};

static dd::task<void> response_ends_before_request(independent_reader_server& server, internet_address addr,
                                                   any_io_context_ref ioctx) {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);
  co_await client.send_headers(1, post_headers(addr), /*endstream=*/false);
  co_await client.send_data(1, "a", /*end_stream=*/false);
  bool end_stream;
  size_t received = co_await receive_response_data(client, 1, size_t(-1), byte_t('r'), end_stream);
  REQUIRE(end_stream);
  REQUIRE(received == 10);
  co_await wait_until([&] { return server.reader_ended; }, ioctx);
  REQUIRE(server.reader_aborted);
}

TEST("response ending before request body aborts body reader") {
  run_custom_server_test(_section, "response ending before request body aborts body reader",
                         slow_reader_options(), &response_ends_before_request);
}

// Клиент отменяет загрузку (например закрыта вкладка браузера), пока ответ ждёт окна стрима. Сервер больше
// ничего не отправляет в этот стрим, даже если окно затем растёт, а соединение продолжает работать
SERVER_TEST("client cancels response blocked on stream window") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);
  co_await client.send_window_size_increment(0, 1 << 30);
  co_await client.send_req(1, post_headers(addr), http_body_bytes(200'000, byte_t('a')));
  bool end_stream;
  size_t received = co_await receive_response_data(client, 1, SLOW_READER_WINDOW, byte_t('a'), end_stream);
  REQUIRE(received == SLOW_READER_WINDOW);
  co_await client.send_rst_stream(1, errc_e::CANCEL);
  co_await client.send_window_size_increment(1, 200'000);
  co_await client.send_req(3, post_headers(addr), http_body_bytes(10, byte_t('b')));
  // первым же кадром должен прийти ответ на стрим 3, а не DATA отменённого стрима
  auto rsp = co_await client.receive_rsp();
  REQUIRE(rsp.streamid == 3);
  REQUIRE(rsp.body == http_body_bytes(10, byte_t('b')));
  co_await client.sync();
}

// Клиент не читает ответ на стрим 1, и окно этого стрима (65'535 по умолчанию) исчерпано. Ответ на стрим 3
// всё равно приходит: писатель сервера не ждёт окна одного стрима
SERVER_TEST("exhausted window of one stream does not block other streams") {
  auto client = co_await fake_client_connection(ioctx, addr);
  // клиент ставит окно стримов 65'535 по умолчанию
  co_await emulate_client_connection(client);
  // окно соединения не ограничивает, только окно стрима
  co_await client.send_window_size_increment(0, 1 << 30);
  std::vector<header> hdrs{
      {":method", "POST"},
      {":path", "/"},
      {":scheme", "http"},
      {":authority", addr.address().to_string()},
  };
  // эхо сервер пытается отправить в окно клиента 200'000 байт
  co_await client.send_req(1, hdrs, http_body_bytes(200'000, byte_t('a')));
  co_await client.send_req(3, hdrs, http_body_bytes(10, byte_t('b')));
  for (;;) {
    h2test_frame f = co_await client.receive_frame(deadline_after(5s));
    if (f.hdr.streamid == 3 && f.hdr.type == frame_e::DATA && (f.hdr.flags & flags::END_STREAM))
      break;
  }
  // ответ 200'000 игнорируется
}

static http_request make_client_request(h2client& client, http_method_e method) {
  http_request req;
  req.method = method;
  req.path = "/";
  req.authority = client.get_remote().to_string();
  return req;
}

// Загрузка большого тела в сервер с маленьким окном стрима (65'535, как у многих серверов) не задерживает
// остальные запросы клиента
CLIENT_TEST("request body larger than stream window does not block other requests") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  constexpr uint32_t WINDOW = INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL;
  constexpr size_t BODY = 200'000;
  http_request upload = make_client_request(client, http_method_e::PUT);
  upload.body.data.resize(BODY);
  auto h1 = client.send_request(std::move(upload), deadline_after(10s)).start_and_detach(true);
  auto h3 = client.send_request(make_client_request(client, http_method_e::GET), deadline_after(10s))
                .start_and_detach(true);
  on_scope_exit {
    h1.destroy();
    h3.destroy();
  };
  size_t received = 0;
  bool request3_received = false;
  while (received < WINDOW || !request3_received) {
    h2test_frame f = co_await server.next_frame(deadline_after(5s), ping_e::RESPONSE, window_e::SKIP);
    if (f.hdr.type == frame_e::HEADERS) {
      hpack::ignore_headers_block(server.get_inner_connection()->decoder, f.data);
      if (f.hdr.streamid == 3) {
        REQUIRE(f.hdr.flags & flags::END_STREAM);
        request3_received = true;
      }
      continue;
    }
    REQUIRE(f.hdr.type == frame_e::DATA);
    REQUIRE(f.hdr.streamid == 1);
    received += f.hdr.length;
  }
  REQUIRE(received == WINDOW);
  std::vector<header> ok{{":status", "200"}};
  co_await server.send_rsp(3, ok);
  co_await wait_until([&] { return h3.done(); }, ioctx);
  REQUIRE(h3.promise().result_or_rethrow().status == 200);
  REQUIRE(!h1.done());

  co_await server.send_window_size_increment(0, BODY);
  co_await server.send_window_size_increment(1, BODY);
  bool end_stream = false;
  while (!end_stream) {
    h2test_frame f = co_await server.receive_data(1);
    received += f.hdr.length;
    end_stream = f.hdr.flags & flags::END_STREAM;
  }
  REQUIRE(received == BODY);
  co_await server.send_rsp(1, ok);
  co_await wait_until([&] { return h1.done(); }, ioctx);
  REQUIRE(h1.promise().result_or_rethrow().status == 200);
}

// канал туннеля CONNECT, читает данные от сервера после `start_reading`
static streaming_body_t counting_tunnel(memory_queue_ptr q, const bool& start_reading, size_t& read,
                                        bool& ended, bool& aborted, any_io_context_ref ioctx) {
  while (!start_reading)
    co_await yield_on_ioctx(ioctx);
  for (;;) {
    bytes_t chunk = co_await q->next_chunk();
    if (chunk.empty())
      break;
    read += chunk.size();
  }
  aborted = q->aborted();
  ended = true;
}

// Туннель CONNECT с медленным потребителем (например прокси, отдающий данные в медленный сокет). Окно стрима
// возвращается серверу только по мере чтения: непрочитанное не растёт больше окна
CLIENT_TEST("CONNECT tunnel window is returned as data is read") {
  constexpr uint32_t WINDOW = 65'535;
  h2client_options opts = client.get_options();
  opts.stream_window_size = WINDOW;
  client.set_options(std::move(opts));
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  bool start_reading = false;
  // при провале теста канал не должен ждать вечно, иначе клиент не остановится
  on_scope_exit {
    start_reading = true;
  };
  size_t read = 0;
  bool ended = false;
  bool aborted = false;
  auto makestream = [&](http_response, memory_queue_ptr q, request_context) {
    return counting_tunnel(std::move(q), start_reading, read, ended, aborted, ioctx);
  };
  auto h = client
               .send_connect_request(make_client_request(client, http_method_e::CONNECT), makestream,
                                     deadline_after(10s))
               .start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  for (;;) {
    h2test_frame f = co_await server.next_frame(deadline_after(5s), ping_e::RESPONSE, window_e::SKIP);
    if (f.hdr.type != frame_e::HEADERS)
      continue;
    hpack::ignore_headers_block(server.get_inner_connection()->decoder, f.data);
    break;
  }
  std::vector<header> ok{{":status", "200"}};
  co_await server.send_headers(1, ok, /*endstream=*/false);

  SECTION("unread data is limited by stream window") {
    co_await server.send_data(1, std::string(WINDOW, 'a'), /*end_stream=*/false);
    // канал не читает, окно не возвращено, лишний байт нарушает его
    co_await server.send_data(1, "b", /*end_stream=*/false);
    h2test_frame f = co_await server.next_frame(deadline_after(5s), ping_e::RESPONSE, window_e::SKIP);
    REQUIRE(f.hdr.type == frame_e::RST_STREAM);
    REQUIRE(f.hdr.streamid == 1);
    start_reading = true;
    co_await wait_until([&] { return ended && h.done(); }, ioctx);
    REQUIRE(aborted);
    REQUIRE(read == WINDOW);
  }
  SECTION("reading returns window") {
    start_reading = true;
    co_await server.send_data(1, std::string(WINDOW, 'a'), /*end_stream=*/false);
    for (;;) {
      h2test_frame f = co_await server.next_frame(deadline_after(5s), ping_e::RESPONSE, window_e::RETURN);
      REQUIRE(f.hdr.type == frame_e::WINDOW_UPDATE);
      if (f.hdr.streamid == 1)
        break;
    }
    co_await server.send_data(1, std::string(WINDOW, 'a'), /*end_stream=*/true);
    co_await wait_until([&] { return ended && h.done(); }, ioctx);
    REQUIRE(h.promise().result_or_rethrow() == 200);
    REQUIRE(!aborted);
    REQUIRE(read == 2 * WINDOW);
  }
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
