#include "test_connection.hpp"

#include <moko3/moko3.hpp>

// Завершение запросов не обычным ответом: таймауты, сбросы стримов, разрыв соединения, ошибки обработчика

using namespace hidi;
using namespace std::chrono_literals;

static http_request make_request(h2client& client, http_method_e method, std::string path = "/") {
  http_request req;
  req.method = method;
  req.path = std::move(path);
  req.authority = client.get_remote().to_string();
  return req;
}

using request_handle_t = decltype(std::declval<h2client&>()
                                      .send_request(std::declval<http_request>(), deadline_t::never())
                                      .start_and_detach(true));

// запрос завершился исключением `E`
template <typename E = std::exception>
static bool failed_with(request_handle_t h) {
  try {
    (void)h.promise().result_or_rethrow();
  } catch (E&) {
    return true;
  } catch (...) {
  }
  return false;
}

// принимает HEADERS запроса (декодер фейкового сервера должен остаться синхронизирован с клиентом)
static dd::task<void> receive_request_headers(test_h2connection& server, stream_id_t streamid) {
  for (;;) {
    h2test_frame f = co_await server.next_frame(deadline_after(5s), ping_e::RESPONSE, window_e::SKIP);
    if (f.hdr.type != frame_e::HEADERS)
      continue;
    REQUIRE(f.hdr.streamid == streamid);
    hpack::ignore_headers_block(server.get_inner_connection()->decoder, f.data);
    co_return;
  }
}

// соединение работает: следующий запрос получает ответ
static dd::task<void> next_request_works(h2client& client, test_h2connection& server, stream_id_t streamid,
                                         any_io_context_ref ioctx) {
  auto h = client.send_request(make_request(client, http_method_e::GET), deadline_after(5s))
               .start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  REQUIRE((co_await server.receive_req()).streamid == streamid);
  std::vector<header> ok{{":status", "200"}};
  co_await server.send_rsp(streamid, ok);
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(h.promise().result_or_rethrow().status == 200);
}

// Тело запроса ждёт окна, которое сервер не даёт, и дедлайн истекает. Клиент сбрасывает стрим и больше ничего
// в него не пишет, даже если окно затем вырастет
CLIENT_TEST("request deadline while body waits for window") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  http_request req = make_request(client, http_method_e::PUT);
  req.body.data.resize(200'000);
  auto h = client.send_request(std::move(req), deadline_after(300ms)).start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  co_await receive_request_headers(server, 1);
  size_t received = 0;
  while (received < INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL)
    received += (co_await server.receive_data(1)).hdr.length;
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(failed_with<timeout_exception>(h));
  co_await server.receive_rst_stream(1, errc_e::CANCEL);

  co_await server.send_window_size_increment(0, 1 << 20);
  co_await server.send_window_size_increment(1, 1 << 20);
  // первым придёт следующий запрос, а не DATA сброшенного стрима
  co_await next_request_works(client, server, 3, ioctx);
}

// Ответ пришёл не целиком, и дедлайн истекает. Клиент сбрасывает стрим, опоздавшие DATA игнорируются, а
// соединение продолжает работать
CLIENT_TEST("request deadline while response body is received") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  auto h = client.send_request(make_request(client, http_method_e::GET), deadline_after(300ms))
               .start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  REQUIRE((co_await server.receive_req()).streamid == 1);
  std::vector<header> ok{{":status", "200"}};
  co_await server.send_headers(1, ok, /*endstream=*/false);
  co_await server.send_data(1, "part", /*end_stream=*/false);
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(failed_with<timeout_exception>(h));
  co_await server.receive_rst_stream(1, errc_e::CANCEL);

  co_await server.send_data(1, "rest", /*end_stream=*/true);
  co_await next_request_works(client, server, 3, ioctx);
}

// канал туннеля CONNECT: читает данные до EOF
static streaming_body_t read_tunnel(memory_queue_ptr q, size_t& read, bool& ended, bool& aborted) {
  for (;;) {
    bytes_t chunk = co_await q->next_chunk();
    if (chunk.empty())
      break;
    read += chunk.size();
  }
  aborted = q->aborted();
  ended = true;
}

// дедлайн CONNECT ограничивает установку туннеля, а не его жизнь
CLIENT_TEST("CONNECT deadline does not limit established tunnel") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  size_t read = 0;
  bool ended = false;
  bool aborted = false;
  auto makestream = [&](http_response, memory_queue_ptr q, request_context) {
    return read_tunnel(std::move(q), read, ended, aborted);
  };
  auto h = client
               .send_connect_request(make_request(client, http_method_e::CONNECT), makestream,
                                     deadline_after(200ms))
               .start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  co_await receive_request_headers(server, 1);
  std::vector<header> ok{{":status", "200"}};
  co_await server.send_headers(1, ok, /*endstream=*/false);
  // туннель переживает дедлайн
  co_await net.sleep(ioctx, 400ms);
  co_await server.send_data(1, "data", /*end_stream=*/true);
  co_await wait_until([&] { return ended && h.done(); }, ioctx);
  REQUIRE(!aborted);
  REQUIRE(read == 4);
  REQUIRE(h.promise().result_or_rethrow() == 200);
}

// сервер сбросил обычный запрос. Запрос завершается ошибкой, соединение продолжает работать
CLIENT_TEST("server resets request") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  errc_e code = errc_e::CANCEL;
  SECTION("CANCEL") {
  }
  SECTION("REFUSED_STREAM") {
    code = errc_e::REFUSED_STREAM;
  }
  auto h = client.send_request(make_request(client, http_method_e::GET), deadline_after(5s))
               .start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  REQUIRE((co_await server.receive_req()).streamid == 1);
  co_await server.send_rst_stream(1, code);
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(failed_with(h));
  co_await next_request_works(client, server, 3, ioctx);
}

// GOAWAY с ошибкой: соединение закрывается, запросы на нём завершаются ошибкой
CLIENT_TEST("server GOAWAY with error") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  auto h = client.send_request(make_request(client, http_method_e::GET), deadline_after(5s))
               .start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  REQUIRE((co_await server.receive_req()).streamid == 1);
  co_await server.send_goaway(/*last_streamid=*/1, errc_e::INTERNAL_ERROR, "test");
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(failed_with(h));
  co_await wait_until([&] { return !client.connected(); }, ioctx);
}

// сервер закрыл TCP соединение посреди запроса
CLIENT_TEST("connection closed during request") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  auto h = client.send_request(make_request(client, http_method_e::GET), deadline_after(5s))
               .start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  REQUIRE((co_await server.receive_req()).streamid == 1);
  server.close();
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(failed_with(h));
  co_await wait_until([&] { return !client.connected(); }, ioctx);
}

// сервер жив по TCP, но не отвечает на PING: клиент рвёт соединение по ping_timeout, не дожидаясь дедлайна
// запроса
CLIENT_TEST("unanswered ping drops connection") {
  h2client_options opts = client.get_options();
  opts.ping_interval = 50ms;
  opts.ping_timeout = 100ms;
  client.set_options(std::move(opts));
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  auto h = client.send_request(make_request(client, http_method_e::GET), deadline_after(30s))
               .start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  REQUIRE((co_await server.receive_req()).streamid == 1);
  // дальше сервер ничего не читает и на PING не отвечает
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(failed_with(h));
  REQUIRE(!client.connected());
}

// подключиться не удалось: запрос завершается ошибкой
CLIENT_TEST("request fails when server is unreachable") {
  any_acceptor a = ioctx.create_acceptor(localhost(), /*reuse_address=*/true);
  a.listen();
  client.set_remote(endpoint(a.get_local_endpoint()));
  deadline_t deadline = deadline_after(30s);
  bool refused = false;
  SECTION("connection refused") {
    // порт освобождается, подключение к нему отклоняется сразу, дедлайн не нужен
    a.close();
    refused = true;
  }
  SECTION("server does not answer") {
    // TCP соединение попадает в очередь listen, но сервер его не принимает и ничего не отвечает.
    // Установку соединения ограничивает дедлайн запроса
    deadline = deadline_after(300ms);
  }
  auto h = client.send_request(make_request(client, http_method_e::GET), deadline).start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(failed_with(h));
  if (refused)
    REQUIRE(!client.connected());
}

static std::vector<header> get_headers(internet_address addr, std::string path) {
  return {
      {":method", "GET"},
      {":path", std::move(path)},
      {":scheme", "http"},
      {":authority", addr.address().to_string()},
  };
}

// клиент сбросил стрим, пока запрос ещё собирается (тело не дослано). Сервер не отвечает на это RST_STREAM и
// продолжает обслуживать соединение
SERVER_TEST("client resets stream before request is assembled") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  std::vector<header> post{
      {":method", "POST"},
      {":path", "/"},
      {":scheme", "http"},
      {":authority", addr.address().to_string()},
  };
  co_await client.send_headers(1, post, /*endstream=*/false);
  co_await client.sync();
  co_await client.send_rst_stream(1, errc_e::CANCEL);

  co_await client.send_req(3, post, http_body_bytes(10, byte_t('b')));
  auto rsp = co_await client.receive_rsp();
  REQUIRE(rsp.streamid == 3);
  REQUIRE(rsp.body == http_body_bytes(10, byte_t('b')));
  co_await client.sync();
}

// обработчик по пути запроса: бросает исключение или ждёт отмены запроса
struct handler_server : h2server {
  using h2server::h2server;
  bool saw_cancel = false;

  dd::task<http_response> handle_request(http_request req, request_context ctx) override {
    if (req.path == "/runtime_error")
      throw std::runtime_error("handler failed");
    if (req.path == "/stream_error")
      throw stream_error(errc_e::ENHANCE_YOUR_CALM, ctx.streamid(), "handler refused");
    if (req.path == "/wait_cancel") {
      // ограничено по времени, чтобы при провале теста обработчик не держал остановку сервера
      deadline_t deadline = deadline_after(5s);
      while (!ctx.canceled() && !deadline.is_reached())
        co_await yield_on_ioctx(*&ioctx());
      saw_cancel = ctx.canceled();
    }
    co_return http_response{.status = 200};
  }
};

// исключение из обработчика сбрасывает только его стрим: обычное - INTERNAL_ERROR, stream_error - своим кодом
static dd::task<void> handler_exceptions_body(handler_server&, internet_address addr,
                                              any_io_context_ref ioctx) {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);
  co_await client.send_req(1, get_headers(addr, "/runtime_error"));
  co_await client.receive_rst_stream(1, errc_e::INTERNAL_ERROR);
  co_await client.send_req(3, get_headers(addr, "/stream_error"));
  co_await client.receive_rst_stream(3, errc_e::ENHANCE_YOUR_CALM);
  co_await client.send_req(5, get_headers(addr, "/"));
  auto rsp = co_await client.receive_rsp();
  REQUIRE(rsp.streamid == 5);
  REQUIRE(rsp.find_hdr(":status") == "200");
}

TEST("handler exception resets its stream") {
  run_custom_server_test(_section, "handler exception resets its stream", h2server_options{},
                         &handler_exceptions_body);
}

// клиент закрыл соединение, пока обработчик работает: обработчик видит отмену, сессия завершается
static dd::task<void> connection_closed_while_handling_body(handler_server& server, internet_address addr,
                                                            any_io_context_ref ioctx) {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);
  co_await client.send_req(1, get_headers(addr, "/wait_cancel"));
  // запрос принят и обработчик запущен
  co_await client.sync();
  client.close();
  co_await wait_until([&] { return server.saw_cancel; }, ioctx);
  co_await wait_until([&] { return server.sessions_count() == 0; }, ioctx);
}

TEST("connection closed while handler runs") {
  run_custom_server_test(_section, "connection closed while handler runs", h2server_options{},
                         &connection_closed_while_handling_body);
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
