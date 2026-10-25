#include "test_connection.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

static const byte_t BODY_PART[] = {'a', 'b', 'c'};

// вторая часть тела отдаётся только после `send_second`
static streaming_body_t two_parts_body(const bool& send_second, bool& second_yielded, any_io_context_ref io) {
  co_yield std::span<const byte_t>(BODY_PART);
  co_await wait_until([&] { return send_second; }, io);
  second_yielded = true;
  co_yield std::span<const byte_t>(BODY_PART);
}

// on_header бросает исключение, пока тело запроса ещё отправляется. Клиент отменяет стрим (RST_STREAM) и
// после этого не должен отправлять по нему DATA
CLIENT_TEST("user exception in on_header stops sending request body") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  bool send_second = false;
  bool second_yielded = false;
  bool user_exception = false;
  auto on_header = [](std::string_view, std::string_view) { throw std::runtime_error("user exception"); };
  auto request = [&]() -> dd::task<void> {
    http_request req;
    req.method = http_method_e::PUT;
    req.path = "/";
    req.authority = client.get_remote().to_string();
    stream_body_maker_t body = [&](http_headers_t&, request_context) {
      return two_parts_body(send_second, second_yielded, ioctx);
    };
    try {
      (void)co_await client.send_streaming_request(&on_header, nullptr, std::move(req), std::move(body),
                                                   deadline_after(10s));
    } catch (std::runtime_error&) {
      user_exception = true;
    }
  };
  auto handle = request().start_and_detach(/*stop_at_end=*/true);
  on_scope_exit {
    handle.destroy();
  };

  for (;;) {
    h2test_frame f = co_await server.receive_frame(deadline_after(5s));
    if (f.hdr.type == frame_e::HEADERS)
      break;
  }
  (void)co_await server.receive_data(1);

  std::vector<header> hdrs{{":status", "200"}, {"x-header", "value"}};
  co_await server.send_headers(1, std::move(hdrs), /*endstream=*/false);
  co_await server.receive_rst_stream(1, errc_e::CANCEL);
  co_await wait_until([&] { return user_exception; }, ioctx);

  send_second = true;
  co_await wait_until([&] { return second_yielded; }, ioctx);
  // DATA по отменённому стриму завершит sync с ошибкой
  co_await server.sync();
}

static http_request make_request(h2client& client, http_method_e method = http_method_e::GET) {
  http_request req;
  req.method = method;
  req.path = "/";
  req.authority = client.get_remote().to_string();
  return req;
}

// канал CONNECT, читает данные от сервера до EOF
static streaming_body_t tunnel_reader(memory_queue_ptr q, bool& started, bool& ended) {
  started = true;
  while (!q->last_chunk_received())
    (void)co_await q->next_chunk();
  ended = true;
  co_return;
}

// Запрос отменяется уничтожением его корутины на разных стадиях. Если HEADERS уже отправлены, сервер получает
// RST_STREAM и больше ничего по этому стриму, а соединение продолжает работать
CLIENT_TEST("request canceled by destroy") {
  h2client_options opts = client.get_options();
  // иначе запрос не ждёт установки соединения
  opts.allow_requests_before_server_settings = false;
  client.set_options(std::move(opts));
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  server.set_max_concurrent_streams(1);

  using handle_t = decltype(client.send_request(make_request(client), deadline_t::never()).start_and_detach(true));
  // HEADERS запроса с телом (receive_req ожидает тело одним DATA)
  auto receive_headers = [&]() -> dd::task<void> {
    for (;;) {
      h2test_frame f = co_await server.receive_frame(deadline_after(5s));
      if (f.hdr.type != frame_e::HEADERS)
        continue;
      // декодер фейкового сервера должен остаться синхронизирован с кодировщиком клиента
      hpack::ignore_headers_block(server.get_inner_connection()->decoder, f.data);
      co_return;
    }
  };
  std::vector<header> ok{{":status", "200"}};

  SECTION("waiting for connection") {
    handle_t h = client.send_request(make_request(client), deadline_after(10s)).start_and_detach(true);
    h.destroy();
  }
  co_await emulate_server_connection(server);

  SECTION("waiting for free stream slot") {
    handle_t active = client.send_request(make_request(client), deadline_after(10s)).start_and_detach(true);
    on_scope_exit {
      active.destroy();
    };
    REQUIRE((co_await server.receive_req()).streamid == 1);
    handle_t queued = client.send_request(make_request(client), deadline_after(10s)).start_and_detach(true);
    queued.destroy();
    // для неотправленного запроса ничего не отправляется
    co_await server.sync();
    co_await server.send_rsp(1, ok);
    co_await wait_until([&] { return active.done(); }, ioctx);
    REQUIRE(active.promise().result_or_rethrow().status == 200);
  }
  SECTION("waiting for response") {
    handle_t h = client.send_request(make_request(client), deadline_after(10s)).start_and_detach(true);
    REQUIRE((co_await server.receive_req()).streamid == 1);
    h.destroy();
    co_await server.receive_rst_stream(1, errc_e::CANCEL);
  }
  SECTION("sending body") {
    http_request req = make_request(client, http_method_e::PUT);
    // больше начального окна, писатель ждёт WINDOW_UPDATE
    req.body.data.resize(2 * INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL);
    handle_t h = client.send_request(std::move(req), deadline_after(10s)).start_and_detach(true);
    co_await receive_headers();
    size_t received = 0;
    while (received < INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL)
      received += (co_await server.receive_data(1)).hdr.length;
    h.destroy();
    co_await server.receive_rst_stream(1, errc_e::CANCEL);
    co_await server.send_window_size_increment(1, INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL);
    co_await server.send_window_size_increment(0, INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL);
  }
  SECTION("sending streaming body") {
    bool send_second = false;
    bool second_yielded = false;
    stream_body_maker_t body = [&](http_headers_t&, request_context) {
      return two_parts_body(send_second, second_yielded, ioctx);
    };
    auto h = client.send_streaming_request(make_request(client, http_method_e::PUT), std::move(body),
                                           deadline_after(10s))
                 .start_and_detach(true);
    co_await receive_headers();
    (void)co_await server.receive_data(1);
    h.destroy();
    co_await server.receive_rst_stream(1, errc_e::CANCEL);
    send_second = true;
    co_await wait_until([&] { return second_yielded; }, ioctx);
  }
  SECTION("CONNECT tunnel") {
    bool started = false;
    bool ended = false;
    auto makestream = [&](http_response, memory_queue_ptr q, request_context) {
      return tunnel_reader(std::move(q), started, ended);
    };
    auto h = client.send_connect_request(make_request(client, http_method_e::CONNECT), makestream,
                                         deadline_after(10s))
                 .start_and_detach(true);
    co_await receive_headers();
    co_await server.send_headers(1, ok, /*endstream=*/false);
    co_await wait_until([&] { return started; }, ioctx);
    h.destroy();
    co_await server.receive_rst_stream(1, errc_e::CANCEL);
    // канал не должен ждать данных вечно
    co_await wait_until([&] { return ended; }, ioctx);
  }
  // по отменённому стриму больше ничего не отправляется, иначе sync завершится с ошибкой
  co_await server.sync();

  // соединение продолжает работать
  handle_t h = client.send_request(make_request(client), deadline_after(10s)).start_and_detach(true);
  on_scope_exit {
    h.destroy();
  };
  stream_id_t id = (co_await server.receive_req()).streamid;
  co_await server.send_rsp(id, ok);
  co_await wait_until([&] { return h.done(); }, ioctx);
  REQUIRE(h.promise().result_or_rethrow().status == 200);
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
