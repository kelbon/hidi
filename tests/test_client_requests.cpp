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

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
