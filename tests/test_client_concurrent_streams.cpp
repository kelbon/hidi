
#include "test_connection.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

// Сервер ограничивает число одновременных стримов значением `limit`
// Клиент должен сразу отправить `limit` запросов, а запрос сверх лимита отправить только когда освободится
// слот
static dd::task<void> check_concurrency_limit(any_io_context_ref ioctx, h2client& client, uint32_t limit) {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  server.set_max_concurrent_streams(limit);
  co_await emulate_server_connection(server);

  auto make_request = [&](std::string path) {
    http_request req;
    req.method = http_method_e::GET;
    req.path = std::move(path);
    req.scheme = scheme_e::HTTP;
    req.authority = client.get_remote().to_string();
    return req;
  };
  using handle_t =
      decltype(client.send_request(make_request("/"), deadline_after(10s)).start_and_detach(true));
  std::vector<handle_t> handles;
  on_scope_exit {
    for (handle_t h : handles)
      h.destroy();
  };
  // на один запрос больше чем разрешено
  for (uint32_t i = 0; i <= limit; ++i)
    handles.push_back(client.send_request(make_request("/" + std::to_string(i)), deadline_after(10s))
                          .start_and_detach(true));

  for (uint32_t i = 0; i < limit; ++i) {
    hdrs_and_data req = co_await server.receive_req();
    REQUIRE(req.streamid == 2 * i + 1);
  }
  // запрос сверх лимита не должен быть отправлен: если он пришёл, то sync завершит тест с ошибкой
  co_await server.sync();

  // освобождаем слот, теперь запрос сверх лимита должен прийти
  std::vector<header> ok{{":status", "200"}};
  co_await server.send_rsp(1, ok);
  hdrs_and_data req = co_await server.receive_req();
  REQUIRE(req.streamid == 2 * limit + 1);
}

CLIENT_TEST("client respects MAX_CONCURRENT_STREAMS == 1") {
  co_await check_concurrency_limit(ioctx, client, 1);
}

CLIENT_TEST("client respects MAX_CONCURRENT_STREAMS == 2") {
  co_await check_concurrency_limit(ioctx, client, 2);
}

// Запрос ждёт свободный слот (MAX_CONCURRENT_STREAMS) и истекает до отправки HEADERS. Для сервера его стрим
// idle, а RST_STREAM на idle стрим - ошибка всего соединения
// https://www.rfc-editor.org/rfc/rfc9113.html#section-6.4-7
// Поэтому клиент не отправляет ни RST_STREAM, ни HEADERS для такого запроса
CLIENT_TEST("timeout of queued request sends nothing") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  server.set_max_concurrent_streams(1);
  co_await emulate_server_connection(server);

  auto make_request = [&] {
    http_request req;
    req.method = http_method_e::GET;
    req.path = "/";
    req.scheme = scheme_e::HTTP;
    req.authority = client.get_remote().to_string();
    return req;
  };
  auto active = client.send_request(make_request(), deadline_after(10s)).start_and_detach(true);
  on_scope_exit {
    active.destroy();
  };
  REQUIRE((co_await server.receive_req()).streamid == 1);

  auto queued = client.send_request(make_request(), deadline_after(100ms)).start_and_detach(true);
  on_scope_exit {
    queued.destroy();
  };
  co_await wait_until([&] { return queued.done(); }, ioctx);
  bool timeout = false;
  try {
    (void)queued.promise().result_or_rethrow();
  } catch (timeout_exception&) {
    timeout = true;
  }
  REQUIRE(timeout);
  // RST_STREAM или HEADERS для стрима 3 завершат sync с ошибкой
  co_await server.sync();

  std::vector<header> ok{{":status", "200"}};
  co_await server.send_rsp(1, ok);
  co_await wait_until([&] { return active.done(); }, ioctx);
  REQUIRE(active.promise().result_or_rethrow().status == 200);
  co_await server.sync();
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
