
#include "test_connection.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

// Сервер ограничивает число одновременных стримов значением `limit`. Клиент должен сразу отправить `limit`
// запросов, а запрос сверх лимита отправить только когда освободится слот.
// Раньше отправляемый стрим учитывался в лимите ещё до отправки: при limit == 1 клиент не отправлял
// ничего, а при limit == N одновременно было не более N - 1 стримов
static dd::task<void> check_concurrency_limit(any_io_context_ref ioctx, h2client& client, uint32_t limit) {
  any_acceptor acceptor = ioctx.create_acceptor(localhost(), /*reuse_address=*/false);
  acceptor.listen();
  client.try_connect(acceptor.get_local_endpoint(), deadline_after(5s)).start_and_detach();
  io_error_code ec;
  any_connection_t tcp = co_await acceptor.accept(ec);
  REQUIRE(!ec);
  test_h2connection server(new h2connection(std::move(tcp), *&ioctx), /*client=*/false);
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
  using handle_t = decltype(client.send_request(make_request("/"), deadline_after(10s)).start_and_detach(true));
  std::vector<handle_t> handles;
  on_scope_exit {
    for (handle_t h : handles)
      h.destroy();
  };
  // на один запрос больше чем разрешено
  for (uint32_t i = 0; i <= limit; ++i)
    handles.push_back(
        client.send_request(make_request("/" + std::to_string(i)), deadline_after(10s)).start_and_detach(true));

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

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
