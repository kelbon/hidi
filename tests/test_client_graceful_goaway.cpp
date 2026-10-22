
#include "test_connection.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

// Клиент получает GOAWAY(NO_ERROR) пока на соединении идёт запрос. После этого на этом соединении нельзя
// открывать новые стримы: новый запрос должен дождаться завершения старого соединения и уйти в новое.
CLIENT_TEST("client does not open new streams after graceful GOAWAY") {
  any_acceptor acceptor = ioctx.create_acceptor(localhost(), /*reuse_address=*/false);
  acceptor.listen();
  // если клиент не переподключится, то accept второго соединения завершится ошибкой и тест упадёт, а не
  // зависнет
  any_timer watchdog = ioctx.create_timer();
  watchdog.set_callback([&](bool canceled) {
    if (!canceled)
      acceptor.close();
  });
  watchdog.arm(deadline_after(5s).tp);
  on_scope_exit {
    watchdog.cancel();
  };

  client.try_connect(acceptor.get_local_endpoint(), deadline_after(5s)).start_and_detach();
  io_error_code ec;
  any_connection_t tcp1 = co_await acceptor.accept(ec);
  REQUIRE(!ec);
  test_h2connection server(new h2connection(std::move(tcp1), *&ioctx), /*client=*/false);
  co_await emulate_server_connection(server);

  auto make_request = [&](std::string path) {
    http_request req;
    req.method = http_method_e::GET;
    req.path = std::move(path);
    req.scheme = scheme_e::HTTP;
    req.authority = client.get_remote().to_string();
    return req;
  };

  // запрос A, на который сервер пока не отвечает
  auto handle_a =
      client.send_request(make_request("/a"), deadline_after(10s)).start_and_detach(/*stop_at_end=*/true);
  on_scope_exit {
    handle_a.destroy();
  };
  hdrs_and_data req_a = co_await server.receive_req();
  REQUIRE(req_a.streamid == 1);

  // graceful shutdown от сервера, A остаётся в работе
  co_await server.send_goaway(/*last_streamid=*/1, errc_e::NO_ERROR);
  co_await server.sync();

  // запрос B, нельзя отправлять в старое соединение
  auto handle_b =
      client.send_request(make_request("/b"), deadline_after(10s)).start_and_detach(/*stop_at_end=*/true);
  on_scope_exit {
    handle_b.destroy();
  };

  std::vector<header> ok{{":status", "200"}};
  co_await server.send_rsp(1, ok);
  co_await wait_until([&] { return handle_a.done(); }, ioctx);
  REQUIRE(handle_a.promise().result_or_rethrow().status == 200);

  // старое соединение завершилось, B должен прийти в новом
  any_connection_t tcp2 = co_await acceptor.accept(ec);
  REQUIRE(!ec);
  test_h2connection server2(new h2connection(std::move(tcp2), *&ioctx), /*client=*/false);
  // запрос B может прийти раньше SETTINGS ACK / WINDOW_UPDATE, порядок этих кадров не важен
  co_await server2.receive_client_magic();
  (void)co_await server2.receive_settings();
  co_await server2.send_settings();
  co_await server2.send_settings_ack();
  stream_id_t req_b_streamid = 0;
  while (req_b_streamid == 0) {
    h2test_frame f = co_await server2.receive_frame(deadline_after(5s));
    if (f.hdr.type == frame_e::HEADERS)
      req_b_streamid = f.hdr.streamid;
  }
  REQUIRE(req_b_streamid == 1);
  co_await server2.send_rsp(1, ok);
  co_await wait_until([&] { return handle_b.done(); }, ioctx);
  REQUIRE(handle_b.promise().result_or_rethrow().status == 200);
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
