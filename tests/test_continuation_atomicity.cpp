
#include "test_connection.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

// Блок заголовков, не поместившийся в один кадр, отправляется как HEADERS + CONTINUATION, и между ними не
// должно быть других кадров https://www.rfc-editor.org/rfc/rfc9113.html#section-6.10
//
// - клиент отсылает гигантский запрос с CONTINUATION (пытаясь забить системный буфер и получить suspend на
// try_write чтобы появилось окно между HEADERS и CONTINUATION)
// - клиент получает пинг (на который ему отвечать запрещено между CONTINUATION)
// - только потом фейк сервер вычитывает данные позволяя писать дальше
CLIENT_TEST("HEADERS and CONTINUATION are not separated by other frames") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await emulate_server_connection(server);

  http_request req;
  req.method = http_method_e::GET;
  req.path = "/";
  req.scheme = scheme_e::HTTP;
  req.authority = client.get_remote().to_string();
  req.headers.push_back(http_header_t("x-big", std::string(40 * 1024 * 1024, 'a')));
  auto handle =
      client.send_request(std::move(req), deadline_after(30s)).start_and_detach(/*stop_at_end=*/true);
  on_scope_exit {
    handle.destroy();
  };

  // клиент начал запись блока и упёрся в заполненные буферы (сервер пока ничего не читает)
  co_await net.sleep(ioctx, 500ms);
  co_await server.send_ping(42);
  // читатель клиента пытается ответить на PING
  co_await net.sleep(ioctx, 500ms);

  h2test_frame f;
  do {
    f = co_await server.receive_frame(deadline_after(10s));
    REQUIRE(f.hdr.type != frame_e::CONTINUATION);
  } while (f.hdr.type != frame_e::HEADERS);  // пропуск ping/window_update и тд
  REQUIRE(f.hdr.streamid == 1);
  REQUIRE(!(f.hdr.flags & flags::END_HEADERS));
  while (!(f.hdr.flags & flags::END_HEADERS)) {
    f = co_await server.receive_frame(deadline_after(10s));
    REQUIRE(f.hdr.type == frame_e::CONTINUATION);
    REQUIRE(f.hdr.streamid == 1);
  }
  // ACK на PING отправляется после блока, а не теряется. Остальные кадры (WINDOW_UPDATE, PING-запросы и т.д.)
  // пропускаем
  for (;;) {
    f = co_await server.receive_frame(deadline_after(10s));
    if (f.hdr.type != frame_e::PING || !(f.hdr.flags & flags::ACK))
      continue;
    ping_frame pf;
    REQUIRE_NOTHROW(pf = ping_frame::parse(f.hdr, f.data));
    REQUIRE(pf.get_data() == 42);
    break;
  }
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
