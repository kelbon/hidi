
#include "test_connection.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

SERVER_TEST("WINDOW_UPDATE reserved bit is ignored") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  std::vector<byte_t> bytes;
  window_update_frame::form(/*streamid=*/0, /*increment=*/0x10, std::back_inserter(bytes));
  // старший бит поля Window Size Increment
  bytes[FRAME_HEADER_LEN] |= 0x80;
  co_await client.send_raw_frame(std::move(bytes));
  // если сервер закрыл соединение, то вместо ответа на PING придёт GOAWAY и sync завершит тест с ошибкой
  co_await client.sync();
}

SERVER_TEST("SETTINGS with len not multiple of 6") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  std::vector<byte_t> bytes;
  frame_header{.length = 5, .type = frame_e::SETTINGS, .flags = 0, .streamid = 0}.form(
      std::back_inserter(bytes));
  bytes.resize(bytes.size() + 5);
  co_await client.send_raw_frame(std::move(bytes));
  co_await client.receive_goaway(MAX_STREAM_ID, errc_e::FRAME_SIZE_ERROR, ping_e::RESPONSE);
}

// Клиент не поддерживает push и обязан явно отправить 0
CLIENT_TEST("client explicitly disables push in SETTINGS") {
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  co_await server.receive_client_magic();
  h2test_frame f = co_await server.receive_settings();
  settings_t client_settings;
  settings_frame::parse(f.hdr, f.data, client_settings_visitor{client_settings, /*firstframe=*/true});
  REQUIRE(!client_settings.enable_push);
}

// использует тот факт что сервер в ответе напишет имя хедера как дебаг информацию
SERVER_TEST("GOAWAY debug info is truncated") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  std::vector<header> hdrs{
      {":method", "POST"}, {":path", "/"}, {":scheme", "http"}, {":authority", addr.address().to_string()}};
  co_await client.send_req(1, hdrs, http_body_bytes{}, /*endstream=*/false);
  // псевдохедеры в трейлерах запрещены, и сервер отвечает GOAWAY с именем этого хедера в debug info
  auto trailers = client.encode_headers({{":" + std::string(20000, 'x'), "value"}});
  co_await client.send_raw_hdr(1, trailers, /*end_stream=*/true);
  for (;;) {
    h2test_frame f = co_await client.receive_frame(deadline_after(5s));
    if (f.hdr.type != frame_e::GOAWAY)
      continue;
    REQUIRE(f.hdr.length <= MIN_MAX_FRAME_LEN);
    break;
  }
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
