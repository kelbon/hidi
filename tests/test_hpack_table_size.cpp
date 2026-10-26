
#include "test_connection.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

// https://www.rfc-editor.org/rfc/rfc7541#section-4.2
// Пир может разрешить в SETTINGS таблицу больше 4096, но пока кодировщик не отправит dynamic table size
// update, декодер пира продолжает использовать текущий размер (4096). Так ведут себя декодер hidi
// (и фейковых пиров в тестах) и nghttp2
//
// "x-const" кэшируется первым и используется в каждом следующем блоке, а уникальные заголовки
// в сумме занимают больше 4096 байт. Если кодировщик молча использует большую таблицу, декодер пира
// вытеснит "x-const" раньше, чем кодировщик, и индексы разойдутся
static constexpr int BLOCKS_COUNT = 50;

static std::string unique_value(int i) {
  return std::format("{:0>100}", i);
}

SERVER_TEST("server encoder signals table size from client SETTINGS") {
  auto client = co_await fake_client_connection(ioctx, addr);
  client.set_header_table_size(64 * 1024);
  co_await emulate_client_connection(client);

  for (int i = 0; i < BLOCKS_COUNT; ++i) {
    stream_id_t streamid = 1 + 2 * i;
    std::vector<header> hdrs{
        {":method", "GET"},  {":path", "/"},
        {":scheme", "http"}, {":authority", addr.address().to_string()},
        {"x-const", "v"},    {"x-unique", unique_value(i)},
    };
    co_await client.send_headers(streamid, hdrs, /*endstream=*/true);
    auto rsp = co_await client.receive_rsp();
    REQUIRE(rsp.streamid == streamid);
    REQUIRE(std::ranges::find(rsp.headers, header{"x-const", "v"}) != rsp.headers.end());
    REQUIRE(std::ranges::find(rsp.headers, header{"x-unique", unique_value(i)}) != rsp.headers.end());
  }
}

// при уменьшении таблицы size update обязателен, например nghttp2 без него отвечает COMPRESSION_ERROR
SERVER_TEST("server encoder signals smaller table size") {
  auto client = co_await fake_client_connection(ioctx, addr);
  client.set_header_table_size(1024);
  co_await emulate_client_connection(client);

  std::vector<header> hdrs{
      {":method", "GET"}, {":path", "/"}, {":scheme", "http"}, {":authority", addr.address().to_string()}};
  co_await client.send_headers(1, hdrs, /*endstream=*/true);
  for (;;) {
    h2test_frame f = co_await client.receive_frame(deadline_after(5s));
    if (f.hdr.type != frame_e::HEADERS)
      continue;
    // https://www.rfc-editor.org/rfc/rfc7541#section-6.3
    REQUIRE(!f.data.empty() && (f.data[0] & 0b1110'0000) == 0b0010'0000);
    break;
  }
}

// собеседник может разрешить огромную таблицу, но кодировщик не должен использовать больше своего
// hpack_dyntab_size
SERVER_TEST("server encoder table size is limited by own table size") {
  // не 4096, иначе size update не нужен вовсе
  server.get_options().hpack_dyntab_size = 8192;
  auto client = co_await fake_client_connection(ioctx, addr);
  client.set_header_table_size(1 << 30);
  co_await emulate_client_connection(client);

  std::vector<header> hdrs{
      {":method", "GET"}, {":path", "/"}, {":scheme", "http"}, {":authority", addr.address().to_string()}};
  co_await client.send_headers(1, hdrs, /*endstream=*/true);
  for (;;) {
    h2test_frame f = co_await client.receive_frame(deadline_after(5s));
    if (f.hdr.type != frame_e::HEADERS)
      continue;
    // https://www.rfc-editor.org/rfc/rfc7541#section-6.3
    // table size update
    REQUIRE(!f.data.empty() && (f.data[0] & 0b1110'0000) == 0b0010'0000);
    const hpack::byte_t* in = f.data.data();
    REQUIRE(hpack::decode_integer(in, f.data.data() + f.data.size(), 5) ==
            server.get_options().hpack_dyntab_size);
    break;
  }
}

static std::vector<byte_t> header_table_size_settings(uint32_t size) {
  std::vector<byte_t> bytes;
  frame_header{.length = 6, .type = frame_e::SETTINGS, .flags = 0, .streamid = 0}.form(
      std::back_inserter(bytes));
  setting_t::form(setting_t{.identifier = SETTINGS_HEADER_TABLE_SIZE, .value = size},
                  std::back_inserter(bytes));
  return bytes;
}

// https://www.rfc-editor.org/rfc/rfc7541#section-4.2
// если размер таблицы уменьшился и снова вырос между блоками заголовков, кодировщик обязан сначала сообщить
// наименьший размер: декодер собеседника уменьшает таблицу после ACK и вытесняет записи
SERVER_TEST("server encoder signals smallest table size after reduce and grow") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  std::vector<header> hdrs{
      {":method", "GET"}, {":path", "/"}, {":scheme", "http"}, {":authority", addr.address().to_string()},
      {"x-const", "v"},
  };
  // сервер кэширует "x-const" в ответе
  co_await client.send_headers(1, hdrs, /*endstream=*/true);
  auto rsp = co_await client.receive_rsp();
  REQUIRE(std::ranges::find(rsp.headers, header{"x-const", "v"}) != rsp.headers.end());

  co_await client.send_raw_frame(header_table_size_settings(0));
  co_await client.send_raw_frame(header_table_size_settings(4096));
  co_await client.receive_settings_ack();
  co_await client.receive_settings_ack();
  hpack::dynamic_table_t& table = client.get_inner_connection()->decoder.dyntab;
  table.set_user_protocol_max_size(0);
  table.set_user_protocol_max_size(4096);

  // без size update 0 сервер сослался бы на вытесненный у клиента "x-const"
  co_await client.send_headers(3, hdrs, /*endstream=*/true);
  rsp = co_await client.receive_rsp();
  REQUIRE(rsp.streamid == 3);
  REQUIRE(std::ranges::find(rsp.headers, header{"x-const", "v"}) != rsp.headers.end());
}

// кодировщик клиента увеличивает таблицу без size update сразу после ACK настроек сервера
SERVER_TEST("server decoder accepts table grown without size update") {
  server.get_options().hpack_dyntab_size = 64 * 1024;
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);
  hpack::dynamic_table_t& table = client.get_inner_connection()->encoder.dyntab;
  REQUIRE(table.user_protocol_max_size() == 64 * 1024);
  table.update_size(64 * 1024);

  for (int i = 0; i < BLOCKS_COUNT; ++i) {
    stream_id_t streamid = 1 + 2 * i;
    std::vector<header> hdrs{
        {":method", "GET"},  {":path", "/"},
        {":scheme", "http"}, {":authority", addr.address().to_string()},
        {"x-const", "v"},    {"x-unique", unique_value(i)},
    };
    co_await client.send_headers(streamid, hdrs, /*endstream=*/true);
    auto rsp = co_await client.receive_rsp();
    REQUIRE(rsp.streamid == streamid);
    REQUIRE(std::ranges::find(rsp.headers, header{"x-const", "v"}) != rsp.headers.end());
  }
}

CLIENT_TEST("client encoder signals table size from server SETTINGS") {
  h2client_options opts = client.get_options();
  // иначе кодировщик создаётся до получения SETTINGS сервера и размер меняется уже штатно
  opts.allow_requests_before_server_settings = false;
  client.set_options(std::move(opts));
  auto server = co_await fake_server_session(ioctx, {localhost()}, client);
  server.set_header_table_size(64 * 1024);
  co_await emulate_server_connection(server);

  std::vector<std::coroutine_handle<>> handles;
  on_scope_exit {
    for (auto h : handles)
      h.destroy();
  };
  for (int i = 0; i < BLOCKS_COUNT; ++i) {
    http_request req;
    req.method = http_method_e::GET;
    req.path = "/";
    req.scheme = scheme_e::HTTP;
    req.authority = client.get_remote().to_string();
    req.headers.push_back(http_header_t{"x-const", "v"});
    req.headers.push_back(http_header_t{"x-unique", unique_value(i)});
    handles.push_back(client.send_request(std::move(req), deadline_after(5s)).start_and_detach(true));

    auto r = co_await server.receive_req();
    REQUIRE(std::ranges::find(r.headers, header{"x-const", "v"}) != r.headers.end());
    REQUIRE(std::ranges::find(r.headers, header{"x-unique", unique_value(i)}) != r.headers.end());
    std::vector<header> status{{":status", "200"}};
    co_await server.send_headers(r.streamid, std::move(status), /*endstream=*/true);
  }
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
