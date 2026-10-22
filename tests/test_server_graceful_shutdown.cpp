
#include "test_connection.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

// graceful shutdown запрещает только НОВЫЕ стримы. Трейлеры стрима, который уже идёт, должны обрабатываться
// как обычно, иначе запрос не завершится, а клиент получит RST_STREAM(REFUSED_STREAM) для принятого стрима
SERVER_TEST("graceful shutdown does not refuse trailers of active stream") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  std::vector<header> hdrs{
      {":method", "POST"},
      {":path", "/"},
      {":scheme", "http"},
      {":authority", addr.address().to_string()},
  };
  const http_body_bytes body(10, byte_t('a'));
  // тело без END_STREAM, сервер ждёт трейлеры
  co_await client.send_req(1, hdrs, body, /*endstream=*/false);

  co_await client.sync();

  server.shutdown().start_and_detach();
  co_await client.receive_goaway(/*last_streamid=*/1, errc_e::NO_ERROR, ping_e::RESPONSE);

  auto trailers = client.encode_headers({{"x-trailer", "t"}});
  co_await client.send_raw_hdr(1, trailers, /*end_stream=*/true);

  // если трейлеры отклонены, то вместо ответа придёт RST_STREAM
  auto rsp = co_await client.receive_rsp();
  REQUIRE(rsp.streamid == 1);
  REQUIRE(rsp.headers[0] == header{":status", "200"});
  REQUIRE(rsp.body == body);
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
