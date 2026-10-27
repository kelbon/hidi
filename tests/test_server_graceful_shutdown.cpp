
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

// после начала graceful shutdown новый стрим отклоняется с REFUSED_STREAM, чтобы клиент мог повторить запрос
// на другом соединении (STREAM_CLOSED повторять нельзя)
SERVER_TEST("graceful shutdown refuses new streams") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  std::vector<header> hdrs{
      {":method", "POST"},
      {":path", "/"},
      {":scheme", "http"},
      {":authority", addr.address().to_string()},
  };
  // активный стрим не даёт сессии завершиться сразу после GOAWAY
  co_await client.send_req(1, hdrs, http_body_bytes(10, byte_t('a')), /*endstream=*/false);
  co_await client.sync();

  server.shutdown().start_and_detach();
  co_await client.receive_goaway(/*last_streamid=*/1, errc_e::NO_ERROR, ping_e::RESPONSE);

  co_await client.send_req(3, hdrs);
  co_await client.receive_rst_stream(3, errc_e::REFUSED_STREAM);
  // HPACK декодер сервера не сломан: трейлеры активного стрима обрабатываются
  auto trailers = client.encode_headers({{"x-trailer", "t"}});
  co_await client.send_raw_hdr(1, trailers, /*end_stream=*/true);
  REQUIRE((co_await client.receive_rsp()).streamid == 1);
}

// стрим, который никогда не завершится (клиент не досылает тело), не даёт мягкой остановке закончиться.
// Её завершает дедлайн или terminate
SERVER_TEST("shutdown with stuck stream") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  std::vector<header> hdrs{
      {":method", "POST"},
      {":path", "/"},
      {":scheme", "http"},
      {":authority", addr.address().to_string()},
  };
  co_await client.send_req(1, hdrs, http_body_bytes(10, byte_t('a')), /*endstream=*/false);
  co_await client.sync();

  SECTION("deadline") {
    auto h = server.shutdown(deadline_after(100ms)).start_and_detach(/*stop_at_end=*/true);
    on_scope_exit {
      // при провале теста shutdown ещё ждёт, его завершит разрушение сервера
      if (h.done())
        h.destroy();
    };
    co_await wait_until([&] { return h.done(); }, ioctx);
  }
  SECTION("terminate") {
    auto h = server.shutdown().start_and_detach(/*stop_at_end=*/true);
    on_scope_exit {
      // при провале теста shutdown ещё ждёт, его завершит разрушение сервера
      if (h.done())
        h.destroy();
    };
    co_await net.sleep(ioctx, 100ms);
    REQUIRE(!h.done());
    co_await server.terminate();
    co_await wait_until([&] { return h.done(); }, ioctx);
  }
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
