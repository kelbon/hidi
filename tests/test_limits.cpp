
#include "test_connection.hpp"
#include "fuzzing/fuzzer.hpp"

#include <moko3/moko3.hpp>

#include <boost/stacktrace.hpp>

using namespace hidi;

static server_ssl_context_ptr test_ssl_ctx() {
  return make_ssl_context_for_server(HTTP2_TLS_DIR "/test_server.crt", HTTP2_TLS_DIR "/test_server.key");
}

SERVER_TEST("server bytes limit", test_ssl_ctx()) {
  constexpr size_t LIMIT = 1000;
  // set options before client connection
  server.get_options().limit_requests_memory_usage_bytes = LIMIT;
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  SECTION("regular request") {
    std::vector<header> hdrs{
        {":method", "GET"},
        {":path", "/README.md"},
        {":scheme", "http"},
        {":authority", addr.address().to_string()},
    };
    size_t sum = 0;
    for (auto& [n, v, x] : hdrs) {
      // name.size() not counted internally as used bytes (only for pseudoheader)
      sum += v.size();
    }
    auto hdrs_bytes = client.encode_headers(hdrs);

    // size == LIMIT

    co_await client.send_raw_hdr(1, hdrs_bytes, /*end_stream=*/false);
    std::string data_frame(LIMIT - sum, char(1));
    co_await client.send_data(1, data_frame, /*end_stream=*/true);
    auto rsp = co_await client.receive_rsp();
    REQUIRE(rsp.end_stream);
    REQUIRE(std::ranges::equal(rsp.body, data_frame));
    REQUIRE(rsp.headers.size() == 1 && rsp.headers[0] == header{":status", "200"});

    // size == LIMIT + 1

    hdrs_bytes = client.encode_headers(hdrs);
    co_await client.send_raw_hdr(3, hdrs_bytes, /*end_stream=*/false);
    data_frame.push_back(char(1));
    co_await client.send_data(3, data_frame, /*end_stream=*/true);
    co_await client.receive_rst_stream(3, errc_e::ENHANCE_YOUR_CALM);
  }

  SECTION("overflow in continuations") {
    std::vector<header> hdrs{
        {":method", "GET"},
        {":path", "/README.md"},
        {":scheme", "http"},
        {"big_header", std::string(LIMIT, char(1))},
        {"some_header", "some_value"},
    };

    auto hdrs_bytes = client.encode_headers(hdrs);

    co_await client.send_raw_hdr(1, hdrs_bytes, /*end_stream=*/false);
    co_await client.receive_rst_stream(1, errc_e::ENHANCE_YOUR_CALM);

    // checks that dynamic table in correct state after skipping request
    hdrs[3].value = "";
    hdrs_bytes = client.encode_headers(hdrs);

    co_await client.send_raw_hdr(3, hdrs_bytes, /*end_stream=*/true);
    auto rsp = co_await client.receive_rsp();
    REQUIRE(rsp.end_stream);
    REQUIRE(rsp.body.empty());
    REQUIRE(rsp.headers.size() == 3 && rsp.headers[0] == header{":status", "200"} &&
            rsp.headers[1] == header{"big_header", ""} &&
            rsp.headers[2] == header{"some_header", "some_value"});
  }

  SECTION("overflow in trailers") {
    std::vector<header> hdrs{
        {":method", "GET"},
        {":path", "/README.md"},
        {":scheme", "http"},
        {":authority", addr.address().to_string()},
    };

    co_await client.send_req(1, hdrs, http_body_bytes(10, byte_t(1)), /*endstream=*/false);

    std::vector<header> trailers{
        {"big_header", std::string(LIMIT, char(1))},
    };
    co_await client.send_headers(1, trailers, /*endstream=*/true);

    co_await client.receive_rst_stream(1, errc_e::ENHANCE_YOUR_CALM);
  }

  SECTION("try big header spam") {
    // cache one big header and then encode it into 1 byte many times trying to ddos server
    std::vector<header> hdrs{
        {":method", "GET"},
        {":path", "/README.md"},
        {":scheme", "http"},
        {"big_header", std::string(100, char(1))},
    };
    h2connection_ptr con = client.get_inner_connection();
    bytes_t hdrs_bytes;
    for (auto& h : hdrs)
      con->encoder.encode_header_and_cache(h.name, h.value, std::back_inserter(hdrs_bytes));
    hpack::find_result_t r = con->encoder.dyntab.find(hdrs.back().name, hdrs.back().value);
    REQUIRE(r.value_indexed && r.header_name_index != 0);
    // 50 * ("big_header".len() + 100)) > LIMIT
    for (int i = 0; i < 50; ++i)
      con->encoder.encode_header_fully_indexed(r.header_name_index, std::back_inserter(hdrs_bytes));

    co_await client.send_raw_hdr(1, hdrs_bytes);
    co_await client.receive_rst_stream(1, errc_e::ENHANCE_YOUR_CALM);
  }
}

SERVER_TEST("server sessions limit", test_ssl_ctx()) {
  server.get_options().limit_clients_count = 0;
  auto client = co_await fake_client_connection(ioctx, addr);
  try {
    co_await emulate_client_connection(client);
  } catch (...) {
    co_return;
  }
  // server must drop connection immediately after connect
  co_await client.wait_connection_dropped(deadline_after(1s));
}

SERVER_TEST("server CONTINUATION limit", test_ssl_ctx()) {
  constexpr size_t LIMIT = 100;
  server.get_options().max_continuation_len_bytes = LIMIT;
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);
  constexpr size_t FIRST_CHUNK = 10;
  static_assert(FIRST_CHUNK < LIMIT);
  bytes_t headers(FIRST_CHUNK, 'a');  // data makes no sense here

  // send HEADERS without END_HEADERS
  h2test_frame f;
  f.hdr.length = uint32_t(headers.size());
  f.hdr.type = frame_e::HEADERS;
  f.hdr.flags = flags::EMPTY_FLAGS;  // no END_HEADERS
  f.hdr.streamid = 1;
  f.hdr.flags |= flags::END_STREAM;
  f.data.assign(headers.begin(), headers.end());
  co_await client.send_frame(std::move(f));

  SECTION("overlimit") {
    headers.resize(LIMIT, 'a');
    co_await client.send_raw_continuation(1, headers, /*end_headers=*/true);
    co_await client.receive_goaway(MAX_STREAM_ID, errc_e::ENHANCE_YOUR_CALM, ping_e::RESPONSE);
  }
  SECTION("headers.size() == LIMIT") {
    headers.resize(LIMIT - FIRST_CHUNK, 'a');
    co_await client.send_raw_continuation(1, headers, /*end_headers=*/true);
    // invalid headers block, but request accepted and parsed
    co_await client.receive_goaway(1, errc_e::COMPRESSION_ERROR, ping_e::RESPONSE);
  }
}

SERVER_TEST("big requests") {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);
  fuzzing::fuzzer fuz;
  stream_id_t id = 1;
  constexpr int COUNT = 100;
  std::unordered_map<stream_id_t, size_t> expected_hashs;
  for (int i = 0; i < COUNT; ++i) {
    std::string body = fuz.rstring(fuz.rint(13, 200) * 1024 /*KB*/);
    size_t hash = std::hash<std::string_view>{}(body);
    std::vector<header> hdrs{
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "http"},
        {":authority", addr.address().to_string()},
        {std::string(EXPECTED_BODY_HASH_HDR), std::format("{}", hash)},
    };
    http_body_bytes bytes(body.begin(), body.end());
    expected_hashs[id] = hash;
    client.send_req(id, std::move(hdrs), std::move(bytes)).start_and_detach();
    id += 2;
  }
  std::unordered_map rsps = co_await client.receive_streams(COUNT);
  for (auto& [streamid, rsp] : rsps)
    REQUIRE(std::hash<std::string_view>{}(rsp.body_strview()) == expected_hashs[streamid]);
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);

int main(int argc, char* argv[]) {
  auto& box = ::moko3 ::get_testbox();
  box.parse_config(argc, argv);
  return box.run_tests();
}
