
#include "test_connection.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

// 1. stream 1: блок со сломанным хедером, затем хедера добавляющиеся в динамическую таблицу
// 2. stream 3: обычный запрос который ссылается на индексированные хедера из первого
static dd::task<void> invalid_header_keeps_hpack_state(test_h2connection& client, std::string authority,
                                                       header invalid, bool invalid_first,
                                                       bool expect_reset = true) {
  const std::vector<header> pseudo{
      {":method", "GET"}, {":path", "/"}, {":scheme", "http"}, {":authority", authority}};
  const header before{"x-before", "before-value"};
  const header after1{"x-after-1", "after-value-1"};
  const header after2{"x-after-2", "after-value-2"};

  std::vector<header> hdrs1 = pseudo;
  if (invalid_first)
    hdrs1.push_back(invalid);
  hdrs1.push_back(before);
  if (!invalid_first)
    hdrs1.push_back(invalid);
  hdrs1.push_back(after1);
  hdrs1.push_back(after2);

  auto bytes = client.encode_headers(hdrs1);  // с индексированием
  co_await client.send_raw_hdr(1, bytes, /*end_stream=*/true);
  if (expect_reset) {
    co_await client.receive_rst_stream(1, errc_e::PROTOCOL_ERROR);
  } else {
    auto rsp1 = co_await client.receive_rsp();
    REQUIRE(rsp1.headers[0] == header{":status", "200"});
  }

  std::vector<header> hdrs2 = pseudo;
  hdrs2.push_back(before);
  hdrs2.push_back(after1);
  hdrs2.push_back(after2);

  bytes = client.encode_headers(hdrs2);
  co_await client.send_raw_hdr(3, bytes, /*end_stream=*/true);

  auto rsp = co_await client.receive_rsp();
  REQUIRE(rsp.headers.size() == 4);
  REQUIRE(rsp.headers[0] == header{":status", "200"});
  REQUIRE(rsp.headers[1] == before);
  REQUIRE(rsp.headers[2] == after1);
  REQUIRE(rsp.headers[3] == after2);
}

#define INVALID_HEADER_TEST(NAME, INVALID_FIRST, EXPECT_RESET, ...)                                    \
  SERVER_TEST("invalid header keeps hpack state: " NAME) {                                             \
    auto client = co_await fake_client_connection(ioctx, addr);                                        \
    co_await emulate_client_connection(client);                                                        \
    co_await invalid_header_keeps_hpack_state(client, addr.address().to_string(), header{__VA_ARGS__}, \
                                              INVALID_FIRST, EXPECT_RESET);                            \
  }

// control: valid header, nothing must be rejected
INVALID_HEADER_TEST("control, TE trailers is allowed", false, false, "te", "trailers")

// invalid header right after pseudoheaders (detected in the first loop of parse_http2_request_headers)
INVALID_HEADER_TEST("uppercase letter in name, right after pseudoheaders", true, true, "Bad-Name", "x")
INVALID_HEADER_TEST("space in name, right after pseudoheaders", true, true, "bad name", "x")
INVALID_HEADER_TEST("control char in name, right after pseudoheaders", true, true, "bad\x01name", "x")
INVALID_HEADER_TEST("colon in name, right after pseudoheaders", true, true, "bad:name", "x")
INVALID_HEADER_TEST("connection, right after pseudoheaders", true, true, "connection", "keep-alive")
INVALID_HEADER_TEST("transfer-encoding, right after pseudoheaders", true, true, "transfer-encoding",
                    "chunked")
INVALID_HEADER_TEST("TE other than trailers, right after pseudoheaders", true, true, "te", "gzip")

// invalid header between regular headers (detected in the second loop)
INVALID_HEADER_TEST("uppercase letter in name, between regular headers", false, true, "Bad-Name", "x")
INVALID_HEADER_TEST("space in name, between regular headers", false, true, "bad name", "x")
INVALID_HEADER_TEST("control char in name, between regular headers", false, true, "bad\x01name", "x")
INVALID_HEADER_TEST("colon in name, between regular headers", false, true, "bad:name", "x")
INVALID_HEADER_TEST("connection, between regular headers", false, true, "connection", "keep-alive")
INVALID_HEADER_TEST("transfer-encoding, between regular headers", false, true, "transfer-encoding", "chunked")
INVALID_HEADER_TEST("TE other than trailers, between regular headers", false, true, "te", "gzip")

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
