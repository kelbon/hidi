
#include "test_connection.hpp"
#include <moko3/moko3.hpp>

using namespace hidi;
using namespace std::chrono_literals;

// свой сервер, так как дефолтный - эхо
struct connect_capable_server : h2server {
  using h2server::h2server;
  dd::task<http_response> handle_request(http_request, request_context) override {
    co_return http_response{.status = 200};
  }
};

static dd::task<void> extended_connect_ordering_body(internet_address addr, any_io_context_ref ioctx);

TEST("extended_connect_protocol_header_ordering") {
  connect_capable_server server(h2server_options{}, make_asio_io_context());
  internet_address addr(asio::ip::address_v4::loopback(), 0);
  addr = server.listen({.addr = addr, .reuse_address = true});
  bool ended = false;
  std::exception_ptr ex;
  (void)run_test("extended_connect_protocol_header_ordering",
                 extended_connect_ordering_body(addr, *&server.ioctx()), ended, ex);
  deadline_t deadline =
      deadline_after(moko3::get_testbox().test_timeout("extended_connect_protocol_header_ordering"));
  fuzzing::fuzzer fuz(moko3::get_testbox().randg());
  fuz.run_until(deadline, ended, server.ioctx());
  if (ex)
    std::rethrow_exception(std::move(ex));
}

dd::task<void> extended_connect_ordering_body(internet_address addr, any_io_context_ref ioctx) {
  auto client = co_await fake_client_connection(ioctx, addr);
  co_await emulate_client_connection(client);

  // :protocol посередине псевдохедеров
  std::vector<header> hdrs{{":method", "CONNECT"},
                           {":protocol", "websocket"},
                           {":scheme", "https"},
                           {":authority", addr.address().to_string()},
                           {":path", "/ws"}};
  auto raw = client.encode_headers(hdrs);
  // send_raw_hdr для сохранения порядка хедеров
  co_await client.send_raw_hdr(1, raw, /*end_stream=*/true);

  auto rsp = co_await client.receive_rsp(testdeadline(5s));
  REQUIRE(rsp.find_hdr(":status") == "200");
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
