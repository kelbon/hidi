#include "hidi/h2client.hpp"
#include "hidi/h2server.hpp"
#include <fuzzer.hpp>

#include <iostream>

#define error_if(...)                                       \
  if ((__VA_ARGS__)) {                                      \
    std::cout << "ERROR ON LINE " << __LINE__ << std::endl; \
    std::exit(__LINE__);                                    \
  }

using namespace hidi;

// all noinlines here is workaround gcc-12 bug (miscompilation)
#define GCC_WORKAROUND [[gnu::noinline]]

constexpr inline std::string_view STREAM_REQUEST_PATH = "/bcd";
constexpr inline std::string_view REQUEST_PATH = "/abc";

const inline http_headers_t EXPECTED_HEADERS{
    http_header_t{"hash", "55555"},
    http_header_t{"ok", "yes"},
    http_header_t{"content-type", "mycontent/type"},
};

const inline http_headers_t EXPECTED_CONNECT_HEADERS{
    http_header_t{":protocol", "websocket"},
    http_header_t{"some-special-hdr", "chat, superchat"},
};

constexpr inline std::string_view EXPECTED_DATA = "hello world!";

GCC_WORKAROUND http_response answer_req(http_request req) {
  http_response rsp;
  if (req.path == REQUEST_PATH && req.method == http_method_e::GET) {
    rsp.status = 200;
    rsp.headers = EXPECTED_HEADERS;
    rsp.body.insert(rsp.body.end(), EXPECTED_DATA.begin(), EXPECTED_DATA.end());
    error_if(!req.body.data.empty());
  } else if (req.path == STREAM_REQUEST_PATH) {
    rsp.status = 200;
    error_if(req.headers != EXPECTED_HEADERS);
    error_if(std::string(req.body.strview()) != EXPECTED_DATA);
    // echo
    rsp.headers = req.headers;
    rsp.body = req.body.data;
  } else {
    error_if(true);
  }

  return rsp;
}

static streaming_body_t handle_connect_request(memory_queue_ptr q, request_context ctx) {
  while (!q->last_chunk_received()) {
    auto chunk = co_await q->next_chunk();
    co_yield chunk;
  }
}

struct test_server : h2server {
  using h2server::h2server;

  bool answer_before_data(const http_request& r) const noexcept override {
    return r.method == hidi::http_method_e::CONNECT;
  }

  dd::task<std::pair<http_response, bistream_body_maker_t>> handle_request_stream(
      http_request req, memory_queue_ptr q, request_context ctx) override {
    error_if(req.headers != EXPECTED_CONNECT_HEADERS);
    error_if(!req.body.data.empty());
    error_if(req.path != "/ada");
    http_response rsp;
    rsp.status = 200;
    rsp.headers = {{"okay", "accepted"}};
    co_return {std::move(rsp), std::bind_front(&handle_connect_request, q)};
  }

  dd::task<http_response> handle_request(http_request req, request_context ctx) override {
    error_if(req.method == hidi::http_method_e::CONNECT);
    http_response rsp = answer_req(std::move(req));
    co_return rsp;
  }
};

inline bool all_good = false;

GCC_WORKAROUND dd::task<http_response> make_test_request(h2client& client) {
  http_request req{
      .path = std::string(REQUEST_PATH),
      .method = http_method_e::GET,
  };
  return client.send_request(std::move(req), deadline_t::never());
}

GCC_WORKAROUND void check_response(const http_response& rsp) {
  error_if(rsp.headers != EXPECTED_HEADERS);
  error_if(!std::ranges::equal(EXPECTED_DATA, rsp.body));
}

void check_streaming_response(const http_response& rsp) {
  error_if(rsp.status != 200);
  error_if(rsp.headers != EXPECTED_HEADERS);
  error_if(rsp.body_strview() != EXPECTED_DATA);
}

streaming_body_t makebody(http_headers_t& trailers) {
  for (const char& c : EXPECTED_DATA)
    co_yield {(const byte_t*)&c, 1};
  trailers = EXPECTED_HEADERS;
}

dd::task<http_response> make_test_stream_request(h2client& client) {
  http_request req{
      .path = std::string(STREAM_REQUEST_PATH),
      .method = http_method_e::PUT,
  };
  req.body.content_type = "text/plain";
  auto body = [](http_headers_t& trailers, request_context) { return makebody(trailers); };
  co_return co_await client.send_streaming_request(std::move(req), body, deadline_t::never());
}

streaming_body_t websocket_connect_test(http_response rsp, memory_queue_ptr q, request_context) {
  error_if(!rsp.body.empty());
  error_if(rsp.status != 200);
  error_if(rsp.headers != http_headers_t{{"okay", "accepted"}});

  std::string data = "hello world!";

  for (size_t i = 0; i < data.size(); ++i) {
    co_yield {(byte_t*)&data[i], 1};
    auto s = co_await q->next_chunk();
    error_if(s.size() != 1);
    error_if(s.front() != data[i]);
    error_if(q->last_chunk_received());
  }
}

dd::task<void> make_test_websocket_request(h2client& client) {
  http_request req;
  req.headers = EXPECTED_CONNECT_HEADERS;
  req.path = "/ada";
  req.method = http_method_e::CONNECT;
  int status = co_await client.send_connect_request(std::move(req), &websocket_connect_test);
  error_if(status != 200);  // server accepted request
}

dd::task<void> main_coro(h2client& client) {
  http_response rsp = co_await make_test_request(client);
  check_response(rsp);

  rsp = co_await make_test_stream_request(client);
  check_streaming_response(rsp);

  co_await make_test_websocket_request(client);

  all_good = true;
  std::cout << "SUCCESS" << std::endl;
}

int main() try {
  std::thread([] {
    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::cout << "TEST TIMEOUT" << std::endl;
    std::exit(-1);
  }).detach();

  namespace asio = boost::asio;

  h2client_options opts{};
  h2client client(endpoint("localhost", 8080), nullptr, std::move(opts));

  test_server server(nullptr /*no https*/, {});

  asio::ip::tcp::endpoint ipv6_endpoint(asio::ip::address_v6::loopback(), 8080);
  server.listen(server_endpoint{.addr = ipv6_endpoint, .reuse_address = true});

  main_coro(client).start_and_detach();
  fuzzing::fuzzer fuz;
  fuz.run_until([&] { return all_good; }, server.ioctx(), client.ioctx());

  return 0;
} catch (std::exception& e) {
  std::cout << "ERROR: " << e.what() << std::endl;
  return 9;
}
