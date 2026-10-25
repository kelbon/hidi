
#include "hidi/h2server.hpp"
#include "fuzzer.hpp"
#include "hidi/asio/asio_executor.hpp"
#include "hidi/h2client.hpp"

#include <boost/stacktrace.hpp>
#include <csignal>
#include <iostream>

#include <moko3/moko3.hpp>

using namespace hidi;
using namespace std::chrono_literals;
using namespace std::string_view_literals;

#define error_if(...)                          \
  if ((__VA_ARGS__)) {                         \
    std::cout << "ERROR ON LINE " << __LINE__; \
    std::exit(__LINE__);                       \
  }

struct bistream_test_server : h2server {
  using h2server::h2server;

  bool answer_before_data(const http_request&) const noexcept override {
    return true;
  }

  static streaming_body_t stream_body(memory_queue_ptr q, request_context ctx) {
    while (!q->last_chunk_received()) {
      auto c = co_await q->next_chunk();
      co_yield c;
    }
    // клиент завершил данные END_STREAM
    REQUIRE(!q->aborted());
  }

  dd::task<std::pair<http_response, bistream_body_maker_t>> handle_request_stream(
      http_request req, memory_queue_ptr q, request_context ctx) override {
    co_await ctx.send_interim_response(100);
    http_response rsp;
    rsp.status = 200;
    rsp.headers = std::move(req.headers);
    rsp.headers.push_back({"ok", "accepted"});
    co_return {std::move(rsp), std::bind_front(&stream_body, q)};
  }

  dd::task<http_response> handle_request(http_request req, request_context ctx) override {
    REQUIRE(false);
    throw 0;
  }
};

inline size_t requests_done = 0;

static streaming_body_t do_request(http_response rsp, memory_queue_ptr q, request_context) {
  REQUIRE(rsp.status == 200);
  REQUIRE(rsp.headers == http_headers_t{{"abc", "edf"}, {"ok", "accepted"}});
  std::string data = "hello world data word big liloaf";

  for (char& c : data)
    co_yield {(byte_t*)&c, 1};
  std::string received;
  while (data != received) {
    auto c = co_await q->next_chunk();
    received.insert(received.end(), c.begin(), c.end());
  }
  REQUIRE(received == data);
}

std::atomic<bool> done = false;

dd::task<void> run_one_request(h2client& c) {
  http_request req;
  req.authority = "abcd";
  req.method = hidi::http_method_e::CONNECT;
  req.headers.push_back({"abc", "edf"});
  int status = co_await c.send_connect_request(std::move(req), &do_request);
  REQUIRE(status == 200);
  ++requests_done;
}

dd::task<void> run_requests(h2client& client, size_t count, asio::ip::tcp::endpoint endpoint) {
  on_scope_exit {
    done = true;
  };
  size_t i = 0;
  while (requests_done != count) {
    if (i < count) {
      ++i;
      run_one_request(client).start_and_detach();
    }
    co_await yield_on_ioctx(*&client.ioctx());
  }
}

inline const asio::ip::tcp::endpoint addr(asio::ip::address_v6::loopback(), 8080);
inline fuzzing::fuzzer fuz;

static void test_connect_requests() {
  bistream_test_server server(h2server_options{.idle_timeout = std::chrono::seconds(50000)});

  server.listen(server_endpoint{.addr = addr, .reuse_address = true});
  h2client client(addr, {.ping_interval = duration_t::max(), .allow_requests_before_server_settings = true});
  run_requests(client, 100, addr).start_and_detach();

  fuz.run_until([] { return done.load(); }, server.ioctx(), client.ioctx());
}

struct wait_rst_server : h2server {
  using h2server::h2server;

  dd::task<http_response> handle_request(http_request req, request_context ctx) override {
    while (!ctx.canceled())
      co_await yield_on_ioctx(*&this->ioctx());
    throw std::runtime_error("error");
  }
};

static streaming_body_t body0() {
  co_return;
}
static streaming_body_t body1() {
  auto bytes = fuz.rbytes(100);
  co_yield bytes;
}
static streaming_body_t body3() {
  co_yield dd::elements_of(body1());
  co_yield dd::elements_of(body0());
  co_yield dd::elements_of(body1());
}

static dd::generator<dd::task<http_response>> different_requests(h2client& client,
                                                                 std::chrono::milliseconds timeout) {
  http_request r;
  r.path = "/abc";
  r.method = hidi::http_method_e::PUT;
  r.body.content_type = "text/plain";
  r.body.data.resize(15, byte_t(1));
  auto deadline = [&] { return deadline_after(timeout); };

  // regular PUT request with body
  co_yield client.send_request(r, deadline());

  // request without body
  r.body = {};
  co_yield client.send_request(r, deadline());

  // streaming request without trailers
  co_yield client.send_streaming_request(r, body0(), deadline());

  co_yield client.send_streaming_request(r, body1(), deadline());

  co_yield client.send_streaming_request(r, body3(), deadline());

  http_headers_t trailers{{"grpc-status", "OK"}};

  co_yield client.send_streaming_request(r, streaming_body_with_trailers(body0(), trailers), deadline());

  co_yield client.send_streaming_request(r, streaming_body_with_trailers(body1(), trailers), deadline());

  co_yield client.send_streaming_request(r, streaming_body_with_trailers(body3(), trailers), deadline());
}

template <typename T>
static dd::task<void> executetask(dd::task<T> t, bool& done, T& result, std::string& errmsg) {
  assert(!!t);
  errmsg.clear();
  result = T{};
  done = false;
  try {
    result = co_await t;
  } catch (std::exception& e) {
    errmsg = e.what();
  }
  done = true;
}

static void test_rst_stream(std::shared_ptr<h2server> server, h2client& client) {
  for (dd::task x : different_requests(client, 10ms)) {
    bool done = false;
    std::string errmsg;
    http_response rsp;
    executetask(std::move(x), done, rsp, errmsg).start_and_detach();
    fuz.run_until(done, server->ioctx(), client.ioctx());
    error_if(errmsg != "timeout"sv);
  }
  client.cancel_all();
  server.reset();
}

static void test_rst_stream() {
  // отсылаю разные запросы, сервер не отвечает, срабатывает таймаут
  // клиент отсылает  rst_stream для таймаутных запросов
  // сервер видит .canceled и прекращает обработку (тоже отсылает rst_stream т.к. бросается ошибка из
  // обработки)
  {
    std::shared_ptr server = std::make_shared<wait_rst_server>();
    server->listen({addr});
    h2client client(addr, {.allow_requests_before_server_settings = false});

    test_rst_stream(std::move(server), client);
  }
  {
    std::shared_ptr server = std::make_shared<wait_rst_server>();
    server->listen({addr});
    h2client client(addr, {.allow_requests_before_server_settings = true});
    test_rst_stream(std::move(server), client);
  }
  // with connection before
  {
    std::shared_ptr server = std::make_shared<wait_rst_server>();
    server->listen({addr});

    h2client client(addr, {.allow_requests_before_server_settings = false});
    auto h = client.try_connect().start_and_detach(/*stop_at_end=*/true);
    while (!h.done()) {
      client.ioctx().poll_one();
      server->ioctx().poll_one();
    }
    error_if(h.promise().result() != true);
    h.destroy();

    test_rst_stream(std::move(server), client);
  }
  {
    std::shared_ptr server = std::make_shared<wait_rst_server>();
    server->listen({addr});

    h2client client(addr, {.allow_requests_before_server_settings = true});
    auto h = client.try_connect().start_and_detach(/*stop_at_end=*/true);
    while (!h.done()) {
      client.ioctx().poll_one();
      server->ioctx().poll_one();
    }
    error_if(h.promise().result() != true);
    h.destroy();

    test_rst_stream(std::move(server), client);
  }
}

void segfault_handler(int sig) {
  std::cerr << "segfault, stacktrace:\n" << boost::stacktrace::stacktrace() << '\n';
  std::exit(1);
}

int main() {
  std::signal(SIGSEGV, segfault_handler);

  test_rst_stream();
  test_connect_requests();
}
