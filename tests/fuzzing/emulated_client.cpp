#include "emulated_client.hpp"
#include "hidi/asio/asio_executor.hpp"
#include "hidi/asio/awaiters.hpp"

#include <kelcoro/algorithm.hpp>
#include <moko3/moko3.hpp>

using namespace std::chrono_literals;

namespace hidi::fuzzing {

static void validate_echo_request(const hreq& req, http_response rsp) {
  if (!req.request.body.content_type.empty()) {
    // content-type should be encoded first (after pseudoheaders, until custom headers)
    // so it should be retunred first, but request.headers does not contain it (must not)
    REQUIRE(!rsp.headers.empty() &&
            rsp.headers.front() == http_header_t{"content-type", req.request.body.content_type});
    rsp.headers.erase(rsp.headers.begin());
  }
  REQUIRE(rsp.headers == req.request.headers);
  REQUIRE(rsp.status == 200);
  REQUIRE(rsp.body == req.request.body.data);
}

dd::task<void> send_echo_request(fuzzer& fuz, h2client& c, hreq req) try {
  assert(req.is_valid);  // TODO not supported yet?
  if (!req.trailers.empty())
    co_return co_await send_echo_request_as_stream(fuz, c, std::move(req));

  http_response rsp = co_await c.send_request(req.request, req.deadline);

  validate_echo_request(req, std::move(rsp));
} catch (std::exception& e) {
  REQUIRE(false);
}

static streaming_body_t as_streaming_body(dd::channel<std::span<const byte_t>> c) {
  auto b = co_await c.begin();
  for (; b != c.end(); (void)(co_await (++b)))
    co_yield *b;
}

// sends requests, but body will be splitted into random chunks
dd::task<void> send_echo_request_as_stream(fuzzer& fuz, h2client& c, hreq req) try {
  auto sleepcb = [&c](duration_t d, io_error_code& ec) -> dd::task<void> {
    any_timer timer = c.ioctx().create_timer();
    co_await net.sleep(timer, d, ec);
  };
  auto bodystr = streaming_body_with_trailers(
      as_streaming_body(fuz.chunks_delayed(req.request.body.data, 0, 30, sleepcb)), req.trailers);
  req.request.body = {};
  http_response rsp = co_await c.send_streaming_request(req.request, std::move(bodystr), req.deadline);
  validate_echo_request(req, std::move(rsp));
} catch (std::exception& e) {
  REQUIRE(false);
}

static move_only_fn<streaming_body_t(http_response, memory_queue_ptr, request_context)> do_makestream(
    fuzzer& fuz, http_headers_t hdrs) {
  return [&fuz, hdrs = std::move(hdrs)](http_response rsp, memory_queue_ptr q,
                                        request_context ctx) -> streaming_body_t {
    REQUIRE(rsp.status == 200);
    REQUIRE(hdrs == rsp.headers);
    REQUIRE(rsp.body.empty());
    std::string sent;
    std::string received;
    size_t count = fuz.rindex(200);
    for (size_t i = 0; i < count; ++i) {
      if (fuz.rbool()) {
        std::string s = fuz.rstring(fuz.rint(1, 200));
        co_yield s;
      } else if (received.size() != sent.size()) {
        std::vector s = co_await q->next_chunk();
        received.append(s.begin(), s.end());
      }
    }
    while (received.size() != sent.size()) {
      std::vector s = co_await q->next_chunk();
      received.append(s.begin(), s.end());
    }
    // echo server
    REQUIRE(received == sent);
    co_return;
  };
}

// sends request, but body will be splitted into random chunks + expects server answers stream
dd::task<void> send_echo_request_connect(fuzzer& fuz, h2client& c, hreq req, bool websocket) try {
  if (websocket) {
    auto& hdrs = req.request.headers;
    req.request.method = http_method_e::CONNECT;
    hdrs.insert(hdrs.begin(), http_header_t{{":protocol", "websocket"}});
  } else {
    req.request.path = {};
    req.request.method = http_method_e::CONNECT;
    req.request.authority = "some.api";
  }
  req.request.body.data = {};  // do_makestream ignores data and sent smth random generated
  int x = co_await c.send_connect_request(req.request, do_makestream(fuz, req.request.headers));
  REQUIRE(x == 200);
} catch (std::exception& e) {
  REQUIRE(false);
}

struct incr {
  size_t* x = nullptr;

  incr(size_t& v) noexcept : x(&v) {
  }

  incr(incr&& other) noexcept : x(std::exchange(other.x, nullptr)) {
  }

  incr& operator=(incr&& other) noexcept {
    std::swap(x, other.x);
    return *this;
  }

  ~incr() {
    if (x)
      ++*x;
  }
};

dd::task<void> emulate_client_n(fuzzer& fuz, h2client& client, any_reqtem tem, size_t request_count,
                                size_t max_active_streams, req_weights weights) {
  std::discrete_distribution<int> dist({weights.regular, weights.stream, weights.connect});
  // receive server settings before (to get correct max_count_requests_allowed)
  bool b = co_await client.try_connect();
  REQUIRE(b);
  size_t done = 0;
  size_t sent = 0;
  while (sent != request_count) {
    if (sent != request_count && request_count >= client.count_active_requests() &&
        client.count_active_requests() < max_active_streams) {
      dd::task<void> task;
      switch (dist(fuz.g)) {
        case 0:
          task = send_echo_request(fuz, client, tem.generate_request(fuz));
          break;
        case 1:
          task = send_echo_request_as_stream(fuz, client, tem.generate_request(fuz));
          break;
        case 2:
          task =
              send_echo_request_connect(fuz, client, tem.generate_request(fuz), /*websocket=*/fuz.rbool(0.3));
          break;
      }
      ++sent;
      dd::with(std::move(task), incr(done)).start_and_detach();
    }
    co_await yield_on_ioctx(*&client.ioctx());
  }
  while (done != request_count)
    co_await yield_on_ioctx(*&client.ioctx());
  co_await client.graceful_stop();
}

dd::task<void> emulate_client(fuzzer& fuz, h2client& client, any_reqtem tem, duration_t dur,
                              size_t max_active_streams, req_weights weights) {
  size_t done = 0;
  std::discrete_distribution<int> dist({weights.regular, weights.stream, weights.connect});
  deadline_t deadline = deadline_after(dur);
  // receive server settings before (to get correct max_count_requests_allowed)
  bool b = co_await client.try_connect();
  REQUIRE(b);
  while (!deadline.is_reached()) {
    while (!deadline.is_reached() && client.count_active_requests() < max_active_streams) {
      dd::task<void> task;
      switch (dist(fuz.g)) {
        case 0:
          task = send_echo_request(fuz, client, tem.generate_request(fuz));
          break;
        case 1:
          task = send_echo_request_as_stream(fuz, client, tem.generate_request(fuz));
          break;
        case 2:
          task =
              send_echo_request_connect(fuz, client, tem.generate_request(fuz), /*websocket=*/fuz.rbool(0.3));
          break;
      }
      dd::with(std::move(task), incr(done)).start_and_detach();
    }
    co_await yield_on_ioctx(*&client.ioctx());
  }
  co_await client.graceful_stop();
  co_return;
}

}  // namespace hidi::fuzzing
