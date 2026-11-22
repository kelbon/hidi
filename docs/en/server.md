# Server

A single-threaded server is created as a descendant of `hidi::h2server` that overrides at least `handle_request`. Interface details are in
[h2server.hpp](../../include/hidi/h2server.hpp)

A multithreaded server is created from a single-threaded one with `hidi::h2server_mt`

```cpp
#include <hidi/h2server.hpp>

struct my_server : hidi::h2server {
  using hidi::h2server::h2server;

  dd::task<hidi::http_response> handle_request(hidi::http_request req, hidi::request_context) override {
    hidi::http_response rsp;
    rsp.status = 200;
    rsp.headers = {{"content-type", "text/plain"}};
    std::string body = "hello from " + req.path;
    rsp.body.assign(body.begin(), body.end());
    co_return rsp;
  }
};

int main() {
  // a thread per core, my_server is created on each thread from the passed arguments
  hidi::h2server_mt server(std::in_place_type<my_server>,
                           hidi::make_ssl_context_for_server("server.crt", "server.key"));
  server.listen(hidi::server_endpoint{.addr = {boost::asio::ip::address_v4::any(), 443}});
  server.run();
}
```

- `nullptr` instead of the TLS context - server without TLS
- `my_server` can be used directly as a single-threaded server - `listen`, then `run`
- stopping: `request_stop` (new sessions are not accepted, current requests are completed)

## Response streaming

The body is sent in parts from a channel (`dd::channel`). The channel may fill in trailers

```cpp
hidi::streaming_body_t by_parts(std::span<const hidi::byte_t> data) {
  for (auto part : data | std::views::chunk(16 * 1024))
    co_yield part;
}

dd::task<hidi::http_response> handle_request(hidi::http_request, hidi::request_context ctx) override {
  // to send trailers use streaming_body_with_trailers(by_parts(big_data), <trailer headers>)
  // if trailers have to be computed from the body, use another stream_response overload instead of the helper
  co_return ctx.stream_response(200, {}, by_parts(big_data));
}
```

## Request streaming and CONNECT

To get a request right after its headers (before the data), override `answer_before_data` and return `true`.

Then `handle_request_stream` is called instead of `handle_request`: the request
body arrives in parts through `memory_queue`, and the response is a channel too. CONNECT and websocket work the same way
(for the client to see that the server supports websocket, use the `supports_websocket` option)

```cpp
bool answer_before_data(const hidi::http_request& r) const noexcept override {
  return r.method == hidi::http_method_e::CONNECT;
}

// echo: returns everything the client sent
static hidi::streaming_body_t echo(hidi::memory_queue_ptr q, hidi::request_context) {
  while (!q->last_chunk_received()) {
    auto data = co_await q->next_chunk();
    co_yield data;
  }
}

dd::task<std::pair<hidi::http_response, hidi::bistream_body_maker_t>> handle_request_stream(
    hidi::http_request, hidi::memory_queue_ptr q, hidi::request_context) override {
  hidi::http_response rsp;
  rsp.status = 200;
  co_return {std::move(rsp), std::bind_front(&echo, q)};
}
```

## Options

Server options are described in detail in [h2server_options.hpp](../../include/hidi/h2server_options.hpp)

`h2server_options::hardened()` is worth a separate mention - a ready-made set of options for protecting a server exposed to the open internet
