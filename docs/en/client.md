# Client

`hidi::h2client` holds one connection to the server and establishes it by itself on a request if it is not connected

The interface is described in detail in [h2client.hpp](../../include/hidi/h2client.hpp)

## Example

```cpp
#include <print>

#include <hidi/h2client.hpp>

dd::task<void> get(hidi::h2client& client) {
  hidi::http_request req{.path = "/hello"};
  hidi::http_response rsp =
      co_await client.send_request(std::move(req), hidi::deadline_after(std::chrono::seconds(5)));
  std::println("{} {}", rsp.status, rsp.body_strview());
  client.ioctx().stop();
}

int main() {
  hidi::h2client client(hidi::endpoint(std::string("example.com"), 443),
                        hidi::make_ssl_context_for_client({}));
  get(client).start_and_detach();
  client.ioctx().run();
}
```

- `nullptr` instead of the TLS context - client without TLS
- `send_request(req, deadline)` throws an exception on error. The version with `on_header` / `on_data_part`
  receives the response in parts and returns the status, and on error - an error code

## Request streaming

The request body is sent in parts from a channel:

```cpp
hidi::streaming_body_t greeting() {
  co_yield std::string_view("hello, ");
  co_yield std::string_view("world");
}

dd::task<void> send(hidi::h2client& client) {
  hidi::http_request req{.path = "/greet", .method = hidi::http_method_e::POST};
  hidi::http_response rsp = co_await client.send_streaming_request(
      std::move(req), greeting(), hidi::deadline_after(std::chrono::seconds(5)));
}
```

## CONNECT

`send_connect_request` opens a tunnel (CONNECT or extended CONNECT, for example websocket)

```cpp
dd::task<void> tunnel(hidi::h2client& client) {
  hidi::http_request req{.path = "/chat", .method = hidi::http_method_e::CONNECT};
  req.headers = {{":protocol", "websocket"}};
  // called after HEADERS are received from the server. Future data is represented by the queue `q`
  // data returned through co_yield is sent to the server
  auto makestream = [](hidi::http_response, hidi::memory_queue_ptr q,
                       hidi::request_context) -> hidi::streaming_body_t {
    co_yield std::string_view("ping");
    auto answer = co_await q->next_chunk();
  };
  int status = co_await client.send_connect_request(std::move(req), std::move(makestream));
}
```

## Options

Client options are described in detail in [h2client_options.hpp](../../include/hidi/h2client_options.hpp)
