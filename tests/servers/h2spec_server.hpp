#pragma once

#include "hidi/h2server.hpp"
#include "hidi/asio/awaiters.hpp"
#include <charconv>

namespace hidi {

inline dd::channel<std::span<const byte_t>> streambody() {
  std::string_view answer = "hello world";
  for (const char& c : answer)
    co_yield {(const byte_t*)&c, 1};
}

struct h2spec_server : h2server {
  using h2server::h2server;
  bool answer_stream = false;

  explicit h2spec_server(log_context ctx = log_context{})
      : h2server(nullptr, h2server_options{
            .max_receive_frame_size = MIN_MAX_FRAME_LEN,  // enables FRAME_SIZE tests
            .max_concurrent_streams = 10,                 // enables h2spec test for it
            .logctx = std::move(ctx),
        }) {
  }

  dd::task<http_response> handle_request(http_request r, request_context ctx) override {
    answer_stream = !answer_stream;
    // some specific h2 test for content-length, which i dont want to handle in server
    auto hdr = std::ranges::find(r.headers, "content-length", &http_header_t::hname);
    if (hdr != r.headers.end()) {
      std::string_view len = hdr->hvalue;
      size_t value;
      auto [ptr, ec] = std::from_chars(len.data(), len.data() + len.size(), value);
      if (ec != std::errc{} || value != r.body.data.size())
        throw stream_error(errc_e::PROTOCOL_ERROR, ctx.streamid(),
                           "\"content-length\" does not equal to DATA len");
    }
    if (answer_stream)
      co_return ctx.stream_response(200, {}, streambody());
    http_response rsp;
    rsp.status = 200;
    std::string_view answer = "hello world";
    auto* in = answer.data();
    rsp.body.assign(in, in + answer.size());
    co_return rsp;
  }
};

}  // namespace hidi
