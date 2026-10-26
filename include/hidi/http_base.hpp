
#pragma once

#include "hidi/http_body.hpp"
#include "hidi/utils/fn_ref.hpp"
#include "hidi/utils/memory_queue.hpp"

#include <string_view>
#include <vector>

#include <format>
#include <algorithm>

#include <kelcoro/channel.hpp>

namespace hidi {

[[nodiscard]] static constexpr bool is_lowercase(std::string_view s) noexcept {
  auto isuppercasechar = [](char c) { return c >= 'A' && c <= 'Z'; };
  return std::none_of(s.begin(), s.end(), isuppercasechar);
}

struct reqerr_e {
  enum values_e : int {
    DONE = 0,                       //
    CANCELLED = -1,                 // e.g. handle.destroy() in HTTP/2
    TIMEOUT = -3,                   //
    NETWORK_ERR = -4,               //
    PROTOCOL_ERR = -5,              // http protocol error
    SERVER_CANCELLED_REQUEST = -6,  // for example rst_stream received
    UNKNOWN_ERR = -7,               // something like bad alloc maybe
  };

  // used for request nodes in server implementation
  enum server_request_progress_e : int {
    // стрим без владельца (detach), сохранён в con.responses
    REQUEST_CREATED = -10,
    // запрос СОБРАН (assembled), корутина send_response создана и владеет стримом
    RESPONSE_IN_PROGRESS = -11,
  };
};

std::string_view e2str(reqerr_e::values_e e) noexcept;

enum struct http_method_e : uint8_t {
  // написано для общей информации, библиотеке на это плевать
  // S = Safe, ничего не меняет на сервере
  // I - Idempotent повторые запросы после первого не изменяют состояние
  // C - Cacheable
  GET,      // S I C
  POST,     // - - -
  PUT,      // - I -
  DELETE,   // - I -
  PATCH,    // - - -
  OPTIONS,  // S I -
  HEAD,     // S I C
  CONNECT,  // - - -
  TRACE,    // S I -
  // https://datatracker.ietf.org/doc/rfc10008/
  QUERY,    // S I C (GET без исторического идиотизма с запретом body)
  UNKNOWN,  // may be extension or smth
};

std::string_view e2str(http_method_e e) noexcept;
// возвращает false если значение незнакомое
// выставляет UNKNOWN при незнакомом методе (т.к. кастомные методы это норма)
bool efromstr(std::string_view, http_method_e&) noexcept;

enum struct scheme_e : uint8_t {
  HTTP,
  HTTPS,
  UNKNOWN,
};

std::string_view e2str(scheme_e e) noexcept;
// возвращает false если значение незнакомое
// выставляет UNKNOWN при незнакомом значении (т.к. кастомные схемы это норма)
bool efromstr(std::string_view, scheme_e&) noexcept;

struct http_header_t {
  std::string hname;
  std::string hvalue;

  std::string_view name() const noexcept {
    return hname;
  }
  std::string_view value() const noexcept {
    return hvalue;
  }

  bool operator==(const http_header_t&) const = default;
};

using http_headers_t = std::vector<http_header_t>;

// client knows authority and scheme and sets it
struct http_request {
  // :authority for HTTP/2
  // empty authority will not be sent.
  // Note: its interpretation of this:
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1-2.3.2
  // (  unless there is no authority information to convey (in which case it MUST NOT generate ":authority").
  // ) this means (?) empty :authority must not be sent
  std::string authority = {};
  // must be setted to not empty string
  std::string path;
  http_method_e method = http_method_e::GET;
  // 'scheme' is for server, clients will ignore it and use their scheme instead
  scheme_e scheme = scheme_e::HTTP;
  http_body body = {};
  // additional headers, all must be lowercase for HTTP/2
  http_headers_t headers;
};

struct http_response {
  int status = 0;
  http_headers_t headers;
  http_body_bytes body;

  std::string_view body_strview() const noexcept {
    return {(const char*)body.data(), body.size()};
  }
};

using streaming_body_t = dd::channel<std::span<const byte_t>>;

struct request_context;

// `trailers` may be settted to sent trailers section
using stream_body_maker_t = heap_move_only_fn<streaming_body_t(http_headers_t& trailers, request_context)>;
// do not allow trailers in bistream
using bistream_body_maker_t = heap_move_only_fn<streaming_body_t(request_context)>;

// helper, mostly for implementation
// `args` will be just stored in returned object
inline stream_body_maker_t streaming_body_without_trailers(streaming_body_t streambody, auto... args) {
  return [x = std::move(streambody), ... pack = std::move(args)](
             http_headers_t& /*trailers*/, request_context&&) mutable -> streaming_body_t {
    return std::move(x);
  };
}

stream_body_maker_t streaming_body_with_trailers(streaming_body_t body, http_headers_t trailers);

}  // namespace hidi

namespace std {

template <>
struct formatter<::hidi::http_header_t> : formatter<std::string_view> {
  auto format(const ::hidi::http_header_t& hdr, auto& ctx) const -> decltype(ctx.out()) {
    return std::format_to(ctx.out(), "{}: {}", hdr.name(), hdr.value());
  }
};

}  // namespace std
