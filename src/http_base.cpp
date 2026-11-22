// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#include "hidi/http_base.hpp"

#include "hidi/request_context.hpp"
#include "hidi/utils/macro.hpp"

#include <strswitch/strswitch.hpp>

namespace hidi {

std::string_view e2str(reqerr_e::values_e e) noexcept {
  using enum reqerr_e::values_e;
  assert((int)e <= 0);
  switch ((int)e) {
    case DONE:
      return "done";
    case CANCELLED:
      return "cancelled";
    case TIMEOUT:
      return "timeout";
    case NETWORK_ERR:
      return "network_err";
    case PROTOCOL_ERR:
      return "protocol_err";
    case SERVER_CANCELLED_REQUEST:
      return "server_cancelled_request";
    case UNKNOWN_ERR:
      return "unknown_err";
    case reqerr_e::REQUEST_CREATED:
      return "REQUEST_CREATED";
    case reqerr_e::RESPONSE_IN_PROGRESS:
      return "RESPONSE_IN_PROGRESS";
  }
  return "UNKNOWN_BAD_STATUS";
}

std::string_view e2str(http_method_e e) noexcept {
  using enum http_method_e;
  switch (e) {
    case GET:
      return "GET";
    case POST:
      return "POST";
    case PUT:
      return "PUT";
    case DELETE:
      return "DELETE";
    case PATCH:
      return "PATCH";
    case OPTIONS:
      return "OPTIONS";
    case HEAD:
      return "HEAD";
    case CONNECT:
      return "CONNECT";
    case TRACE:
      return "TRACE";
    case QUERY:
      return "QUERY";
    case UNKNOWN:
      return "UNKNOWN";
    default:
      unreachable();  // error
  }
}

bool efromstr(std::string_view str, http_method_e& m) noexcept {
  // https://datatracker.ietf.org/doc/html/rfc9110#name-methods
  // "The method token is case-sensitive", все токены в реестре большими буквами
  using enum http_method_e;
  m = ss::string_switch<http_method_e>(str)
          .case_("GET", GET)
          .case_("POST", POST)
          .case_("PUT", PUT)
          .case_("DELETE", DELETE)
          .case_("PATCH", PATCH)
          .case_("HEAD", HEAD)
          .case_("CONNECT", CONNECT)
          .case_("OPTIONS", OPTIONS)
          .case_("TRACE", TRACE)
          .case_("QUERY", QUERY)
          .or_default(UNKNOWN);
  return m != UNKNOWN;
}

std::string_view e2str(scheme_e e) noexcept {
  // маленькие буквы, так как в статической таблице HPACK схемы написаны маленькими http/https
  switch (e) {
    case scheme_e::HTTP:
      return "http";
    case scheme_e::HTTPS:
      return "https";
    case scheme_e::UNKNOWN:
      return "UNKNOWN";
    default:
      unreachable();  // error
  }
}

bool efromstr(std::string_view str, scheme_e& s) noexcept {
  using enum scheme_e;
  s = ss::string_switch<scheme_e>(str).case_("http", HTTP).case_("https", HTTPS).or_default(UNKNOWN);
  return s != UNKNOWN;
}

stream_body_maker_t streaming_body_with_trailers(streaming_body_t body, http_headers_t trailers) {
  return [b = std::move(body), t = std::move(trailers)](http_headers_t& hdrs,
                                                        request_context) mutable -> streaming_body_t {
    co_yield dd::elements_of(std::move(b));
    hdrs = std::move(t);
  };
}

}  // namespace hidi
