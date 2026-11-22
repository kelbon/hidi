// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include <format>

// validates FMT_STR to not be empty token, forbids LOG(, arg)
#define HIDI_TOKEN_IS_EMPTY_ invalid_empty_token
#define HIDI_TOKEN_IS_EMPTY_NO
#define HIDI_CHECK_NOT_EMPTY_IMPL(TOKEN) HIDI_TOKEN_IS_EMPTY_##TOKEN
#define HIDI_CHECK_NOT_EMPTY(...) HIDI_CHECK_NOT_EMPTY_IMPL(__VA_OPT__(NO))

namespace hidi {
// avoids compiler error with rvalue args in std::make_format_args (`args` will never outlive expression)
// format string here only for compile time checking
template <typename... Args>
constexpr auto make_temp_fmt_args(std::format_string<Args...>, Args&&... args) {
  return std::make_format_args(args...);
}

}  // namespace hidi

#define HTTP2_DO_LOG(LOGCTX, LEVEL, FMT_STR, ...)                                    \
  do {                                                                               \
    if (LOGCTX.should_log(::hidi::log_level_e::LEVEL))                               \
      LOGCTX.dolog(::hidi::log_level_e::LEVEL, "[" #LEVEL "][HTTP/2] " FMT_STR "\n", \
                   ::hidi::make_temp_fmt_args(FMT_STR, __VA_ARGS__));                \
  } while (false)

#define HTTP2_LOG(LOGCTX, TYPE, FMT_STR, ...) \
  HIDI_CHECK_NOT_EMPTY(LOGCTX)                \
  HIDI_CHECK_NOT_EMPTY(FMT_STR)               \
  HTTP2_DO_LOG(LOGCTX, TYPE, FMT_STR " {}" __VA_OPT__(, ) __VA_ARGS__, LOGCTX.name)

#ifdef HTTP2_ENABLE_TRACE
  #define HTTP2_LOG_TRACE(LOGCTX, FMT_STR, ...) HTTP2_LOG(LOGCTX, TRACE, FMT_STR, __VA_ARGS__)
#else
  #define HTTP2_LOG_TRACE(LOGCTX, FMT_STR, ...) (void)0
#endif
