// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include "hidi/h2errors.hpp"
#include "hidi/utils/macro.hpp"

#include <exception>

#include <format>

#include <boost/system/error_code.hpp>

namespace hidi {

using io_error_code = boost::system::error_code;

struct network_exception : std::exception {
  std::string data;

  template <typename... ARGS>
  explicit network_exception(std::format_string<ARGS...> fmt, ARGS&&... args)
      : data(std::format(fmt, std::forward<ARGS>(args)...)) {
  }
  explicit network_exception(const io_error_code& ec) : data(std::format("{}", ec.message())) {
  }
  explicit network_exception(std::string s) noexcept : data(std::move(s)) {
  }
  const char* what() const noexcept KELCORO_LIFETIMEBOUND override {
    return data.c_str();
  }
};

struct timeout_exception : std::exception {
  const char* what() const noexcept override {
    return "timeout";
  }
};

}  // namespace hidi
