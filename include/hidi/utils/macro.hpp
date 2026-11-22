// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include <kelcoro/noexport/macro.hpp>
#include <zal/zal.hpp>

#ifdef __clang__
  #define KELHTTP2_TRIVIAL_ABI [[clang::trivial_abi]]
#else
  #define KELHTTP2_TRIVIAL_ABI
#endif

namespace hidi {

[[noreturn]] inline void unreachable() noexcept {
  assert(false);
  KELCORO_UNREACHABLE;
}

}  // namespace hidi
