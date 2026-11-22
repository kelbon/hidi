// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include <chrono>
#include <compare>

namespace hidi {

using duration_t = std::chrono::steady_clock::duration;

struct deadline_t {
  using time_point_t = std::chrono::steady_clock::time_point;

  time_point_t tp;

  deadline_t() = default;
  constexpr deadline_t(time_point_t p) noexcept : tp(p) {
  }
  template <typename REP, typename PERIOD>
  constexpr deadline_t(std::chrono::duration<REP, PERIOD> d) noexcept;

  [[nodiscard]] constexpr bool is_reached(
      time_point_t point = std::chrono::steady_clock::now()) const noexcept {
    return tp <= point;
  }

  duration_t remaining_time() const noexcept {
    return tp - std::chrono::steady_clock::now();
  }

  static constexpr deadline_t never() noexcept {
    return deadline_t{time_point_t::max()};
  }
  static constexpr deadline_t yesterday() noexcept {
    return deadline_t{time_point_t::min()};
  }
  std::strong_ordering operator<=>(const deadline_t&) const = default;
};

inline deadline_t deadline_after(duration_t duration) noexcept {
  if (duration.count() <= 0) [[unlikely]]
    return deadline_t::yesterday();
  // avoid overflow
  auto tp = std::chrono::steady_clock::now();
  if (tp.max() - tp <= duration) [[unlikely]]
    return deadline_t::never();
  return deadline_t{tp + duration};
}

template <typename REP, typename PERIOD>
constexpr deadline_t::deadline_t(std::chrono::duration<REP, PERIOD> d) noexcept
    : deadline_t(deadline_after(d)) {
}

}  // namespace hidi
