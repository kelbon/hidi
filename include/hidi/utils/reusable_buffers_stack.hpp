// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include "hidi/utils/memory.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace hidi {

struct reusable_buffers_stack {
 private:
  std::vector<std::vector<byte_t>> bufs;
  // минимум bufs.size() за текущее окно: столько буферов за окно не понадобилось
  size_t low_water = 0;
  // сколько буферов выдано в текущем окне
  size_t taken = 0;

  // окно - столько выдач буферов
  static constexpr size_t WINDOW = 1 << 16;

  void trim() noexcept {
    bufs.erase(bufs.begin(), bufs.begin() + low_water);
    low_water = bufs.size();
    taken = 0;
  }

 public:
  std::vector<byte_t> get_buffer() noexcept {
    if (++taken == WINDOW)
      trim();
    if (bufs.empty())
      return {};
    std::vector<byte_t> b = std::move(bufs.back());
    bufs.pop_back();
    low_water = std::min(low_water, bufs.size());
    return b;
  }

  void return_buffer(std::vector<byte_t> b) noexcept {
    if (b.capacity() >= 256 * 1024)
      return;
    b.clear();
    try {
      bufs.push_back(std::move(b));
    } catch (...) {
      // не хватило памяти - буфер просто освобождается
    }
  }
};

}  // namespace hidi
