#pragma once

#include "hidi/utils/memory.hpp"

#include <utility>
#include <vector>

namespace hidi {

struct reusable_buffers_stack {
 private:
  std::vector<std::vector<byte_t>> bufs;
  size_t max_count;

 public:
  explicit reusable_buffers_stack(size_t max) : max_count(max) {
    bufs.reserve(max_count);
  }

  std::vector<byte_t> get_buffer() noexcept {
    if (bufs.empty())
      return {};
    std::vector<byte_t> b = std::move(bufs.back());
    bufs.pop_back();
    return b;
  }

  void return_buffer(std::vector<byte_t> b) noexcept {
    if (bufs.size() == max_count || b.capacity() >= 256 * 1024)
      return;
    b.clear();
    // исключение невозможно т.к. в конструкторе был reserve
    bufs.push_back(std::move(b));
  }
};

}  // namespace hidi
