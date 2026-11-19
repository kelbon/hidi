#pragma once

#include <vector>
#include <span>
#include <cassert>

#include "hidi/utils/memory.hpp"

namespace hidi {

struct readahead_buffer {
 private:
  std::vector<byte_t> readen;
  byte_t* readen_start;
  byte_t* readen_end;
  // TODO grow
 public:
  // pre: bufsz > 0
  explicit readahead_buffer(size_t bufsz = (1 << 14) + 9)
      : readen(bufsz), readen_start(readen.data()), readen_end(readen.data()) {
    assert(bufsz > 0);
  }

  // уже прочитанное
  [[nodiscard]] std::span<const byte_t> available() const noexcept {
    return std::span(readen_start, readen_end);
  }

  // передаёт доступные байты в буфер и возвращает сколько байт прочитано
  size_t read_some_r(std::span<byte_t> buf) noexcept {
    if (buf.empty()) [[unlikely]]
      return 0;
    size_t sz = std::min(buf.size(), available_count());
    memcpy(buf.data(), readen_start, sz);
    readen_start += sz;
    return sz;
  }
  // передаёт доступные байты в буфер и возвращает незаполненную часть буфера
  std::span<byte_t> read_some(std::span<byte_t> buf) noexcept {
    return buf.subspan(read_some_r(buf));
  }

  [[nodiscard]] size_t available_count() const noexcept {
    return readen_end - readen_start;
  }

  // свободное место, записанные данные станут available после commit_readen
  [[nodiscard]] std::span<byte_t> input() noexcept {
    // несъеденное переносится в начало, место за ним - для нового
    size_t sz = available_count();
    if (readen.data() != readen_start) {
      std::memmove(readen.data(), readen_start, sz);
      readen_start = readen.data();
      readen_end = readen_start + sz;
    }
    return std::span(readen).subspan(sz);
  }

  // означает конец чтения в input()
  void commit_readen(size_t n) {
    assert(((readen.data() + readen.size()) - readen_end) >= n);
    readen_end += n;
    // TODO? если забил лимит, то увеличивать буфер?
  }
};

}  // namespace hidi
