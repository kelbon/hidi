#pragma once

#include <algorithm>
#include <cassert>
#include <cstring>
#include <span>
#include <vector>

#include "hidi/utils/memory.hpp"

namespace hidi {

struct readahead_buffer {
 private:
  std::vector<byte_t> readen;
  byte_t* readen_start;
  byte_t* readen_end;
  size_t sz_limit;

  void grow() noexcept {
    assert(readen.size() <= sz_limit);
    size_t b = readen_start - readen.data();
    size_t e = readen_end - readen.data();
    try {
      readen.resize(std::min(readen.size() * 2, sz_limit));
    } catch (...) {
      // не прокатило
      return;
    }
    readen_start = readen.data() + b;
    readen_end = readen.data() + e;
  }

 public:
  // pre: bufsz > 0
  explicit readahead_buffer(size_t bufsz = (1 << 14) + 9) : readahead_buffer(bufsz, bufsz * 8) {
  }
  // pre: bufsz > 0, limit > bufsz
  explicit readahead_buffer(size_t bufsz, size_t limit)
      : readen(bufsz), readen_start(readen.data()), readen_end(readen.data()), sz_limit(limit) {
    assert(bufsz > 0 && limit > bufsz);
  }

  readahead_buffer(readahead_buffer&&) = delete;
  void operator=(readahead_buffer&&) = delete;

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
  // отдаёт `n` доступных байт без копирования, действительны до следующего input()
  [[nodiscard]] std::span<byte_t> take(size_t n) noexcept {
    assert(n <= available_count());
    std::span<byte_t> r(readen_start, n);
    readen_start += n;
    return r;
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
    if (available_count() == readen.size())
      grow();  // только растём
  }
};

}  // namespace hidi
