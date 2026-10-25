
#pragma once

#include "hidi/utils/memory.hpp"

#include <memory_resource>

namespace hidi {

struct reusable_buffer {
 private:
  byte_t* m_bytes = nullptr;
  size_t m_sz = 0;
  std::pmr::memory_resource* m_resource = nullptr;

 public:
  explicit reusable_buffer(std::pmr::memory_resource* mr = std::pmr::new_delete_resource()) : m_resource(mr) {
    assert(m_resource);
  }

  // владеет сырой памятью: копия освободила бы её дважды
  reusable_buffer(reusable_buffer&&) = delete;
  void operator=(reusable_buffer&&) = delete;

  ~reusable_buffer() {
    clear();
  }

  void reserve(size_t count) {
    (void)get_exactly(count);
  }

  void clear() noexcept {
    if (m_bytes) {
      m_resource->deallocate(m_bytes, m_sz);
      m_bytes = nullptr;
      m_sz = 0;
    }
  }

  std::span<byte_t> get_max_buffer() noexcept {
    if (!m_bytes)
      return {};
    return std::span(m_bytes, m_sz);
  }
  // value will be invalidated on next call
  // may return uninitialized memory
  std::span<byte_t> get_exactly(size_t count) {
    if (m_sz >= count)
      return std::span<byte_t>(m_bytes, count);
    if (m_bytes)
      clear();
    m_bytes = static_cast<byte_t*>(m_resource->allocate(count));
    m_sz = count;
    return std::span<byte_t>(m_bytes, count);
  }

  std::span<byte_t> get_atleast(size_t count) {
    if (m_sz >= count)
      return std::span<byte_t>(m_bytes, m_sz);
    return get_exactly(count);
  }
};

}  // namespace hidi
