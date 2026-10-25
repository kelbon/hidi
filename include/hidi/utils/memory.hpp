
#pragma once

#include <algorithm>
#include <bit>
#include <cassert>
#include <cstring>
#include <span>

namespace hidi {

using byte_t = unsigned char;

template <typename T>
std::span<byte_t, sizeof(T)> as_bytes(T& t) noexcept {
  static_assert(/*std::has_unique_object_representations_v<T> &&*/ !std::is_const_v<T> &&
                std::is_trivially_copyable_v<T>);
  return std::span<byte_t, sizeof(T)>(reinterpret_cast<byte_t*>(std::addressof(t)), sizeof(T));
}

template <typename T>
std::span<const byte_t, sizeof(T)> as_bytes(const T& t) noexcept {
  static_assert(/*std::has_unique_object_representations_v<T> &&*/ std::is_trivially_copyable_v<T>);
  return std::span<const byte_t, sizeof(T)>(reinterpret_cast<const byte_t*>(std::addressof(t)), sizeof(T));
}
// this is for trivial types, not for spans
template <typename T>
void as_bytes(std::span<T>) = delete;

template <typename T, size_t E>
std::span<byte_t> reinterpret_span_as_bytes(std::span<T, E> t) {
  static_assert(std::is_same_v<T, char> || std::is_same_v<T, unsigned char> || std::is_same_v<T, std::byte>);

  return std::span<byte_t, E>(reinterpret_cast<byte_t*>(t.data()), t.size());
}

template <typename T, size_t E>
std::span<const byte_t> reinterpret_span_as_bytes(std::span<const T, E> t) {
  static_assert(std::is_same_v<T, char> || std::is_same_v<T, unsigned char> || std::is_same_v<T, std::byte>);

  return std::span<const byte_t, E>(reinterpret_cast<const byte_t*>(t.data()), t.size());
}

template <typename T>
[[nodiscard]] constexpr T htonl_value(T value) noexcept {
  if constexpr (std::is_enum_v<T>) {
    return T(htonl_value(static_cast<std::underlying_type_t<T>>(value)));
  } else {
    using enum std::endian;
    static_assert(native == little || native == big);
    if constexpr (native == little) {
#if __cpp_lib_byteswap >= 202110L
      return std::byteswap(value);
#else
      char* p = (char*)std::addressof(value);
      std::reverse(p, p + sizeof(value));
      return value;
#endif
    } else {
      return value;
    }
  }
}

// i - in place
template <typename T>
constexpr void htonli(T& value) noexcept {
  value = htonl_value(value);
}

template <typename T>
constexpr void remove_prefix(std::span<T>& s, size_t n) noexcept {
  assert(s.size() >= n);
  T* b = s.data() + n;
  T* e = s.data() + s.size();
  s = std::span<T>(b, e);
}

template <typename T>
constexpr void remove_suffix(std::span<T>& s, size_t n) noexcept {
  assert(s.size() >= n);
  T* b = s.data();
  T* e = s.data() + (s.size() - n);
  s = std::span<T>(b, e);
}

template <typename T>
constexpr std::span<T> prefix(std::span<T> s, size_t n) noexcept {
  assert(s.size() >= n);
  T* b = s.data();
  T* e = s.data() + n;
  return std::span<T>(b, e);
}

template <typename T>
constexpr std::span<T> suffix(std::span<T> s, size_t n) noexcept {
  assert(s.size() >= n);
  T* b = s.data() + (s.size() - n);
  T* e = s.data() + s.size();
  return std::span<T>(b, e);
}

}  // namespace hidi
