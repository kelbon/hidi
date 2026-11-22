// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include "hidi/utils/memory.hpp"

#include <vector>

namespace hidi {

namespace detail {

struct noinit {
  unsigned char c;

  // user-declared конструктор, так как это единственный способ запретить
  // zero-initialization в случае такого кода: "noinit v{}" always_inline, чтобы
  // максимально приблизить этот тип к простому unsigned char
  [[gnu::always_inline]] noinit() noexcept {
  }
};

// этот аллокатор гарантирует FRAME_HEADER_LEN (9) байт до каждой аллокации. Это
// используется при отправке HTTP/2 запроса для оптимизации: уже отправленные
// байты запроса используются как буфер при отправке следующих template для
// поддержки rebind (static assert в std::vector)
template <typename T>
struct allocator_p9 {
  // msvc stdlib abi breaking uselss container uses _Alloc_Proxy smth
#if _ITERATOR_DEBUG_LEVEL == 0
  static_assert(std::is_same_v<T, byte_t> || std::is_same_v<noinit, T>);

#endif
  allocator_p9() = default;
  // required only on msvclib with _Container_proxy useless shit
  template <typename U>
  allocator_p9(allocator_p9<U>) noexcept : allocator_p9() {
  }

  using value_type = T;
  using size_type = size_t;
  using difference_type = ptrdiff_t;
  using propagate_on_container_move_assignment = std::true_type;
  using is_always_equal = std::true_type;

  static value_type* allocate(std::size_t n) {
    // FRAME_HEADER_LEN == 9, not include http2_protocol.hpp here
    value_type* r = new value_type[n + 9];
    return r + 9;
  }
  static void deallocate(value_type* p, std::size_t) noexcept {
    delete[] (p - 9);
  }

  bool operator==(const allocator_p9&) const {
    return true;
  }
};

}  // namespace detail

// тег тип и значение по аналогии с стандартными std::in_place_t /
// std::nullopt_T
struct uninitialized_byte_t {
  explicit uninitialized_byte_t() = default;
};
constexpr inline uninitialized_byte_t uninitialized_byte = uninitialized_byte_t{};

struct http_body_bytes : private std::vector<byte_t, detail::allocator_p9<byte_t>> {
  // приватное наследование используется чтобы с одной стороны не повторять
  // реализацию std::vector с другой стороны не получать автоматически в этот
  // тип методы, добавляемые в std::vector в новых стандартах

 private:
  using base_t = std::vector<byte_t, detail::allocator_p9<byte_t>>;

 public:
  using base_t::allocator_type;
  using base_t::const_iterator;
  using base_t::const_pointer;
  using base_t::const_reference;
  using base_t::difference_type;
  using base_t::iterator;
  using base_t::pointer;
  using base_t::reference;
  using base_t::size_type;
  using base_t::value_type;

  using base_t::base_t;
  // require explicitly choose between uninitialized and initialized resize
  http_body_bytes(size_type sz) = delete;
  // creates container with size 'sz' and uninitialized memory
  http_body_bytes(size_type sz, uninitialized_byte_t) {
    resize(sz, uninitialized_byte);
  }
  using base_t::operator=;
  using base_t::assign;
  using base_t::data;
  using base_t::empty;
  using base_t::insert;
  using base_t::push_back;
  using base_t::resize;
  using base_t::size;
  using base_t::operator[];
  using base_t::capacity;
  using base_t::clear;
  using base_t::erase;
  using base_t::pop_back;
  using base_t::rbegin;
  using base_t::rend;
  using base_t::reserve;
  using base_t::swap;

  // не инициализирует память
  void resize(size_type sz, uninitialized_byte_t) {
    resize_noinit(static_cast<base_t*>(this), sz);
  }
  using base_t::begin;
  using base_t::end;

  bool operator==(const http_body_bytes&) const = default;

 private:
  // noinline to guarantee compiler cannot optimize strict aliasing
  [[gnu::noinline]] void resize_noinit(void* p, size_t sz) {
    // здесь компилятор не знает ничего о 'p' и не может ничего сломать
    // делаем resize, будто под 'p' vector<noinit>.
    // За счёт того как устроен noinit компилятор уберёт инициализацию памяти
    // (memset)
    using dirty_hack_t = std::vector<detail::noinit, detail::allocator_p9<detail::noinit>>;
    ((dirty_hack_t*)p)->resize(sz);
  }
};

}  // namespace hidi
