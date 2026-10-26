#pragma once

#include <random>
#include <limits>
#include <string>
#include <string_view>
#include <ranges>
#include <cassert>
#include <algorithm>

#include <kelcoro/generator.hpp>
#include "hidi/errors.hpp"
#include "hidi/utils/deadline.hpp"
#include "hidi/utils/memory.hpp"

namespace hidi::fuzzing {

#define FUZ_ENGLISH_ALP_LC "abcdefghijklmnopqrstuvwxyz"
#define FUZ_ENGLISH_ALP_UC "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define FUZ_ENGLISH_ALPHABET FUZ_ENGLISH_ALP_LC FUZ_ENGLISH_ALP_UC
#define FUZ_DIGITS "0123456789"
#define FUZ_SPECIAL_SYMS "_!@#$%^&*()"
#define FUZ_BASE64_SYMS FUZ_ENGLISH_ALPHABET "+/="

// helper fn for random string generation
std::string exclude_symbols(std::string_view included, std::string_view excluded);

// helper fn for random string generation
// returns only unique characters
std::string unique_symbols(std::string_view syms);

using random_generator_type = std::mt19937;

struct fuzzer {
  random_generator_type g;

  fuzzer() : g(std::random_device{}()) {
  }

  explicit fuzzer(size_t seed) : g(seed) {
  }

  inline bool rbool(double probability = 0.5) {
    return std::bernoulli_distribution(probability)(g);
  }

  // precondition: min <= max
  // returns int in range [min, max]
  template <std::integral T = int>
  T rint(T min = 0, T max = std::numeric_limits<T>::max()) {
    assert(min <= max);
    return std::uniform_int_distribution<T>(min, max)(g);
  }

  // precondition: `max` != 0
  // returns random size_t in range [0, max - 1]
  size_t rindex(size_t sz) {
    assert(sz != 0);
    return rint<size_t>(0, sz - 1);
  }

  void shuffle(std::ranges::random_access_range auto& r) {
    std::ranges::shuffle(r, g);
  }

  // selects random symbols form range
  template <std::ranges::random_access_range T>
  std::ranges::range_reference_t<T> select(T&& r) {
    assert(!std::ranges::empty(r));
    return *(std::ranges::begin(r) + rindex(std::ranges::size(r)));
  }

  // returns `out`
  // O(N) where N is count elements in range
  // precondition: count <= range.size()
  auto sample(std::ranges::random_access_range auto&& range, size_t count,
              std::input_or_output_iterator auto out) {
    assert(count <= std::ranges::size(range));
    std::ranges::sample(range, out, count, g);
    return out;
  }

  // precondition: `possiblechars` not empty
  // Note: repeating symbol in possible chars may be used as `weight` (more repeats => more probability
  // to be selected)
  std::string rstring(size_t len = 32, std::string_view possiblechars = FUZ_ENGLISH_ALPHABET FUZ_DIGITS) {
    std::string r(len, '\0');
    auto randsym = [&]() { return select(possiblechars); };
    std::generate_n(r.data(), len, randsym);
    return r;
  }

  std::string rstring(size_t len, std::string_view possiblechars, std::string_view excluded) {
    return rstring(len, exclude_symbols(possiblechars, excluded));
  }

  // replaces all X symbols in `mask` with random chars
  // example: rstring("ABC-XXX". FUZ_DIGITS) -> "ABC-321"
  // postcondition: returned string does not contain `X`
  // precondition: `possiblechars` has something other than `X`
  std::string rstring(std::string_view mask,
                      std::string_view possiblechars = FUZ_ENGLISH_ALPHABET FUZ_DIGITS) {
    assert(possiblechars.find_first_not_of('X') != std::string_view::npos);
    std::string r(mask);
    for (char& c : r) {
      while (c == 'X')
        c = select(possiblechars);
    }
    return r;
  }

  std::string rstring(std::string_view mask, std::string_view possiblechars, std::string_view excluded) {
    return rstring(mask, exclude_symbols(possiblechars, excluded));
  }

  // делит строку на случайного размера чанки
  dd::generator<std::string_view> chunks(std::string str) {
    std::string_view s = str;
    while (!s.empty()) {
      auto i = rindex(s.size());
      co_yield s.substr(0, i);
      s.remove_prefix(i);
    }
  }

  template <std::ranges::contiguous_range T>
  dd::generator<std::span<const std::ranges::range_value_t<T>>> chunks(T data) {
    std::span d = data;
    while (!d.empty()) {
      auto i = rindex(d.size() + 1);
      co_yield d.subspan(0, i);
      d = d.subspan(i);
    }
  }

  // sleepcb (duration, io_error_code) -> awaitable for sleep
  template <std::ranges::contiguous_range T>
  dd::channel<std::span<const std::ranges::range_value_t<T>>> chunks_delayed(T data, size_t mindelayms,
                                                                             size_t maxdelayms,
                                                                             auto sleepcb) {
    static_assert(!std::ranges::borrowed_range<T>);
    assert(mindelayms <= maxdelayms);
    std::span d = data;
    io_error_code ec;
    while (!d.empty()) {
      if (rbool()) {
        auto i = rindex(d.size());
        co_yield d.subspan(0, i);
        d = d.subspan(i);
      } else {
        co_await sleepcb(std::chrono::milliseconds(rint(mindelayms, maxdelayms)), ec);
        if (ec)
          co_return;
      }
    }
  }

  // runs `ioctxs` with random ordeing
  void run_until(deadline_t d, auto condition, auto&&... ioctxs) {
    // should be asio::io_context (not included here)
    std::vector ctxs{std::addressof(ioctxs)...};
    while (!condition() && !d.is_reached())
      select(ctxs)->poll_one();
    if (d.is_reached())
      throw timeout_exception();
    // доделать готовые задачи. Контексты опрашиваются по очереди: задача одного может ждать задачу другого,
    // например сервер ждёт RST_STREAM, который клиент отправит только в конце своего такта
    for (bool any = true; any;) {
      any = false;
      ((any |= ioctxs.poll_one()), ...);
    }
  }

  void run_until(auto condition, auto&&... ioctxs) {
    return run_until(deadline_t::never(), std::move(condition), ioctxs...);
  }

  void run_until(bool& done, auto&&... ioctxs) {
    return run_until(deadline_t::never(), [&] { return done; }, ioctxs...);
  }

  void run_until(deadline_t d, bool& done, auto&&... ioctxs) {
    return run_until(d, [&] { return done; }, ioctxs...);
  }

  void rbytes_fill(std::forward_iterator auto b, auto e) {
    for (; b != e; ++b)
      *b = byte_t(rint(0, 255));
  }

  std::vector<byte_t> rbytes(size_t count) {
    std::vector<byte_t> res(count);
    rbytes_fill(res.begin(), res.end());
    return res;
  }
};

}  // namespace hidi::fuzzing
