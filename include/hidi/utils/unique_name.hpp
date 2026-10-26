#pragma once

#include <format>
#include <string_view>

#include "hidi/utils/fn_ref.hpp"

namespace hidi {

// unique name for logging (server / server session/ client / client connection)
// allows grep by name and find all logs associated with entity
struct unique_name {
 private:
  static constexpr size_t LEN = 16;

  char m_str[LEN] = {};

 public:
  unique_name();
  // creates empty name
  explicit unique_name(std::nullptr_t) noexcept {
  }

  // prefix denotes the belonging of the entity, e.g. client or connection
  void set_prefix(char prefix) noexcept;

  std::string_view str() const noexcept {
    return std::string_view(+m_str, LEN);
  }
};

constexpr inline char CLIENT_PREFIX = 'C';
constexpr inline char SERVER_PREFIX = 'S';
constexpr inline char CLIENT_CONNECTION_PREFIX = 'c';
constexpr inline char SERVER_SESSION_PREFIX = 's';

enum struct log_level_e : int {
  ALL = 0,
  TRACE,  // logged only if HTTP2_ENABLE_TRACE defined
  INFO,
  WARN,
  ERROR,
  NOTHING = std::numeric_limits<int>::max(),
};

inline void noop_log_function(log_level_e, std::string_view fmt_str, std::format_args) {
}
void default_log_function(log_level_e, std::string_view fmt_str, std::format_args);

// log_level_e checked before invoking, but passed for more information / advanced log filtering
// precondition: fmt str and args compile-time checked
using log_fn_t = copyable_fn<void(log_level_e, std::string_view fmt_str, std::format_args) const>;

struct log_context {
  log_level_e lvl = log_level_e::INFO;
  log_fn_t dolog = &default_log_function;
  unique_name name = {};

  [[nodiscard]] bool should_log(log_level_e l) const noexcept {
    return l >= lvl;
  }
};

static const log_context empty_log_context{
    .lvl = log_level_e::NOTHING, .dolog = &noop_log_function, .name = unique_name(nullptr)};

}  // namespace hidi

namespace std {

template <>
struct formatter<::hidi::unique_name> : formatter<string_view> {
  auto format(const ::hidi::unique_name& n, auto& ctx) const -> decltype(ctx.out()) {
    return formatter<string_view>::format(n.str(), ctx);
  }
};

}  // namespace std
