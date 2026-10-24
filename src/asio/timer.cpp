#include "hidi/asio/timer.hpp"

#include "hidi/errors.hpp"

#include <boost/asio/steady_timer.hpp>

namespace hidi {

struct asio_timer::impl {
  boost::asio::steady_timer timer;
  std::optional<duration> period;
  timer_callback_t fn;
  bool armed = false;
  // увеличивается при каждом arm. Отменённое ожидание завершается позже (operation_aborted), и если таймер
  // уже перевзведён, это завершение относится к старому взводу и должно игнорироваться
  uint64_t generation = 0;

  explicit impl(boost::asio::io_context& ctx) : timer(ctx) {
  }
};

asio_timer::asio_timer(boost::asio::io_context& ctx) : m_impl(std::make_shared<asio_timer::impl>(ctx)) {
}

void asio_timer::arm(duration d) {
  arm(std::chrono::steady_clock::now() + d);
}

struct callback_t {
  std::weak_ptr<asio_timer::impl> w;
  uint64_t generation = 0;

  void operator()(const io_error_code& ec) {
    auto x = w.lock();
    if (!x || x->generation != generation)
      return;
    if (ec) {
      if (x->fn)
        x->fn(/*canceled=*/true);
      x->armed = false;
      return;
    }
    if (x->fn)
      x->fn(/*canceled=*/false);
    if (!x->period) {
      x->armed = false;
      return;
    }
    x->timer.expires_after(*x->period);
    x->timer.async_wait(callback_t(std::move(w), generation));
  }
};

void asio_timer::arm(time_point tp) {
  cancel();
  m_impl->timer.expires_at(tp);
  m_impl->armed = true;
  ++m_impl->generation;
  m_impl->timer.async_wait(callback_t(m_impl, m_impl->generation));
}

void asio_timer::arm_periodic(duration d) {
  arm(d);
  m_impl->period = d;
}

bool asio_timer::is_armed() const noexcept {
  return m_impl->armed;
}

bool asio_timer::cancel() noexcept {
  if (!is_armed())
    return false;
  m_impl->period = std::nullopt;
  m_impl->armed = false;
  m_impl->timer.cancel();
  return true;
}

void asio_timer::set_callback(timer_callback_t fn) {
  m_impl->fn = std::move(fn);
}

}  // namespace hidi
