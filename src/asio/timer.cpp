#include "hidi/asio/timer.hpp"

#include "hidi/errors.hpp"

#include <boost/asio/steady_timer.hpp>

namespace hidi {

struct asio_timer::impl {
  boost::asio::steady_timer timer;
  std::optional<duration> period;
  timer_callback_t fn;
  bool armed = false;
  // выставляется set_callback, см. `invoke`
  bool fn_replaced = false;
  // увеличивается при каждом arm. Отменённое ожидание завершается позже (operation_aborted), и если таймер
  // уже перевзведён, это завершение относится к старому взводу и должно игнорироваться
  uint64_t generation = 0;

  explicit impl(boost::asio::io_context& ctx) : timer(ctx) {
  }

  // колбек может заменить или убрать себя через set_callback во время вызова, поэтому вызывается из локальной
  // переменной и доживает до конца вызова. На место он возвращается, только если его не заменили
  void invoke(bool canceled) {
    if (!fn)
      return;
    timer_callback_t f = std::move(fn);
    fn_replaced = false;
    f(canceled);
    if (!fn_replaced)
      fn = std::move(f);
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
      x->armed = false;
      x->invoke(/*canceled=*/true);
      return;
    }
    if (x->period) {
      // перевзвод внутри колбека отменит это ожидание, а cancel завершит его с canceled == true
      x->timer.expires_after(*x->period);
      x->timer.async_wait(callback_t(w, generation));
    } else {
      x->armed = false;
    }
    x->invoke(/*canceled=*/false);
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
  m_impl->fn_replaced = true;
}

}  // namespace hidi
