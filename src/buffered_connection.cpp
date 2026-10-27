#include "hidi/buffered_connection.hpp"

#include <boost/asio/error.hpp>

#include <kelcoro/job.hpp>

namespace hidi {

namespace {

// писатель засыпает, пока его не запланируют (см. `schedule_writer`)
struct writer_idle_awaiter {
  buffered_connection* c = nullptr;

  static bool await_ready() noexcept {
    return false;
  }
  void await_suspend(std::coroutine_handle<> h) noexcept {
    assert(!c->writer);
    c->writer = h;
    // shutdown ждёт, пока всё будет дописано. Будится через очередь, а не здесь, потому что shutdown
    // уничтожает писателя, а писатель ещё выполняется
    if (c->drain_waiter) {
      c->drain_task.task = std::exchange(c->drain_waiter, nullptr);
      c->io.attach(&c->drain_task);
    }
  }
  static void await_resume() noexcept {
  }
};

struct drain_awaiter {
  buffered_connection* c = nullptr;

  bool await_ready() const noexcept {
    return c->idle();
  }
  void await_suspend(std::coroutine_handle<> h) noexcept {
    assert(!c->drain_waiter);
    c->drain_waiter = h;
  }
  static void await_resume() noexcept {
  }
};

using nodes_t = bi::slist<writer_node, bi::cache_last<true>>;

// переносит данные ждущих места в outbuf, пока он не заполнится. Возвращает перенесённых, их надо разбудить
nodes_t move_waiters_to_outbuf(buffered_connection& c) {
  nodes_t moved;
  while (!c.waiters.empty() && c.outbuf.size() < buffered_connection::OUTBUF_LIMIT) {
    writer_node& n = c.waiters.front();
    c.waiters.pop_front();
    c.outbuf.insert(c.outbuf.end(), n.data.begin(), n.data.end());
    n.ec.clear();
    moved.push_back(n);
  }
  return moved;
}

void resume_all(nodes_t& nodes) {
  // узел живёт в кадре корутины, которая продолжится, поэтому убирается из списка до resume
  while (!nodes.empty()) {
    writer_node& n = nodes.front();
    nodes.pop_front();
    n.callback.resume();
  }
}

void fail_waiters(buffered_connection& c) {
  assert(c.write_ec);
  while (!c.waiters.empty()) {
    writer_node& n = c.waiters.front();
    c.waiters.pop_front();
    n.ec = c.write_ec;
    n.callback.resume();
  }
}

// Гарантирует:
// * писатель либо ждёт работы (c->writer != nullptr), либо запланирован, либо пишет. Сам не завершается
// * порядок байт во внутреннем соединении совпадает с порядком try_write / start_write
dd::job buffered_writer_job(buffered_connection* c) {
  // terminates on bad alloc
  assert(c);
  for (;;) {
    co_await writer_idle_awaiter(c);
    // запланированный писатель мог проснуться после ошибки, тогда отправлять уже нечего
    while (c->has_work() && !c->write_ec) {
      nodes_t moved = move_waiters_to_outbuf(*c);
      std::swap(c->sendbuf, c->outbuf);
      // перенесённые уже в sendbuf, пока он пишется, они могут писать дальше в outbuf
      resume_all(moved);
      io_error_code ec;
      co_await write_awaiter(c->inner, ec, c->sendbuf);
      c->sendbuf.clear();
      if (ec && !c->write_ec)
        c->write_ec = ec;
    }
    if (c->write_ec) {
      // накопленное уже не отправить
      c->outbuf.clear();
      fail_waiters(*c);
    }
  }
}

}  // namespace

buffered_connection::buffered_connection(any_connection_t in, any_io_context_ref ctx)
    : inner(std::move(in)), io(ctx) {
  assert(inner);
  (void)buffered_writer_job(this);
}

buffered_connection::~buffered_connection() {
  assert(writer || !allow_write);
  if (writer)
    writer.destroy();
}

void buffered_connection::schedule_writer() {
  if (!writer)
    return;
  writer_task.task = std::exchange(writer, nullptr);
  io.attach(&writer_task);
}

size_t buffered_connection::try_write(std::span<const byte_t> buf, io_error_code& ec) noexcept {
  if (!allow_write) [[unlikely]] {
    ec = boost::asio::error::operation_aborted;
    return 0;
  }
  if (write_ec) [[unlikely]] {
    ec = write_ec;
    return 0;
  }
  // пока кто-то ждёт места, новые данные встают за ним, чтобы не нарушить порядок
  if (!waiters.empty() || outbuf.size() >= OUTBUF_LIMIT)
    return 0;
  outbuf.insert(outbuf.end(), buf.begin(), buf.end());
  schedule_writer();
  return buf.size();
}

void buffered_connection::start_write(writer_node* n) {
  assert(n);
  assert(allow_write);
  waiters.push_back(*n);
  schedule_writer();
}

dd::task<void> buffered_connection::shutdown() noexcept {
  if (!allow_write)
    co_return;
  // запрещает новые try_write / start_write
  allow_write = false;
  if (!idle()) {
    // принятое уже считается записанным (например последние ответы и GOAWAY), поэтому его надо дописать.
    // Но если пир не читает, запись не завершится никогда, тогда ожидание прекращается по таймауту, а
    // зависшую запись прерывает shutdown внутреннего соединения
    any_timer timer = io.create_timer();
    timer.set_callback([this](bool canceled) {
      if (canceled)
        return;
      // писатель может быть запланирован, а не в записи, тогда внутренний shutdown его не остановит
      if (!write_ec)
        write_ec = boost::asio::error::operation_aborted;
      if (drain_waiter) {
        drain_task.task = std::exchange(drain_waiter, nullptr);
        io.attach(&drain_task);
      }
    });
    timer.arm(deadline_after(DRAIN_TIMEOUT));
    co_await drain_awaiter(this);
    (void)timer.cancel();
  }
  co_await inner->shutdown();
  // после таймаута писатель ещё мог дописывать или быть запланирован: с write_ec он сразу встанет на ожидание
  co_await drain_awaiter(this);
  std::exchange(writer, nullptr).destroy();
}

}  // namespace hidi
