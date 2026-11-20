#pragma once

#include "hidi/any_connection.hpp"
#include "hidi/utils/any_io_context.hpp"

#include <boost/intrusive/slist.hpp>
#include <boost/asio/error.hpp>

#include <chrono>
#include <vector>

#include <kelcoro/job.hpp>

namespace hidi {

// * буферизирует write для Inner, даёт ей гарантию не более одного читателя/писателя одновременно
// * try_write копирует данные в `outbuf` и сразу сообщает, что всё записано
// отправляется одной записью в конце такта, при ошибке фейлит следующие операции
// * shutdown сначала дописывает принятое (не дольше DRAIN_TIMEOUT), затем закрывает внутреннее соединение
template <typename Inner>
struct buffered_connection {
  // сколько shutdown ждёт отправки принятого, если пир не читает
  static constexpr std::chrono::seconds DRAIN_TIMEOUT{1};

  using inner_connection_type = Inner;

  Inner inner;
  // если в outbuf столько байт или больше, try_write ничего не принимает и запись ждёт в `waiters`
  size_t outbuf_limit;
  // планирует отправку в конце такта и создаёт таймер для shutdown. Меняется при rebind
  any_io_context_ref io;

  // копится до конца такта
  std::vector<byte_t> outbuf;
  // пишется сейчас, хранится для переиспользования памяти
  std::vector<byte_t> sendbuf;
  // ждут места в outbuf (противодавление), данные переносятся в outbuf в порядке очереди
  bi::slist<writer_node, bi::cache_last<true>> waiters;
  // первая ошибка записи, после неё запись невозможна
  io_error_code write_ec;
  // писатель ждёт работы. nullptr, если он работает или уже запланирован
  std::coroutine_handle<> writer;
  // shutdown ждёт, пока писатель допишет принятое
  std::coroutine_handle<> drain_waiter;
  // узлы для io.attach: в очереди одновременно не больше одного запланированного писателя и одного shutdown
  dd::task_node writer_task;
  dd::task_node drain_task;
  bool allow_write = true;
  ZAL_PIN;

  template <typename... Args>
  buffered_connection(any_io_context_ref ctx, size_t outbuf_limit, Args&&... args)
      : inner(std::forward<Args>(args)...), outbuf_limit(outbuf_limit), io(ctx) {
    assert(outbuf_limit > 0);
    (void)buffered_writer_job(this);
  }
  // соединение может быть уничтожено без shutdown (например не удался TLS handshake), писатель в этот момент
  // ждёт работы и должен быть уничтожен
  // pre: писатель не запланирован (иначе нужен shutdown перед уничтожением)
  ~buffered_connection() {
    assert(writer || !allow_write);
    if (writer)
      writer.destroy();
  }

  bool try_read(std::span<byte_t> buf) noexcept {
    return inner.try_read(buf);
  }
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec) {
    inner.start_read(callback, buf, ec);
  }
  size_t try_write(std::span<const byte_t> buf, io_error_code& ec) noexcept {
    if (!allow_write) [[unlikely]] {
      ec = boost::asio::error::operation_aborted;
      return 0;
    }
    if (write_ec) [[unlikely]] {
      ec = write_ec;
      return 0;
    }
    // пока кто-то ждёт места, новые данные встают за ним, чтобы не нарушить порядок
    if (!waiters.empty() || outbuf.size() >= outbuf_limit)
      return 0;
    // TODO? если гигантская запись идти сразу в start_write без мемкпи
    outbuf.insert(outbuf.end(), buf.begin(), buf.end());
    schedule_writer();
    return buf.size();
  }
  void start_write(writer_node* n) {
    assert(n);
    assert(allow_write);
    waiters.push_back(*n);
    schedule_writer();
  }

  dd::task<void> shutdown() noexcept {
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
    co_await inner.shutdown();
    // после таймаута писатель ещё мог дописывать или быть запланирован: с write_ec он сразу встанет на
    // ожидание
    co_await drain_awaiter(this);
    std::exchange(writer, nullptr).destroy();
  }
  dd::task<void> handshake(io_error_code& ec, bool is_client) {
    return inner.handshake(ec, is_client);
  }
  static constexpr bool is_https = Inner::is_https;

  [[nodiscard]] bool has_work() const noexcept {
    return !outbuf.empty() || !waiters.empty();
  }
  // писатель ждёт работы и работы нет
  [[nodiscard]] bool idle() const noexcept {
    return writer && !has_work();
  }

  void rebind(void* ctx, rebind_result& r) {
    inner.rebind(ctx, r);
    assert(r.ptr);
    io = *r.ptr;
  }

  // писатель отправит накопленное в конце такта: всё, что уже готово выполниться, успеет дописать в outbuf
  void schedule_writer() {
    if (!writer)
      return;
    writer_task.task = std::exchange(writer, nullptr);
    io.attach(&writer_task);
  }

 private:
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
  static nodes_t move_waiters_to_outbuf(buffered_connection& c) {
    nodes_t moved;
    while (!c.waiters.empty() && c.outbuf.size() < c.outbuf_limit) {
      writer_node& n = c.waiters.front();
      c.waiters.pop_front();
      c.outbuf.insert(c.outbuf.end(), n.data.begin(), n.data.end());
      n.ec.clear();
      moved.push_back(n);
    }
    return moved;
  }

  static void resume_all(nodes_t& nodes) {
    // узел живёт в кадре корутины, которая продолжится, поэтому убирается из списка до resume
    while (!nodes.empty()) {
      writer_node& n = nodes.front();
      nodes.pop_front();
      n.callback.resume();
    }
  }

  static void fail_waiters(buffered_connection& c) {
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
  static dd::job buffered_writer_job(buffered_connection* c) {
    // terminates on bad alloc
    assert(c);
    for (;;) {
      co_await writer_idle_awaiter(c);
      // запланированный писатель мог проснуться после ошибки, тогда отправлять уже нечего
      while (c->has_work() && !c->write_ec) {
        nodes_t moved = move_waiters_to_outbuf(*c);
        // перенесённые дописывают в outbuf (пока не заполнится), это уходит той же записью
        resume_all(moved);
        std::swap(c->sendbuf, c->outbuf);
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
};

}  // namespace hidi
