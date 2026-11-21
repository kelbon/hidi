#pragma once

#include "hidi/any_connection.hpp"
#include "hidi/utils/any_io_context.hpp"
#include "hidi/utils/reusable_buffers_stack.hpp"

#include <boost/intrusive/slist.hpp>
#include <boost/asio/error.hpp>

#include <chrono>
#include <vector>

#include <kelcoro/job.hpp>

namespace hidi {

namespace noexport {

inline reusable_buffers_stack& reusable_buffers() noexcept {
  // благодаря этим буферам при большом количестве соединений память
  // переиспользуется лучше и меньше кеш мисов
  thread_local reusable_buffers_stack s(1024);
  return s;
}

}  // namespace noexport

// * буферизирует write для Inner, даёт ей гарантию не более одного читателя/писателя одновременно
// * shutdown сначала дописывает принятое (не дольше DRAIN_TIMEOUT), затем закрывает внутреннее соединение
template <typename Inner>
struct buffered_connection {
  // сколько shutdown ждёт отправки
  static constexpr std::chrono::seconds DRAIN_TIMEOUT{2};

  using inner_connection_type = Inner;

  Inner inner;
  // если в outbuf столько байт или больше, try_write ничего не принимает и запись ждёт в `waiters`
  size_t outbuf_limit;
  // планирует отправку в конце такта и создаёт таймер для shutdown. Меняется при rebind
  any_io_context_ref io;

  // копится до отправки
  std::vector<byte_t> outbuf;
  // ждут места в outbuf
  bi::slist<writer_node, bi::cache_last<true>> waiters;

  // посылается прямо сейчас
  std::vector<byte_t> sending;
  size_t sending_offset = 0;

  // первая ошибка, после неё запись невозможна
  io_error_code write_ec;
  // писатель ждёт работы. nullptr, если он работает или уже запланирован
  std::coroutine_handle<> writer;
  dd::task_node writer_task;
  // shutdown ждёт, пока писатель допишет принятое
  std::coroutine_handle<> drain_waiter;
  dd::task_node drain_task;

  bool shutdowned = false;

  template <typename... Args>
  buffered_connection(any_io_context_ref ctx, size_t outbuf_limit, Args&&... args)
      : inner(std::forward<Args>(args)...), outbuf_limit(outbuf_limit), io(ctx) {
    assert(outbuf_limit > 0);
    (void)buffered_writer_job(this);
  }

  buffered_connection(buffered_connection&&) = delete;
  void operator=(buffered_connection&&) = delete;

  // соединение может быть уничтожено без shutdown (например не удался TLS handshake), писатель в этот момент
  // ждёт работы и должен быть уничтожен
  // pre: писатель не пишет (иначе нужен shutdown перед уничтожением)
  ~buffered_connection() {
    assert(writer || shutdowned);
    if (writer)
      writer.destroy();
  }

  bool try_read(std::span<byte_t>& buf) noexcept {
    return inner.try_read(buf);
  }
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec) {
    // эвристика: если данные кончились, отвечать больше не на что
    if (!shutdowned)
      send_ready();
    inner.start_read(callback, buf, ec);
  }
  size_t try_write(std::span<const byte_t> buf, io_error_code& ec) noexcept {
    if (shutdowned) [[unlikely]] {
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
    append_to_outbuf(buf);
    notify_writer();
    return buf.size();
  }
  void start_write(writer_node* n) {
    assert(n);
    assert(!shutdowned);
    assert(!write_ec);
    waiters.push_back(*n);
    notify_writer();
  }

  // запрещает новые записи (waiters / outbuf), но дожидается старых
  dd::task<void> shutdown() noexcept {
    if (shutdowned)
      co_return;
    // запрещает новые try_write / start_write
    shutdowned = true;
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
        notify_drain_waiter();
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

  void rebind(void* ctx, rebind_result& r) {
    inner.rebind(ctx, r);
    assert(r.ptr);
    io = *r.ptr;
  }

 private:
  bool can_write() const noexcept {
    // гарантия для Inner - не более одного писателя за раз
    // поэтому пока находимся в start_write больше писать
    return sending.empty() && !write_ec;
  }
  [[nodiscard]] bool has_work() const noexcept {
    return !outbuf.empty() || !waiters.empty();
  }
  // писатель ждёт работы и работы нет
  [[nodiscard]] bool idle() const noexcept {
    return writer && !has_work();
  }

  // писатель отправит накопленное в конце такта: всё, что уже готово выполниться, успеет дописать в outbuf
  void notify_writer() {
    if (!writer)
      return;
    writer_task.task = std::exchange(writer, nullptr);
    io.attach(&writer_task);
  }

  void notify_drain_waiter() {
    if (!drain_waiter)
      return;
    drain_task.task = std::exchange(drain_waiter, nullptr);
    io.attach(&drain_task);
  }

  struct writer_idle_awaiter {
    buffered_connection* c = nullptr;

    bool await_ready() noexcept {
      return c->has_work();
    }
    void await_suspend(std::coroutine_handle<> h) noexcept {
      assert(!c->writer);
      c->writer = h;
      // shutdown ждёт, пока всё будет дописано. Будится через очередь, а не здесь, потому что shutdown
      // уничтожает писателя, а писатель ещё выполняется
      c->notify_drain_waiter();
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

  struct start_write_awaiter : write_awaiter<Inner> {
    using write_awaiter<Inner>::write_awaiter;
    // без try_write
    bool await_ready() const noexcept {
      return false;
    }
  };

  using nodes_t = bi::slist<writer_node, bi::cache_last<true>>;

  void append_to_outbuf(std::span<const byte_t> data) {
    if (outbuf.capacity() == 0)
      outbuf = noexport::reusable_buffers().get_buffer();
    outbuf.insert(outbuf.end(), data.begin(), data.end());
  }

  // переносит данные ждущих места в outbuf, пока он не заполнится. Возвращает перенесённых, их надо разбудить
  [[nodiscard]] static nodes_t move_waiters_to_outbuf(buffered_connection& c) {
    nodes_t moved;
    while (!c.waiters.empty() && c.outbuf.size() < c.outbuf_limit) {
      writer_node& n = c.waiters.front();
      c.waiters.pop_front();
      c.append_to_outbuf(n.data);
      n.ec.clear();
      moved.push_back(n);
    }
    return moved;
  }

  static void resume_all(nodes_t& nodes) {
    while (!nodes.empty()) {
      writer_node& n = nodes.front();
      nodes.pop_front();
      n.callback.resume();
    }
  }

  // пытается записать тех кто ждёт. Кому не хватило места идут в sending
  // инвариант: если !sending.empty(), то !write_ec
  void send_ready() noexcept {
    while (can_write() && (!outbuf.empty() || !waiters.empty())) {
      nodes_t moved = move_waiters_to_outbuf(*this);
      // перенесённые дописывают в outbuf (пока не заполнится), это уходит той же записью
      resume_all(moved);
      if (!can_write())
        break;  // start_read уже написал
      size_t written = inner.try_write(outbuf, write_ec);
      if (write_ec || written == outbuf.size()) {
        noexport::reusable_buffers().return_buffer(std::move(outbuf));
      } else {
        sending = std::move(outbuf);
        sending_offset = written;
      }
    }
  }

  static void fail_waiters(buffered_connection& c) {
    assert(c.write_ec);
    nodes_t wtrs = std::move(c.waiters);
    for (auto& w : wtrs)
      w.ec = c.write_ec;
    resume_all(wtrs);
    // в waiters невозможно попасть, запись уже запрещена
    assert(c.waiters.empty());
  }

  // либо ждёт работы, либо пишет. Сам не завершается
  static dd::job buffered_writer_job(buffered_connection* c) {
    // terminates on bad alloc
    assert(c);
    for (;;) {
      // если начался шатдаун, то больше писатель не проснётся
      co_await writer_idle_awaiter(c);

      if (c->write_ec) {
        // накопленное уже не отправить
        c->outbuf.clear();
        fail_waiters(*c);
        continue;  // писатель идёт ждать конца
      }
      c->send_ready();
      if (!c->sending.empty()) {
        assert(!c->write_ec);
        // сокет принял не всё: остаток дописывается с ожиданием, новое копится в следующем буфере
        io_error_code ec;
        co_await start_write_awaiter(c->inner, ec,
                                     std::span<const byte_t>(c->sending).subspan(c->sending_offset));
        noexport::reusable_buffers().return_buffer(std::move(c->sending));
        if (ec && !c->write_ec)
          c->write_ec = ec;
      }
    }
  }
};

}  // namespace hidi
