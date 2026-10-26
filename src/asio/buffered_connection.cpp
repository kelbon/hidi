#include "hidi/asio/buffered_connection.hpp"

#include "connection_common.hpp"

#include <boost/asio/steady_timer.hpp>

namespace hidi {

using noexport::buffered_writer;

namespace {

// писатель засыпает, пока его не запланируют (см. `schedule_writer`)
struct writer_idle_awaiter {
  buffered_writer* w = nullptr;
  boost::asio::any_io_executor executor;

  static bool await_ready() noexcept {
    return false;
  }
  void await_suspend(std::coroutine_handle<> h) noexcept {
    assert(!w->writer);
    w->writer = h;
    // shutdown ждёт, пока всё будет дописано. Будится через очередь, а не здесь, потому что shutdown
    // уничтожает писателя, а писатель ещё выполняется
    if (w->drain_waiter)
      boost::asio::post(executor, std::exchange(w->drain_waiter, nullptr));
  }
  static void await_resume() noexcept {
  }
};

struct drain_awaiter {
  buffered_writer* w = nullptr;

  bool await_ready() const noexcept {
    return w->idle();
  }
  void await_suspend(std::coroutine_handle<> h) noexcept {
    assert(!w->drain_waiter);
    w->drain_waiter = h;
  }
  static void await_resume() noexcept {
  }
};

}  // namespace

// писатель отправит накопленное в конце такта: всё, что уже готово выполниться, успеет дописать в outbuf
static void schedule_writer(auto& self) {
  buffered_writer& w = self.writedata;
  if (w.writer)
    boost::asio::post(self.sock.get_executor(), std::exchange(w.writer, nullptr));
}

// переносит данные ждущих места в outbuf, пока он не заполнится. Возвращает перенесённых, их надо разбудить
static bi::slist<writer_node, bi::cache_last<true>> move_waiters_to_outbuf(buffered_writer& w) {
  bi::slist<writer_node, bi::cache_last<true>> moved;
  while (!w.waiters.empty() && w.outbuf.size() < buffered_writer::OUTBUF_LIMIT) {
    writer_node& n = w.waiters.front();
    w.waiters.pop_front();
    w.outbuf.insert(w.outbuf.end(), n.data.begin(), n.data.end());
    n.ec.clear();
    moved.push_back(n);
  }
  return moved;
}

static void resume_all(bi::slist<writer_node, bi::cache_last<true>>& nodes) {
  // узел живёт в кадре корутины, которая продолжится, поэтому убирается из списка до resume
  while (!nodes.empty()) {
    writer_node& n = nodes.front();
    nodes.pop_front();
    n.callback.resume();
  }
}

static void fail_waiters(buffered_writer& w) {
  assert(w.write_ec);
  while (!w.waiters.empty()) {
    writer_node& n = w.waiters.front();
    w.waiters.pop_front();
    n.ec = w.write_ec;
    n.callback.resume();
  }
}

// Гарантирует:
// * писатель либо ждёт работы (w.writer != nullptr), либо запланирован, либо пишет. Сам не завершается
// * порядок байт в сокете совпадает с порядком try_write / start_write
static dd::job start_buffered_writer_for(auto* self) {
  // terminates on bad alloc
  assert(self);
  buffered_writer& w = self->writedata;
  for (;;) {
    co_await writer_idle_awaiter(&w, self->sock.get_executor());
    // запланированный писатель мог проснуться после ошибки, тогда отправлять уже нечего
    while (w.has_work() && !w.write_ec) {
      auto moved = move_waiters_to_outbuf(w);
      std::swap(w.sendbuf, w.outbuf);
      // перенесённые уже в sendbuf, пока он пишется, они могут писать дальше в outbuf
      resume_all(moved);
      io_error_code ec;
      co_await net.write(self->sock, w.sendbuf, ec);
      w.sendbuf.clear();
      if (ec && !w.write_ec)
        w.write_ec = ec;
    }
    if (w.write_ec) {
      // накопленное уже не отправить
      w.outbuf.clear();
      fail_waiters(w);
    }
  }
}

static size_t do_buffered_try_write(auto& self, std::span<const byte_t> buf, io_error_code& ec) {
  buffered_writer& w = self.writedata;
  if (!w.allow_write) [[unlikely]] {
    ec = boost::asio::error::operation_aborted;
    return 0;
  }
  if (w.write_ec) [[unlikely]] {
    ec = w.write_ec;
    return 0;
  }
  // пока кто-то ждёт места, новые данные встают за ним, чтобы не нарушить порядок
  if (!w.waiters.empty() || w.outbuf.size() >= buffered_writer::OUTBUF_LIMIT)
    return 0;
  w.outbuf.insert(w.outbuf.end(), buf.begin(), buf.end());
  schedule_writer(self);
  return buf.size();
}

static void do_buffered_start_write(auto& self, writer_node* n) {
  buffered_writer& w = self.writedata;
  assert(n);
  assert(w.allow_write);
  w.waiters.push_back(*n);
  schedule_writer(self);
}

static dd::task<void> do_buffered_shutdown(buffered_writer& w, auto& tcp_sock) {
  if (!w.allow_write)
    co_return;
  // запрещает новые try_write / start_write
  w.allow_write = false;
  if (!w.idle()) {
    // принятое уже считается записанным (например последние ответы и GOAWAY), поэтому его надо дописать.
    // Но если пир не читает, запись не завершится никогда, тогда она отменяется по таймауту
    boost::asio::steady_timer timer(tcp_sock.get_executor(), buffered_writer::DRAIN_TIMEOUT);
    timer.async_wait([&w, &tcp_sock](const io_error_code& ec) {
      if (ec)
        return;
      // писатель может быть запланирован, а не в записи, тогда cancel его не остановит
      if (!w.write_ec)
        w.write_ec = boost::asio::error::operation_aborted;
      io_error_code e;
      e = tcp_sock.cancel(e);
      (void)e;
    });
    co_await drain_awaiter(&w);
    timer.cancel();
  }
  assert(w.idle());
  std::exchange(w.writer, nullptr).destroy();
  noexport::close_tcp_sock(tcp_sock);
}

// TCP

asio_buffered_connection::asio_buffered_connection(asio::ip::tcp::socket s) : sock(std::move(s)) {
  sock.non_blocking(true);
  (void)start_buffered_writer_for(this);
}

bool asio_buffered_connection::try_read(std::span<byte_t> buf) noexcept {
  return noexport::do_try_read(readdata, buf);
}

void asio_buffered_connection::start_read(std::coroutine_handle<> h, std::span<byte_t> buf,
                                          io_error_code& ec) {
  noexport::do_start_read(*this, h, buf, ec);
}

size_t asio_buffered_connection::try_write(std::span<const byte_t> buf, io_error_code& ec) noexcept {
  return do_buffered_try_write(*this, buf, ec);
}

void asio_buffered_connection::start_write(writer_node* n) {
  do_buffered_start_write(*this, n);
}

dd::task<void> asio_buffered_connection::shutdown() noexcept {
  return do_buffered_shutdown(writedata, sock);
}

// TLS

asio_tls_buffered_connection::asio_tls_buffered_connection(asio::ip::tcp::socket s, ssl_context_ptr ctx)
    // Note: order
    : sock(std::move(s), ctx->ctx), sslctx(std::move(ctx)) {
  sock.lowest_layer().non_blocking(true);
  (void)start_buffered_writer_for(this);
}

bool asio_tls_buffered_connection::try_read(std::span<byte_t> buf) noexcept {
  return noexport::do_try_read(readdata, buf);
}

void asio_tls_buffered_connection::start_read(std::coroutine_handle<> h, std::span<byte_t> buf,
                                              io_error_code& ec) {
  noexport::do_start_read(*this, h, buf, ec);
}

size_t asio_tls_buffered_connection::try_write(std::span<const byte_t> buf, io_error_code& ec) noexcept {
  // в отличие от asio_tls_connection запись здесь только копирует в буфер, TLS поток не затрагивается
  return do_buffered_try_write(*this, buf, ec);
}

void asio_tls_buffered_connection::start_write(writer_node* n) {
  do_buffered_start_write(*this, n);
}

dd::task<void> asio_tls_buffered_connection::shutdown() noexcept {
  return do_buffered_shutdown(writedata, sock.lowest_layer());
}

dd::task<void> asio_tls_buffered_connection::handshake(io_error_code& ec) {
  co_await net.handshake(sock, asio::ssl::stream_base::server, ec);
}

}  // namespace hidi
