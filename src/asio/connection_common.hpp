#pragma once

// общие части asio соединений: с буферизацией записи и без (см. tcp_connection_options::buffer_writes)

#include "hidi/asio/io_impl.hpp"
#include "hidi/asio/awaiters.hpp"

#include <kelcoro/job.hpp>

namespace hidi::noexport {

// переносит сокет на `new_ioctx`
inline asio::ip::tcp::socket move_socket_to(auto& sock, asio::io_context& new_ioctx) {
  asio::ip::tcp::socket newsock(new_ioctx);
  io_error_code ec;
  auto p = sock.local_endpoint(ec).protocol();
  if (ec)
    throw network_exception(ec);
  auto rawsock = sock.release(ec);
  if (ec)
    throw network_exception(ec);
  ec = newsock.assign(p, rawsock, ec);
  if (ec)
    throw network_exception(ec);
  // assign не знает, что сокет был неблокирующим. Без этого синхронный write_some в try_write при полном
  // буфере сокета ждёт в poll и блокирует весь поток
  ec = newsock.non_blocking(true, ec);
  if (ec)
    throw network_exception(ec);
  return newsock;
}

// для соединения с `asio::ip::tcp::socket sock`
template <typename Connection>
void rebind_tcp_executor(Connection& c, asio::io_context& new_ioctx) {
  c.sock = move_socket_to(c.sock, new_ioctx);
}

// для соединения с `asio::ssl::stream<asio::ip::tcp::socket> sock` и `ssl_context_ptr sslctx`
template <typename Connection>
void rebind_tls_executor(Connection& c, asio::io_context& new_ioctx) {
  // rebind делается до TLS handshake (см. connection_i::handshake), состояния TLS ещё нет, поэтому
  // ssl::stream пересоздаётся целиком. Его внутренние таймеры (pending_read_ / pending_write_) создаются на
  // executor потока и при замене только сокета остались бы на старом io_context: ожидание одной операции TLS
  // другой (например чтение, которому нужно записать ответ на KeyUpdate, пока идёт запись) завершалось бы в
  // чужом потоке
  c.sock = asio::ssl::stream<asio::ip::tcp::socket>(move_socket_to(c.sock.lowest_layer(), new_ioctx),
                                                    c.sslctx->ctx);
}

[[nodiscard]] inline bool do_try_read(single_read_assumption& rd, std::span<byte_t> buf) noexcept {
  size_t avail = rd.readen_end - rd.readen_start;
  bool b = avail >= buf.size();
  if (b && !buf.empty()) {
    memcpy(buf.data(), rd.readen_start, buf.size());
    rd.readen_start += buf.size();
  }
  return b;
}

inline dd::job do_read_some(auto& c, std::span<byte_t> userbuf, io_error_code& ec,
                            std::coroutine_handle<> callback) {
  size_t readen = 0;
  const size_t userbufsz = userbuf.size();
  byte_t* const userbufend = userbuf.data() + userbufsz;
  while (readen < userbufsz) {
    readen += co_await net.read_some_many(c.sock, ec, std::span(userbuf.data() + readen, userbufend),
                                          std::span(c.readdata.readen));
    if (ec) [[unlikely]]
      break;
  }
  // при ошибке может быть прочитано меньше userbufsz, тогда в readdata ничего не попало
  if (readen > userbufsz)
    c.readdata.readen_end += readen - userbufsz;
  co_await dd::this_coro::destroy_and_transfer_control_to(callback);
}

inline void do_start_read(auto& self, std::coroutine_handle<> h, std::span<byte_t> buf, io_error_code& ec) {
  // assumes only one reader at one time
  size_t avail = self.readdata.readen_end - self.readdata.readen_start;
  assert(avail < buf.size());  // start_read must be invoked only if try_read failed
  memcpy(buf.data(), self.readdata.readen_start, avail);
  self.readdata.readen_start = self.readdata.readen_end = self.readdata.readen;
  (void)do_read_some(self, suffix(buf, buf.size() - avail), ec, h);
}

inline void close_tcp_sock(auto& tcp_sock) {
  if (!tcp_sock.is_open())
    return;
  io_error_code ec;
  ec = tcp_sock.cancel(ec);
  // dont stop on errors, i need to stop connection somehow
  (void)ec;
  // Do not do SSL shutdown, useless errors and wasting time
  ec = tcp_sock.shutdown(asio::socket_base::shutdown_both, ec);
  (void)ec;
  ec = tcp_sock.close(ec);
  (void)ec;
}

}  // namespace hidi::noexport
