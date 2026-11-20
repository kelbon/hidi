#pragma once

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

[[nodiscard]] inline bool do_try_read(readahead_buffer& rd, std::span<byte_t>& buf) noexcept {
  if (rd.available_count() < buf.size())
    return false;
  buf = rd.take(buf.size());
  return true;
}

inline dd::job do_read_some(auto& c, std::span<byte_t> userbuf, io_error_code& ec,
                            std::coroutine_handle<> callback) {
  size_t readen = 0;
  const size_t userbufsz = userbuf.size();
  byte_t* const userbufend = userbuf.data() + userbufsz;
  while (readen < userbufsz) {
    readen += co_await net.read_some_many(c.sock, ec, std::span(userbuf.data() + readen, userbufend),
                                          c.raf.input());
    if (ec) [[unlikely]]
      break;
  }
  // при ошибке может быть прочитано меньше userbufsz, тогда в readdata ничего не попало
  if (readen > userbufsz)
    c.raf.commit_readen(readen - userbufsz);
  co_await dd::this_coro::destroy_and_transfer_control_to(callback);
}

// отдаёт в начало `buf` всё непрочитанное из `rd`, возвращает ещё не заполненную часть `buf`
// pre: непрочитанного меньше buf.size() (try_read вернул false)
inline std::span<byte_t> take_readen(readahead_buffer& raf, std::span<byte_t> buf) noexcept {
  assert(raf.available_count() < buf.size());  // try_read должен был дать false по контракту
  return raf.read_some(buf);
}

inline void do_start_read(auto& self, std::coroutine_handle<> h, std::span<byte_t> buf, io_error_code& ec) {
  // assumes only one reader at one time
  (void)do_read_some(self, take_readen(self.raf, buf), ec, h);
}

inline void close_tcp_sock(auto& tcp_sock) {
  if (!tcp_sock.is_open())
    return;
  io_error_code ec;
  ec = tcp_sock.cancel(ec);
  // dont stop on errors, i need to stop connection somehow
  (void)ec;
  ec = tcp_sock.shutdown(asio::socket_base::shutdown_both, ec);
  (void)ec;
  ec = tcp_sock.close(ec);
  (void)ec;
}

}  // namespace hidi::noexport
