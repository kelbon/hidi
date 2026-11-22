// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include "hidi/any_connection.hpp"
#include "hidi/asio/ssl_context.hpp"
#include "hidi/asio/timer.hpp"
#include "hidi/tcp_connection_options.hpp"
#include "hidi/tls_session.hpp"
#include "hidi/utils/any_io_context.hpp"
#include "hidi/utils/readahead_buffer.hpp"

#include <boost/intrusive/slist.hpp>

#include <vector>

#include <kelcoro/job.hpp>

namespace hidi {

using starter_t = move_only_fn<dd::task<void>(boost::asio::ip::tcp::socket&, deadline_t) const>;

// any_connection, используется всегда под buffered_connection
struct asio_connection {
  asio::ip::tcp::socket sock;
  readahead_buffer raf;

  explicit asio_connection(asio::ip::tcp::socket,
                           size_t read_buffer_limit = tcp_connection_options::DEFAULT_READ_BUFFER_LIMIT);

  bool try_read(std::span<byte_t>& buf) noexcept;
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec);
  size_t try_write(std::span<const byte_t>, io_error_code&) noexcept;
  void start_write(writer_node*);
  dd::task<void> shutdown() noexcept;
  dd::task<void> handshake(io_error_code&, bool) {
    co_return;
  }
  static constexpr bool is_https = false;
  void rebind(void*, rebind_result&);
};

// контекст на asio::io_context, которым не владеет. TLS или нет и параметры TCP - аргументы
// create_connection_client / create_acceptor
struct asio_ref_io {
  asio::io_context& ioctx;
  // invoked after tcp handshake (before TLS), may set socket options etc
  starter_t starter;

  explicit asio_ref_io(asio::io_context&, starter_t = {});

  bool poll_one() {
    return ioctx.poll_one() > 0;
  }

  size_t poll() {
    return ioctx.poll();
  }
  size_t run() {
    return ioctx.run();
  }
  void stop() {
    return ioctx.stop();
  }
  bool stopped() {
    return ioctx.stopped();
  }
  void restart() {
    return ioctx.restart();
  }
  any_timer create_timer(timer_precision) {
    return asio_timer(ioctx);
  }
  void attach(dd::task_node* n) {
    boost::asio::post(ioctx, n->task);
  }
  bool running_in_this_thread() {
    return ioctx.get_executor().running_in_this_thread();
  }
  void start_task() {
    ioctx.get_executor().on_work_started();
  }
  void end_task() {
    ioctx.get_executor().on_work_finished();
  }

  void* native() noexcept {
    return static_cast<void*>(this);
  }

  dd::task<any_connection_t> create_connection_client(remote_and_local_endpoints, deadline_t,
                                                      tcp_connection_options, client_ssl_context_ptr);
  any_acceptor create_acceptor(internet_address, bool reuse_address, tcp_connection_options,
                               server_ssl_context_ptr);
};

namespace noexport {
// для порядка инициализиации
struct asio_io_holder {
  asio::io_context owned;
};

}  // namespace noexport

// то же, владеет asio::io_context
struct asio_io : noexport::asio_io_holder, asio_ref_io {
  explicit asio_io(starter_t = {});
};

// any_connection, используется всегда под buffered_connection
// TCP соединение с TLS (tls_session)
struct tls_connection {
  asio::ip::tcp::socket sock;
  // расшифрованное, но ещё не отданное читателю
  readahead_buffer raf;
  ssl_context_ptr sslctx;
  tls_session session;
  // шифротекст, который try_write не смог записать в сокет сразу. Его дописывает start_write
  std::vector<byte_t> unsent;

  // precondition: ctx != nullptr
  explicit tls_connection(asio::ip::tcp::socket s, ssl_context_ptr ctx,
                          size_t read_buffer_limit = tcp_connection_options::DEFAULT_READ_BUFFER_LIMIT);

  bool try_read(std::span<byte_t>& buf) noexcept;
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec);
  // шифрует `buf` целиком одним вызовом и пишет в сокет сколько получится
  // возвращает buf.size(), если записано всё, иначе 0: по числу записанных байт шифротекста нельзя сказать,
  // сколько байт `buf` доставлено. Остаток шифротекста допишет start_write
  size_t try_write(std::span<const byte_t> buf, io_error_code&) noexcept;
  // pre: только что try_write тех же данных вернул 0 без ошибки
  void start_write(writer_node*);
  // close_notify не отправляется
  dd::task<void> shutdown() noexcept;
  dd::task<void> handshake(io_error_code& ec, bool is_client);
  static constexpr bool is_https = true;
  void rebind(void*, rebind_result&);
};

}  // namespace hidi
