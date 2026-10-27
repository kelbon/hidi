#pragma once

#include "hidi/any_connection.hpp"
#include "hidi/asio/ssl_context.hpp"
#include "hidi/asio/timer.hpp"
#include "hidi/tcp_connection_options.hpp"
#include "hidi/utils/any_io_context.hpp"

#include <boost/intrusive/slist.hpp>

#include <kelcoro/job.hpp>

namespace hidi {

using starter_t = move_only_fn<dd::task<void>(boost::asio::ip::tcp::socket&, deadline_t) const>;

namespace noexport {

struct single_read_assumption {
  static constexpr size_t readen_capacity = (1 << 14) + 9;
  unsigned char readen[readen_capacity];
  unsigned char* readen_start = readen;
  unsigned char* readen_end = readen;
  ZAL_PIN;
};

struct single_writer_guarantee {
  // boost::asio запрещает более одного async_write одновременно
  // https://www.boost.org/doc/libs/latest/doc/html/boost_asio/reference/async_write/overload1.html
  // поэтому для того чтобы send_ping не сломал большой запрос нужно создать очередь на отправку
  bi::slist<writer_node, bi::cache_last<true>> writersqueue;
  std::coroutine_handle<> writer;
  bool allow_write = true;
  ZAL_PIN;

  single_writer_guarantee() = default;
  // соединение может быть уничтожено без shutdown (например не удался TLS handshake), writer в этот момент
  // ждёт работы и должен быть уничтожен
  ~single_writer_guarantee() {
    if (writer)
      writer.destroy();
  }

  [[nodiscard]] bool writer_done() const noexcept {
    // writer ожидает новой работы, но её никогда не будет
    return !allow_write && writersqueue.empty() && writer != nullptr;
  }

  void notify_writer() {
    if (writer)
      std::exchange(writer, nullptr).resume();
  }
};

}  // namespace noexport

struct asio_connection : connection_i {
  asio::ip::tcp::socket sock;
  noexport::single_read_assumption readdata;
  noexport::single_writer_guarantee writedata;

  explicit asio_connection(asio::ip::tcp::socket);

  bool try_read(std::span<byte_t> buf) noexcept override;
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec) override;
  size_t try_write(std::span<const byte_t>, io_error_code&) noexcept override;
  void start_write(writer_node*) override;
  dd::task<void> shutdown() noexcept override;
  bool is_https() override {
    return false;
  }
};

struct asio_io_base {
  asio::io_context ioctx;

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
  any_timer create_timer() {
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
};

struct asio_io_ref_base {
  asio::io_context& ioctx;

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
  any_timer create_timer() {
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
};

struct asio_io : asio_io_base {
  tcp_connection_options options;
  // invoked after tcp handshake, may set socket options etc
  starter_t starter;

  explicit asio_io(tcp_connection_options = {}, starter_t = {});

  dd::task<any_connection_t> create_connection_client(remote_and_local_endpoints, deadline_t);
  any_acceptor create_acceptor(internet_address, bool reuse_address);
  static void rebind_context(any_connection_t& con, any_io_context_ref other);
};

struct asio_ref_io : asio_io_ref_base {
  tcp_connection_options options;
  // invoked after tcp handshake, may set socket options etc
  starter_t starter;

  explicit asio_ref_io(asio::io_context&, tcp_connection_options = {}, starter_t = {});

  dd::task<any_connection_t> create_connection_client(remote_and_local_endpoints, deadline_t);
  any_acceptor create_acceptor(internet_address, bool reuse_address);
  static void rebind_context(any_connection_t& con, any_io_context_ref other);
};

struct asio_tls_connection : connection_i {
  noexport::single_read_assumption readdata;
  asio::ssl::stream<asio::ip::tcp::socket> sock;
  ssl_context_ptr sslctx;
  noexport::single_writer_guarantee writedata;

  // precondition: ctx != nullptr
  explicit asio_tls_connection(asio::ip::tcp::socket s, ssl_context_ptr ctx);

  bool try_read(std::span<byte_t>) noexcept override;
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec) override;
  size_t try_write(std::span<const byte_t>, io_error_code&) noexcept override;
  void start_write(writer_node*) override;
  dd::task<void> shutdown() noexcept override;
  dd::task<void> handshake(io_error_code& ec, bool is_client) override;
  bool is_https() override {
    return true;
  }
};

struct asio_tls_io : asio_io_base {
  tcp_connection_options options;
  // invoked after tcp handshake (before TLS), may set socket options etc
  starter_t starter;
  // must be setted for server
  ssl_context_ptr server_sslctx = nullptr;
  // optional for client
  ssl_context_ptr client_sslctx = nullptr;

  // pre: ctx != nullptr
  asio_tls_io(client_ssl_context_ptr ctx, tcp_connection_options = {}, starter_t = {});
  // pre: ctx != nullptr
  asio_tls_io(server_ssl_context_ptr ctx, tcp_connection_options = {}, starter_t = {});

  dd::task<any_connection_t> create_connection_client(remote_and_local_endpoints, deadline_t);
  any_acceptor create_acceptor(internet_address, bool reuse_address);
  static void rebind_context(any_connection_t& con, any_io_context_ref other);
};

struct asio_tls_ref_io : asio_io_ref_base {
  tcp_connection_options options;
  // invoked after tcp handshake (before TLS), may set socket options etc
  starter_t starter;
  // must be setted for server
  ssl_context_ptr server_sslctx = nullptr;
  // optional for client
  ssl_context_ptr client_sslctx = nullptr;

  // pre: ctx != nullptr
  asio_tls_ref_io(asio::io_context&, client_ssl_context_ptr ctx, tcp_connection_options = {}, starter_t = {});

  // pre: ctx != nullptr
  asio_tls_ref_io(asio::io_context&, server_ssl_context_ptr ctx, tcp_connection_options = {}, starter_t = {});

  dd::task<any_connection_t> create_connection_client(remote_and_local_endpoints, deadline_t);
  any_acceptor create_acceptor(internet_address, bool reuse_address);
  static void rebind_context(any_connection_t& con, any_io_context_ref other);
};

}  // namespace hidi
