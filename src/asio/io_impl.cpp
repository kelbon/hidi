#include "hidi/asio/io_impl.hpp"
#include "hidi/asio/awaiters.hpp"
#include "hidi/buffered_connection.hpp"
#include "hidi/tcp_connection_options.hpp"

#include "connection_common.hpp"

#include <kelcoro/job.hpp>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>

namespace {

template <typename E>
void apply_tcp_options(boost::asio::basic_socket<boost::asio::ip::tcp, E>& tcp_sock,
                       const hidi::tcp_connection_options& opts) try {
  using tcp = boost::asio::ip::tcp;

  tcp_sock.set_option(tcp::no_delay(!opts.merge_small_requests));
  if (opts.send_buffer_size)
    tcp_sock.set_option(boost::asio::socket_base::send_buffer_size(*opts.send_buffer_size));
  if (opts.receive_buffer_size)
    tcp_sock.set_option(boost::asio::socket_base::receive_buffer_size(*opts.receive_buffer_size));
} catch (std::exception& /*e*/) {
  // its not critical if options are not applied
  // HTTP2_LOG_WARN("Cannot apply tcp settings to socket, err: {}", e.what());
}

}  // namespace

namespace hidi {

static size_t write_buffer_limit(const tcp_connection_options& opts) {
  return opts.write_buffer_limit ? opts.write_buffer_limit
                                 : tcp_connection_options::DEFAULT_WRITE_BUFFER_LIMIT;
}

static any_connection_t make_tcp_connection(asio::ip::tcp::socket sock, const tcp_connection_options& opts,
                                            any_io_context_ref io) {
  return any_connection_t(std::in_place_type<buffered_connection<asio_connection>>, io,
                          write_buffer_limit(opts), std::move(sock));
}

static any_connection_t make_tls_connection(asio::ip::tcp::socket sock, ssl_context_ptr ctx,
                                            const tcp_connection_options& opts, any_io_context_ref io) {
  return any_connection_t(std::in_place_type<buffered_connection<asio_tls_connection>>, io,
                          write_buffer_limit(opts), std::move(sock), std::move(ctx));
}

// pre: предыдущая запись завершена (у соединения один писатель)
static void do_start_write(auto& sock, writer_node* n) {
  assert(n);
  asio::async_write(sock, asio::buffer(n->data.data(), n->data.size()), [n](const io_error_code& ec, size_t) {
    // 'ec' обрабатывает callback
    n->ec = ec;
    n->callback.resume();
  });
}

asio_tls_connection::asio_tls_connection(asio::ip::tcp::socket s, ssl_context_ptr ctx)
    // Note: order
    : sock(std::move(s), ctx->ctx), sslctx(std::move(ctx)) {
  sock.lowest_layer().non_blocking(true);
}

bool asio_tls_connection::try_read(std::span<byte_t> buf) noexcept {
  return noexport::do_try_read(readdata, buf);
}

void asio_tls_connection::start_read(std::coroutine_handle<> h, std::span<byte_t> buf, io_error_code& ec) {
  noexport::do_start_read(*this, h, buf, ec);
}

size_t asio_tls_connection::try_write(std::span<const byte_t>, io_error_code&) noexcept {
  // Синхронный ssl::stream::write_some на неблокирующем сокете нельзя использовать: если сокет заполнится
  // посреди записи зашифрованных данных, asio выбросит их остаток (ssl::detail::io, case want_output),
  // а вызывающему сообщит, что открытый текст записан. Поток TLS будет испорчен.
  // Поэтому для TLS запись всегда асинхронная
  return 0;
}

void asio_tls_connection::start_write(writer_node* n) {
  do_start_write(sock, n);
}

dd::task<void> asio_tls_connection::shutdown() noexcept {
  noexport::close_tcp_sock(sock.lowest_layer());
  co_return;
}

dd::task<void> asio_tls_connection::handshake(io_error_code& ec, bool is_client) {
  co_await net.handshake(sock, is_client ? asio::ssl::stream_base::client : asio::ssl::stream_base::server,
                         ec);
}

void asio_tls_connection::rebind(void* p, rebind_result& r) {
  auto* ctx = reinterpret_cast<asio_ref_io*>(p);
  noexport::rebind_tls_executor(*this, ctx->ioctx);
  r.ptr = ctx;
}

asio_connection::asio_connection(asio::ip::tcp::socket s) : sock(std::move(s)) {
  sock.non_blocking(true);
}

bool asio_connection::try_read(std::span<byte_t> buf) noexcept {
  return noexport::do_try_read(readdata, buf);
}

void asio_connection::start_read(std::coroutine_handle<> h, std::span<byte_t> buf, io_error_code& ec) {
  noexport::do_start_read(*this, h, buf, ec);
}

size_t asio_connection::try_write(std::span<const byte_t> buf, io_error_code& ec) noexcept {
  size_t written = sock.write_some(asio::buffer(buf.data(), buf.size()), ec);
  if (ec == asio::error::would_block)
    ec.clear();  // not a error
  return written;
}

void asio_connection::start_write(writer_node* n) {
  do_start_write(sock, n);
}

dd::task<void> asio_connection::shutdown() noexcept {
  noexport::close_tcp_sock(sock);
  co_return;
}

void asio_connection::rebind(void* p, rebind_result& r) {
  auto* ctx = reinterpret_cast<asio_ref_io*>(p);
  noexport::rebind_tcp_executor(*this, ctx->ioctx);
  r.ptr = ctx;
}

// создаёт и настраивает клиентское TLS соединение. Handshake делает вызывающий (connection_i::handshake),
// чтобы его можно было прервать через shutdown
static any_connection_t make_client_tls_connection(asio::ip::tcp::socket tcp_sock, ssl_context_ptr sslctx,
                                                   const tcp_connection_options& opts,
                                                   const remote_and_local_endpoints& ep,
                                                   any_io_context_ref io) {
  namespace ssl = asio::ssl;
  any_connection_t res;
  asio_tls_connection& c = res.emplace<buffered_connection<asio_tls_connection>>(
                                  io, write_buffer_limit(opts), std::move(tcp_sock), std::move(sslctx))
                               .inner;
  if (opts.host_for_name_verification) {
    c.sock.set_verify_mode(ssl::verify_peer);
    c.sock.set_verify_callback(asio::ssl::host_name_verification(*opts.host_for_name_verification));
  } else {
    c.sock.set_verify_mode(ssl::verify_none);
  }
  if (!opts.is_primal_connection)
    SSL_set_mode(c.sock.native_handle(), SSL_MODE_RELEASE_BUFFERS);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-9.2
  // SNI, по RFC 6066 только для доменного имени, не для IP адреса
  if (const std::string* host = ep.remote.fqdn()) {
    io_error_code ipec;
    (void)asio::ip::make_address(*host, ipec);
    if (ipec && !SSL_set_tlsext_host_name(c.sock.native_handle(), host->c_str()))
      throw network_exception("[TCP/SSL] cannot set SNI host name: {}", *host);
  }
  return res;
}

static dd::task<any_connection_t> do_create_connection_client(auto& self, remote_and_local_endpoints ep,
                                                              deadline_t deadline,
                                                              tcp_connection_options opts,
                                                              client_ssl_context_ptr ssl) {
  using tcp = asio::ip::tcp;

  tcp::resolver resolver(self.ioctx);

  asio_timer timer(self.ioctx);
  bool timeoutflag = false;

  timer.arm(deadline);
  timer.set_callback([&](bool canceled) {
    if (!canceled) {
      timeoutflag = true;
      resolver.cancel();
    }
  });

  io_error_code ec;
  auto results = co_await net.resolve(resolver, ep.remote, ec);
  if (timeoutflag)
    throw timeout_exception();
  if (results.empty() || ec)
    throw network_exception("[TCP] cannot resolve host: {}, err: {}", ep.remote.to_string(), ec.message());
  tcp::socket tcp_sock(self.ioctx);

  timer.cancel();
  timer.arm(deadline);
  timer.set_callback([&](bool canceled) {
    if (!canceled) {
      timeoutflag = true;
      noexport::close_tcp_sock(tcp_sock);
    }
  });
  if (ep.local) {
    tcp_sock.open(ep.local->protocol());
    tcp_sock.bind(*ep.local);
  }
  co_await net.connect(tcp_sock, std::move(results), ec);

  if (timeoutflag)
    throw timeout_exception();
  if (ec)
    throw network_exception("[TCP] cannot connect to {}, err: {}", ep.remote.to_string(), ec.message());
  if (self.starter)
    co_await self.starter(tcp_sock, deadline);
  // таймер мог сработать во время starter и закрыть сокет. Таймаут TLS handshake - забота вызывающего
  if (timeoutflag)
    throw timeout_exception();
  apply_tcp_options(tcp_sock, opts);
  if (ssl)
    co_return make_client_tls_connection(std::move(tcp_sock), std::move(ssl.p), opts, ep, self);
  co_return make_tcp_connection(std::move(tcp_sock), opts, self);
}

struct asio_acceptor {
  boost::asio::ip::tcp::acceptor a;
  // nullptr - без TLS
  ssl_context_ptr sslctx;
  tcp_connection_options options;
  // контекст, создавший acceptor (для buffered_connection)
  any_io_context_ref io;

  internet_address get_local_endpoint() const {
    return a.local_endpoint();
  }

  internet_address listen() {
    a.listen();
    return get_local_endpoint();
  }

  dd::task<any_connection_t> accept(io_error_code& ec) {
    asio::ip::tcp::socket socket(a.get_executor());

    co_await net.accept(a, socket, ec);
    if (ec)
      co_return any_connection_t{};
    apply_tcp_options(socket, options);
    // TLS handshake делает сервер через connection_i::handshake
    if (sslctx)
      co_return make_tls_connection(std::move(socket), sslctx, options, io);
    co_return make_tcp_connection(std::move(socket), options, io);
  }

  void close() {
    return a.close();
  }
};

static any_acceptor do_create_acceptor(auto& self, internet_address addr, bool reuse_address,
                                       tcp_connection_options opts, server_ssl_context_ptr ssl) {
  return asio_acceptor{boost::asio::ip::tcp::acceptor{self.ioctx, std::move(addr), reuse_address},
                       std::move(ssl.p), std::move(opts), self};
}

asio_ref_io::asio_ref_io(asio::io_context& ctx, starter_t s) : ioctx(ctx), starter(std::move(s)) {
}

dd::task<any_connection_t> asio_ref_io::create_connection_client(remote_and_local_endpoints ep,
                                                                 deadline_t deadline,
                                                                 tcp_connection_options opts,
                                                                 client_ssl_context_ptr ssl) {
  return do_create_connection_client(*this, std::move(ep), deadline, std::move(opts), std::move(ssl));
}

any_acceptor asio_ref_io::create_acceptor(internet_address addr, bool reuse_address,
                                          tcp_connection_options opts, server_ssl_context_ptr ssl) {
  return do_create_acceptor(*this, std::move(addr), reuse_address, std::move(opts), std::move(ssl));
}

asio_io::asio_io(starter_t s) : asio_ref_io(owned, std::move(s)) {
}

}  // namespace hidi
