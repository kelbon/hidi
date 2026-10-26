#include "hidi/asio/io_impl.hpp"
#include "hidi/asio/asio_executor.hpp"
#include "hidi/asio/awaiters.hpp"
#include "hidi/tcp_connection_options.hpp"

#include <kelcoro/job.hpp>

#include <boost/asio/read.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>

namespace {

struct work_awaiter {
  hidi::noexport::single_writer_guarantee* i = nullptr;
  ZAL_PIN;

  bool await_ready() const noexcept {
    return !i->writersqueue.empty();
  }
  void await_suspend(std::coroutine_handle<dd::job_promise> writer) noexcept {
    assert(i->writer == nullptr);
    i->writer = writer;
  }
  static void await_resume() noexcept {
  }
};

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

static void rebind_executor(asio_connection& c, asio::io_context& new_ioctx) {
  asio::ip::tcp::socket newsock(new_ioctx);
  io_error_code ec;
  auto p = c.sock.local_endpoint(ec).protocol();
  if (ec)
    throw network_exception(ec);
  auto rawsock = c.sock.release(ec);
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
  c.sock = std::move(newsock);
}

static void rebind_executor(asio_tls_connection& c, asio::io_context& new_ioctx) {
  asio::ip::tcp::socket newsock(new_ioctx);
  io_error_code ec;
  auto p = c.sock.lowest_layer().local_endpoint(ec).protocol();
  if (ec)
    throw network_exception(ec);
  auto rawsock = c.sock.lowest_layer().release(ec);
  if (ec)
    throw network_exception(ec);
  ec = newsock.assign(p, rawsock, ec);
  if (ec)
    throw network_exception(ec);
  ec = newsock.non_blocking(true, ec);
  if (ec)
    throw network_exception(ec);
  // rebind делается до TLS handshake (см. connection_i::handshake), состояния TLS ещё нет, поэтому
  // ssl::stream пересоздаётся целиком. Его внутренние таймеры (pending_read_ / pending_write_) создаются на
  // executor потока и при замене только сокета остались бы на старом io_context: ожидание одной операции TLS
  // другой (например чтение, которому нужно записать ответ на KeyUpdate, пока идёт запись) завершалось бы в
  // чужом потоке
  c.sock = asio::ssl::stream<asio::ip::tcp::socket>(std::move(newsock), c.sslctx->ctx);
}

template <typename Connection, typename Context>
static void do_rebind_context(any_connection_t& con, any_io_context_ref other) {
  auto* p = dynamic_cast<Connection*>(con.get());
  assert(p);
  rebind_executor(*p, aa::any_cast<std::remove_cv_t<Context>&>(other).ioctx);
}

// Гарантирует:
// * writer либо в wait_work либо в net.write, никогда не завершается сам
// * если в очереди ничего нет, значит ничего не пишется и сейчас нет активного write
static dd::job start_inner_writer_for(auto* self) {
  // terminates on bad alloc
  assert(self);

  on_scope_exit {
    assert(self->writedata.writersqueue.empty());
  };
  noexport::single_writer_guarantee& wd = self->writedata;
  for (;;) {
    co_await work_awaiter(&wd);

    while (!wd.writersqueue.empty()) {
      writer_node& n = wd.writersqueue.front();

      co_await net.write(self->sock, n.data, n.ec);
      // убираем из очереди только здесь, чтобы гарантировать для shutdown
      // что пустая очередь == обработанная очередь
      self->writedata.writersqueue.pop_front();
      // 'ec' обрабатывает callback
      n.callback.resume();
      if (!self->writedata.allow_write) {
        wd.writersqueue.clear_and_dispose([](writer_node* node) {
          node->ec = boost::asio::error::operation_aborted;
          node->callback.resume();
        });
        // встаём на ожидание .destroy
        co_await work_awaiter(&wd);
        hidi::unreachable();
      }
    }
    // TODO experiment flush
  }
}

[[nodiscard]] static bool do_try_read(noexport::single_read_assumption& rd, std::span<byte_t> buf) noexcept {
  size_t avail = rd.readen_end - rd.readen_start;
  bool b = avail >= buf.size();
  if (b && !buf.empty()) {
    memcpy(buf.data(), rd.readen_start, buf.size());
    rd.readen_start += buf.size();
  }
  return b;
}

static dd::job do_read_some(auto& c, std::span<byte_t> userbuf, io_error_code& ec,
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

static void do_start_read(auto& self, std::coroutine_handle<> h, std::span<byte_t> buf, io_error_code& ec) {
  // assumes only one reader at one time
  size_t avail = self.readdata.readen_end - self.readdata.readen_start;
  assert(avail < buf.size());  // start_read must be invoked only if try_read failed
  memcpy(buf.data(), self.readdata.readen_start, avail);
  self.readdata.readen_start = self.readdata.readen_end = self.readdata.readen;
  (void)do_read_some(self, suffix(buf, buf.size() - avail), ec, h);
}

static size_t do_try_write(auto& self, std::span<const byte_t> buf, io_error_code& ec) {
  if (!self.writedata.allow_write) [[unlikely]] {
    ec = boost::asio::error::operation_aborted;
    return 0;
  }
  // просто напоминание, что при изменении try_write/start_write неплохо бы проверить с этим флагом что ничего
  // не сломалось (try_write лишь оптимизация, start_write должен справляться и сам)
#ifdef HIDI_DISABLE_TRY_WRITE
  return 0;
#endif
  // нельзя писать когда есть кто-то в writersqueue, чтобы не нарушить порядок отправки
  if (!self.writedata.writersqueue.empty())
    return 0;
  size_t written = self.sock.write_some(asio::buffer(buf.data(), buf.size()), ec);
  if (ec) {
    if (ec == asio::error::would_block)
      ec.clear();  // not a error
  }
  return written;
}

static void do_start_write(noexport::single_writer_guarantee& g, writer_node* n) {
  assert(n);
  assert(g.allow_write);
  g.writersqueue.push_back(*n);
  g.notify_writer();
}

static void close_tcp_sock(auto& tcp_sock) {
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

dd::task<void> do_shutdown(noexport::single_writer_guarantee& wd, auto& sock) {
  if (!wd.allow_write) {
    assert(wd.writer == nullptr);
    co_return;
  }
  // запрещает новые try_write/start_write
  wd.allow_write = false;
  // если пир не читает, начатый async_write не завершится никогда, поэтому он отменяется.
  // writer получит operation_aborted и сбросит остаток очереди
  io_error_code ec;
  ec = sock.cancel(ec);
  (void)ec;
  // либо writer сейчас работает, либо уже done
  // (т.к. любой write бы его разбудил и он бы никогда не заснул пока не обработает всё)
  while (!wd.writer_done())
    co_await yield_on_asio_ioctx(sock.get_executor());
  std::exchange(wd.writer, nullptr).destroy();
  close_tcp_sock(sock);
}

asio_tls_connection::asio_tls_connection(asio::ip::tcp::socket s, ssl_context_ptr ctx)
    // Note: order
    : sock(std::move(s), ctx->ctx), sslctx(std::move(ctx)) {
  sock.lowest_layer().non_blocking(true);
  (void)start_inner_writer_for(this);
}

bool asio_tls_connection::try_read(std::span<byte_t> buf) noexcept {
  return do_try_read(readdata, buf);
}

void asio_tls_connection::start_read(std::coroutine_handle<> h, std::span<byte_t> buf, io_error_code& ec) {
  do_start_read(*this, h, buf, ec);
}

size_t asio_tls_connection::try_write(std::span<const byte_t> buf, io_error_code& ec) noexcept {
  (void)buf;
  if (!writedata.allow_write) [[unlikely]] {
    ec = boost::asio::error::operation_aborted;
    return 0;
  }
  // Синхронный ssl::stream::write_some на неблокирующем сокете нельзя использовать: если сокет заполнится
  // посреди записи зашифрованных данных, asio выбросит их остаток (ssl::detail::io, case want_output),
  // а вызывающему сообщит, что открытый текст записан. Поток TLS будет испорчен.
  // Поэтому для TLS запись всегда асинхронная
  return 0;
}

void asio_tls_connection::start_write(writer_node* n) {
  do_start_write(writedata, n);
}

dd::task<void> asio_tls_connection::shutdown() noexcept {
  return do_shutdown(writedata, sock.lowest_layer());
}

dd::task<void> asio_tls_connection::handshake(io_error_code& ec) {
  co_await net.handshake(sock, asio::ssl::stream_base::server, ec);
}

asio_connection::asio_connection(asio::ip::tcp::socket s) : sock(std::move(s)) {
  sock.non_blocking(true);
  (void)start_inner_writer_for(this);
}

bool asio_connection::try_read(std::span<byte_t> buf) noexcept {
  return do_try_read(readdata, buf);
}

void asio_connection::start_read(std::coroutine_handle<> h, std::span<byte_t> buf, io_error_code& ec) {
  do_start_read(*this, h, buf, ec);
}

size_t asio_connection::try_write(std::span<const byte_t> buf, io_error_code& ec) noexcept {
  return do_try_write(*this, buf, ec);
}

void asio_connection::start_write(writer_node* n) {
  do_start_write(writedata, n);
}

dd::task<void> asio_connection::shutdown() noexcept {
  return do_shutdown(writedata, sock);
}

static dd::task<any_connection_t> do_create_connection_client(auto& self, remote_and_local_endpoints ep,
                                                              deadline_t deadline) {
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
      close_tcp_sock(tcp_sock);
    }
  });
  if (ep.local) {
    tcp_sock.open(ep.local->protocol());
    tcp_sock.bind(*ep.local);
  }
  co_await net.connect(tcp_sock, results, ec);

  if (ec)
    throw network_exception("[TCP] cannot connect to {}, err: {}", ep.remote.to_string(), ec.message());
  if (self.starter)
    co_await self.starter(tcp_sock, deadline);
  apply_tcp_options(tcp_sock, self.options);
  co_return any_connection_t(new asio_connection(std::move(tcp_sock)));
}

asio_io::asio_io(tcp_connection_options opts, starter_t s) : options(std::move(opts)), starter(std::move(s)) {
}

dd::task<any_connection_t> asio_io::create_connection_client(remote_and_local_endpoints ep,
                                                             deadline_t deadline) {
  return do_create_connection_client(*this, ep, deadline);
}

struct asio_acceptor {
  boost::asio::ip::tcp::acceptor a;
  tcp_connection_options options;

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
      co_return nullptr;
    apply_tcp_options(socket, options);
    co_return any_connection_t(new asio_connection(std::move(socket)));
  }

  void close() {
    return a.close();
  }
};

any_acceptor asio_io::create_acceptor(internet_address addr, bool reuse_address) {
  return asio_acceptor{boost::asio::ip::tcp::acceptor{ioctx, std::move(addr), reuse_address}, options};
}

void asio_io::rebind_context(any_connection_t& con, any_io_context_ref other) {
  do_rebind_context<asio_connection, asio_io>(con, other);
}

asio_ref_io::asio_ref_io(asio::io_context& ctx, tcp_connection_options opts, starter_t s)
    : asio_io_ref_base(ctx), options(std::move(opts)), starter(std::move(s)) {
}

dd::task<any_connection_t> asio_ref_io::create_connection_client(remote_and_local_endpoints ep,
                                                                 deadline_t deadline) {
  return do_create_connection_client(*this, ep, deadline);
}

any_acceptor asio_ref_io::create_acceptor(internet_address addr, bool reuse_address) {
  return asio_acceptor{boost::asio::ip::tcp::acceptor{ioctx, std::move(addr), reuse_address}, options};
}

void asio_ref_io::rebind_context(any_connection_t& con, any_io_context_ref other) {
  do_rebind_context<asio_connection, asio_ref_io>(con, other);
}

// TLS

static dd::task<any_connection_t> do_create_connection_client_tls(auto& self, remote_and_local_endpoints ep,
                                                                  deadline_t deadline) {
  namespace ssl = asio::ssl;
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
  asio::ip::tcp::socket tcp_sock(self.ioctx);

  timer.cancel();
  timer.arm(deadline);
  timer.set_callback([&](bool canceled) {
    if (!canceled) {
      timeoutflag = true;
      close_tcp_sock(tcp_sock);
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
  apply_tcp_options(tcp_sock, self.options);
  if (!self.client_sslctx)
    self.client_sslctx = make_ssl_context_for_client(self.options.additional_ssl_certificates).p;
  std::unique_ptr<asio_tls_connection> res(new asio_tls_connection(std::move(tcp_sock), self.client_sslctx));
  // tcp_sock перемещён, теперь по таймауту нужно закрывать сокет внутри res
  timer.set_callback([&](bool canceled) {
    if (!canceled) {
      timeoutflag = true;
      close_tcp_sock(res->sock.lowest_layer());
    }
  });
  if (self.options.host_for_name_verification) {
    res->sock.set_verify_mode(ssl::verify_peer);
    res->sock.set_verify_callback(
        asio::ssl::host_name_verification(*self.options.host_for_name_verification));
  } else {
    res->sock.set_verify_mode(ssl::verify_none);
  }
  if (!self.options.is_primal_connection)
    SSL_set_mode(res->sock.native_handle(), SSL_MODE_RELEASE_BUFFERS);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-9.2
  // SNI, по RFC 6066 только для доменного имени, не для IP адреса
  if (const std::string* host = ep.remote.fqdn()) {
    io_error_code ipec;
    (void)asio::ip::make_address(*host, ipec);
    if (ipec && !SSL_set_tlsext_host_name(res->sock.native_handle(), host->c_str()))
      throw network_exception("[TCP/SSL] cannot set SNI host name: {}", *host);
  }
  co_await net.handshake(res->sock, ssl::stream_base::handshake_type::client, ec);
  if (timeoutflag)
    throw timeout_exception();
  if (ec)
    throw network_exception("[TCP/SSL] cannot ssl handshake: {}", ec.message());
  co_return any_connection_t(std::move(res));
}

asio_tls_io::asio_tls_io(client_ssl_context_ptr ctx, tcp_connection_options opts, starter_t s)
    : asio_io_base(), options(std::move(opts)), client_sslctx(std::move(ctx.p)), starter(std::move(s)) {
  assert(client_sslctx != nullptr);
}

asio_tls_io::asio_tls_io(server_ssl_context_ptr ctx, tcp_connection_options opts, starter_t s)
    : asio_io_base(), options(std::move(opts)), server_sslctx(std::move(ctx.p)), starter(std::move(s)) {
  assert(server_sslctx != nullptr);
}

dd::task<any_connection_t> asio_tls_io::create_connection_client(remote_and_local_endpoints endpoint,
                                                                 deadline_t deadline) {
  return do_create_connection_client_tls(*this, endpoint, deadline);
}

struct asio_tls_acceptor {
  boost::asio::ip::tcp::acceptor a;
  ssl_context_ptr sslctx;
  tcp_connection_options options;

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
      co_return nullptr;
    apply_tcp_options(socket, options);
    // TLS handshake делает сервер через connection_i::handshake
    co_return any_connection_t(new asio_tls_connection(std::move(socket), sslctx));
  }

  void close() {
    return a.close();
  }
};

any_acceptor asio_tls_io::create_acceptor(internet_address addr, bool reuse_address) {
  assert(server_sslctx);
  return asio_tls_acceptor{boost::asio::ip::tcp::acceptor{ioctx, std::move(addr), reuse_address},
                           server_sslctx, options};
}

void asio_tls_io::rebind_context(any_connection_t& con, any_io_context_ref other) {
  do_rebind_context<asio_tls_connection, asio_tls_io>(con, other);
}

asio_tls_ref_io::asio_tls_ref_io(asio::io_context& ctx, client_ssl_context_ptr ssl,
                                 tcp_connection_options opts, starter_t s)
    : asio_io_ref_base(ctx),
      options(std::move(opts)),
      client_sslctx(std::move(ssl.p)),
      starter(std::move(s)) {
  assert(client_sslctx != nullptr);
}

asio_tls_ref_io::asio_tls_ref_io(asio::io_context& ctx, server_ssl_context_ptr ssl,
                                 tcp_connection_options opts, starter_t s)
    : asio_io_ref_base(ctx),
      options(std::move(opts)),
      server_sslctx(std::move(ssl.p)),
      starter(std::move(s)) {
  assert(server_sslctx != nullptr);
}

any_acceptor asio_tls_ref_io::create_acceptor(internet_address addr, bool reuse_address) {
  assert(server_sslctx);
  return asio_tls_acceptor{boost::asio::ip::tcp::acceptor{ioctx, std::move(addr), reuse_address},
                           server_sslctx, options};
}

dd::task<any_connection_t> asio_tls_ref_io::create_connection_client(remote_and_local_endpoints endpoint,
                                                                     deadline_t deadline) {
  return do_create_connection_client_tls(*this, endpoint, deadline);
}

void asio_tls_ref_io::rebind_context(any_connection_t& con, any_io_context_ref other) {
  do_rebind_context<asio_tls_connection, asio_tls_ref_io>(con, other);
}

}  // namespace hidi
