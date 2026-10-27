
#include "hidi/h2server.hpp"

#include "hidi/asio/asio_executor.hpp"
#include "hidi/asio/io.hpp"
#include "hidi/h2send_frames.hpp"
#include "hidi/h2server_session.hpp"
#include "hidi/h2connection.hpp"
#include "hidi/h2connection_establishment.hpp"
#include "hidi/h2server_reader.hpp"
#include "hidi/h2writer.hpp"
#include "hidi/logger.hpp"
#include "hidi/asio/awaiters.hpp"

#include <exception>
#include <latch>
#include <list>

#include <kelcoro/common.hpp>
#include <kelcoro/algorithm.hpp>

#include <zal/zal.hpp>

#include <boost/asio/ip/tcp.hpp>

/*

Предназначение сервера это управление соединениями. Вся логика по обработке соединений с клиентами внутри
h2server_session

listen добавляет server_address в прослушиваемые и создаёт корутину accept_connections слушающую этот адрес
    Note: эти корутины останавливаются после `stop_listeners`, но адреса продолжают висеть вплоть до удаления
сервера. "Так сложилось"

accept_connections вечно создаёт сокеты прослушивая адрес пока не получит специальную ошибку означающую отмену
слушания При получении сокета создаёт корутину session_lifecycle

session_lifecycle устанавливает соединение уровнем выше TCP (tls/http2), задаёт нужные настройки и далее
служит жизненным пространством для h2server_session, которая в свою очередь обёртка над h2connection
h2server_session завершается когда читатель отдаёт управление, например при получении GOAWAY фрейма

Другой путь завершения h2server_session это методы сервера shutdown/terminate

shutdown отсылает goaway клиенту на всех соединениях и ждёт завершения всех соединений

terminate отсылает goaway и отменяет все запросы на всех соединениях, затем ждёт завершения соединений

*/

namespace hidi {

struct h2server::impl {
  // on top bcs of destroy order
  any_io_context io;
  bi::list<h2server_session> sessions;
  std::list<any_acceptor> listeners;
  // gate for opened sessions / acceptors
  dd::gate sessionsgate;
  h2server_options options;
  h2server* creator = nullptr;
  move_only_fn<void(any_connection_t)> acceptcb;
#ifndef NDEBUG
  std::thread::id tid = std::this_thread::get_id();
#endif
  any_io_context& ioctx() {
    return io;
  }
  any_io_context_ref ioctx_ref() {
    return *&io;
  }
  const log_context& logctx() const noexcept {
    return options.logctx;
  }

  explicit impl(any_io_context io, h2server_options opts, h2server& owner)
      : io(std::move(io)), options(std::move(opts)), creator(&owner) {
    options.logctx.name = unique_name{};  // generate new (for different names for each server in h2server_mt)
    options.logctx.name.set_prefix(SERVER_PREFIX);
  }

  internet_address listen(server_endpoint a) {
    assert(std::this_thread::get_id() == tid);
    any_acceptor& acceptor = listeners.emplace_back(io.create_acceptor(a.addr, a.reuse_address));
    // store resolved endpoint (e.g. if port 0 was used) and store it before accept_connections
    // (accept_connections may delete acceptor!)
    internet_address binded = acceptor.get_local_endpoint();
    acceptor.listen();
    auto lit = std::prev(listeners.end());
    on_scope_failure(eraselistener) {
      listeners.erase(lit);
    };
    accept_connections(sessionsgate.hold(), lit).start_and_detach();
    eraselistener.no_longer_needed();
    HTTP2_LOG(logctx(), INFO, "Server listening on {}:{}", binded.address().to_string(), a.addr.port());
    return binded;
  }

  dd::task<void> accept_connections(dd::gate::holder, decltype(listeners)::iterator lit) try {
    assert(std::this_thread::get_id() == tid);
    assert(lit != listeners.end());
    on_scope_exit {
      HTTP2_LOG_TRACE(logctx(), "stops listening");
      listeners.erase(lit);
    };
    std::string addrstr = [&] {
      try {
        return lit->get_local_endpoint().address().to_string();
      } catch (...) {
        return std::string();
      }
    }();
    // подряд идущие ошибки accept не должны превращать цикл в спинлок
    // одиночные ошибки не замедляют приём
    constexpr duration_t MAX_ACCEPT_BACKOFF = std::chrono::milliseconds(100);
    constexpr duration_t MIN_ACCEPT_BACKOFF = std::chrono::microseconds(500);
    duration_t backoff = MIN_ACCEPT_BACKOFF;
    // note: do not remove listener on scope exit
    while (!sessionsgate.is_closed()) {
      io_error_code ec;
      any_connection_t socket = co_await lit->accept(ec);
      assert(std::this_thread::get_id() == tid);
      if (ec == asio::error::operation_aborted) {
        HTTP2_LOG_TRACE(logctx(), "listening on {} stopped", addrstr);
        if (sessionsgate.is_closed())
          co_return;
        else
          continue;
      }
      if (ec) {
        HTTP2_LOG(logctx(), ERROR, "accept failed on {}, err: {}", addrstr, ec.message());
        if (sessionsgate.is_closed())
          co_return;
        backoff = std::min(backoff * 2, MAX_ACCEPT_BACKOFF);
        co_await net.sleep(ioctx_ref(), backoff);
        continue;
      }
      backoff = MIN_ACCEPT_BACKOFF;
      HTTP2_LOG_TRACE(logctx(), "accepted connection");
      if (!sessionsgate.is_closed()) {
        if (!acceptcb)
          session_lifecycle(sessionsgate.hold(), std::move(socket)).start_and_detach();
        else
          acceptcb(std::move(socket));
      }
    }
    HTTP2_LOG_TRACE(logctx(), "accept_connections: gate is closed");
  } catch (std::exception& e) {
    HTTP2_LOG(logctx(), ERROR, "accept_connections failed with err {}", e.what());
  }

  // Note: this code ignores possible bad_alloc and other logs exceptions
  dd::task<void> session_lifecycle(dd::gate::holder, any_connection_t socket) try {
    assert(std::this_thread::get_id() == tid);

    h2connection_ptr http2con = new h2connection(std::move(socket), ioctx_ref());
    if (!http2con || !creator)
      co_return;
    if (sessionsgate.is_closed()) {
      http2con->shutdown(reqerr_e::CANCELLED);
      HTTP2_LOG(logctx(), INFO, "session completed, but server stopped (server session is not created)");
      co_return;
    }

    int reader_ec = 0;

    // firstly insert session into list, so server will drop it if stops during session establishing
    server_session_ptr session_ptr = new h2server_session(std::move(http2con), options, *creator);
    h2server_session& session = *session_ptr;
    session.connection->logctx.name.set_prefix(SERVER_SESSION_PREFIX);

    session.connection->logctx.lvl = logctx().lvl;
    session.connection->logctx.dolog = logctx().dolog;

    HTTP2_LOG_TRACE(session.logctx(), "server {} new session", logctx().name);

    sessions.push_back(session);
    on_scope_exit {
      erase_byref(sessions, session);
    };

    auto request_terminate_inactive = [session_ptr, nm = this->logctx().name](bool canceled) {
      if (canceled)
        return;
      HTTP2_LOG_TRACE(session_ptr->logctx(), "{} drops connection due client inactivity", nm);
      session_ptr->request_terminate();
    };
    auto request_terminate = [session_ptr] {
      HTTP2_LOG_TRACE(session_ptr->logctx(), "writer drops connection");
      session_ptr->request_terminate();
    };

    try {
      any_timer timer = ioctx().create_timer();
      timer.set_callback([session_ptr](bool canceled) {
        if (canceled)
          return;
        HTTP2_LOG(session_ptr->logctx(), ERROR, "connection timeout");
        session_ptr->connection->shutdown(reqerr_e::TIMEOUT);
      });
      timer.arm(options.connection_timeout);
      {
        io_error_code ec;
        co_await session.connection->tcpcon->handshake(ec, /*is_client=*/false);
        if (ec)
          throw network_exception(ec);
      }
      (void)co_await establish_http2_session_server(session.connection, options);
      session.established = true;
      timer.cancel();
      if (sessions.size() > options.limit_clients_count) [[unlikely]] {
        HTTP2_LOG(session.logctx(), WARN, "connection dropped due server`s clients limit exceeding");
        (void)co_await send_goaway(session.connection, 0, errc_e::NO_ERROR,
                                   "server's clients limit exceeded, try later");
        goto drop_session;
      }
    } catch (std::exception& e) {
      HTTP2_LOG(logctx(), ERROR, "server -> client connection establishment failed, err: {}", e.what());
      goto drop_session;
    }

    if (sessionsgate.is_closed())
      goto drop_session;

    (void)start_writer_for_server(session.connection, request_terminate, options.force_disable_hpack,
                                  session.connection_parts_gate.hold());

    session.connection->pingdeadlinetimer.set_callback(request_terminate_inactive);
    // clang-format off
    session.connection->pingtimer.set_callback([framecount = size_t(0), &session, server = this](bool canceled) mutable {
      if (canceled)
        return;
      if (session.framecount != framecount) {
        framecount = session.framecount;
        return;
      }
      // nothing happens since last call
      if (!session.connection->pingdeadlinetimer.is_armed() && !session.has_unfinished_requests()) {
        HTTP2_LOG_TRACE(session.logctx(), "detect nothing happens, arm idle deadline timer");
        session.connection->pingdeadlinetimer.arm(server->options.idle_timeout);
      }
    });
    // clang-format on
    session.connection->pingtimer.arm_periodic(std::chrono::milliseconds(100));
    reader_ec = co_await start_server_reader_for(session);
    if (reader_ec != reqerr_e::DONE) {
      // give time for sending goaway
      co_await net.sleep(ioctx_ref(), std::chrono::milliseconds(1));
    }
    HTTP2_LOG_TRACE(session.logctx(), "reader stops, waiting stop");
  drop_session:
    session.request_terminate();
    while (session.has_unfinished_requests())
      co_await yield_on_ioctx(*&session.server->ioctx());

    // we are here if reader ended with exception or after soft shutdown (streams closed, new requests
    // forbidden)
    co_await session.connection_parts_gate.close();
    co_await session.responsegate.close();
    co_await yield_on_ioctx(ioctx_ref());  // give `leave` callers time to finish their work
    HTTP2_LOG_TRACE(session.logctx(), "session stop ended");
  } catch (std::exception& e) {
    HTTP2_LOG(logctx(), ERROR, "session ended with exception: {}", e.what());
  }

  void stop_listeners() {
    assert(std::this_thread::get_id() == tid);
    HTTP2_LOG_TRACE(logctx(), "shutdown: listeners size {}", listeners.size());
    for (auto& l : listeners)
      l.close();
    // after this function sessiongate must be closed to ensure all listeners are done
  }

  dd::task<void> shutdown(deadline_t deadline) {
    co_await jump_on_ioctx(ioctx_ref());
    assert(std::this_thread::get_id() == tid);
    HTTP2_LOG_TRACE(logctx(), "shutdown started");
    on_scope_exit {
      HTTP2_LOG_TRACE(logctx(), "shutdown ended");
    };
    auto closeg = sessionsgate.close();
    for (auto& session : sessions)
      session.request_shutdown();
    stop_listeners();
    any_timer timer = ioctx().create_timer();
    if (deadline != deadline_t::never()) {
      timer.set_callback([this](bool canceled) {
        if (canceled)
          return;
        HTTP2_LOG(logctx(), WARN, "shutdown deadline reached, terminating {} sessions", sessions.size());
        for (auto& session : sessions)
          session.request_terminate();
      });
      timer.arm(deadline.tp);
    }
    co_await closeg;
    timer.cancel();
    co_await yield_on_ioctx(ioctx_ref());
    if (sessionsgate.is_closed())  // may be another shutdown/terminate
      sessionsgate.reopen();
    assert(sessions.empty());
    assert(listeners.empty());
  }

  dd::task<void> terminate() {
    co_await jump_on_ioctx(ioctx_ref());
    assert(std::this_thread::get_id() == tid);
    HTTP2_LOG_TRACE(logctx(), "terminate started");
    on_scope_exit {
      HTTP2_LOG_TRACE(logctx(), "terminate ended");
    };
    auto closeg = sessionsgate.close();
    for (auto& session : sessions)
      session.request_terminate();
    stop_listeners();
    co_await closeg;
    co_await yield_on_ioctx(ioctx_ref());
    sessionsgate.reopen();
    assert(sessions.empty());
    assert(listeners.empty());
  }
};

h2server::h2server(h2server_options options) : h2server(std::move(options), make_asio_io_context()) {
}

h2server::h2server(h2server_options options, any_io_context io)
    : m_impl(std::make_unique<h2server::impl>(std::move(io), std::move(options), *this)) {
}

h2server::h2server(h2server_options options, tcp_connection_options tcpopts)
    : h2server(std::move(options), make_asio_io_context(std::move(tcpopts))) {
}

h2server::h2server(server_ssl_context_ptr ctx, h2server_options options, tcp_connection_options tcpopts)
    : h2server(std::move(options), make_asio_tls_io_context(std::move(ctx), std::move(tcpopts))) {
}

h2server::~h2server() {
  stop();
}

void h2server::stop() {
  assert(m_impl);
  HTTP2_LOG_TRACE(m_impl->logctx(), "~h2server");
  m_impl->creator = nullptr;
#ifndef NDEBUG
  m_impl->tid = std::this_thread::get_id();  // change working thread
#endif
  std::coroutine_handle h = m_impl->terminate().start_and_detach(/*stop_at_end=*/true);

  on_scope_exit {
    h.destroy();
  };
  if (ioctx().stopped())
    ioctx().restart();
  try {
    // assume 'h' is suspended here every time when we check h.done()
    while (!h.done())
      ioctx().poll();
    ioctx().poll();
  } catch (std::exception& e) {
    HTTP2_LOG(m_impl->logctx(), ERROR, "error while ~h2server: {}", e.what());
  }
}

void h2server::set_accept_callback(move_only_fn<void(any_connection_t)> cb) {
  m_impl->acceptcb = std::move(cb);
}

size_t h2server::sessions_count() const noexcept {
  return m_impl->sessions.size();
}

internet_address h2server::listen(server_endpoint a) {
  return m_impl->listen(std::move(a));
}

dd::task<void> h2server::shutdown(deadline_t deadline) {
  return m_impl->shutdown(deadline);
}

dd::task<void> h2server::terminate() {
  return m_impl->terminate();
}

any_io_context& h2server::ioctx() {
  return m_impl->ioctx();
}

void h2server::request_stop() {
  shutdown().start_and_detach();
}

void h2server::run() {
#ifndef NDEBUG
  m_impl->tid = std::this_thread::get_id();
#endif
  if (ioctx().stopped())
    ioctx().restart();
  ioctx().run();
}

h2server_options& h2server::get_options() noexcept {
  return m_impl->options;
}

const h2server_options& h2server::get_options() const noexcept {
  return m_impl->options;
}

// multi threaded server

void h2server_mt::initialize() {
  auto cb = [this](any_connection_t sock) {
    auto& server = next_server().server;

    try {
      aa::invoke<rebind_context_m>(server->ioctx())(sock, *&server->ioctx());
    } catch (std::exception& e) {
      HTTP2_LOG(server->m_impl->logctx(), ERROR, "error when transfering accepted socket, err: {}", e.what());
      return;
    }
    // переезжаем на обрабатывающий поток
    [](std::unique_ptr<h2server>& server, any_connection_t sock) -> dd::job {
      dd::schedule_status e = co_await dd::jump_on(server->ioctx());
      assert(!!e);
      if (server->m_impl->sessionsgate.is_closed()) [[unlikely]]
        co_return;
      server->m_impl->session_lifecycle(server->m_impl->sessionsgate.hold(), std::move(sock))
          .start_and_detach();
    }(server, std::move(sock));
  };

  listen_server().server->set_accept_callback(cb);
}

internet_address h2server_mt::listen(server_endpoint e) {
  // listen always on main thread, so `listen` effects will be observable after `server::listen` return
  return listen_server().server->listen(e);
}

void h2server_mt::run() {
  assert(servers.size() == 1 || servers.size() == pool->queues_range().size() + 1);
  if (running)
    throw std::runtime_error("`run` already called");
  running = true;
  on_scope_exit {
    running = false;
  };
  if (listen_server().server->m_impl->listeners.empty())
    throw std::runtime_error("h2server_mt `run` called, but no one address listen!");
  std::latch all_done(servers.size());
  if (pool) {
    std::span qs = pool->queues_range();
    for (size_t i = 1; i != servers.size(); ++i) {
      dd::schedule_to(qs[i - 1], [&all_done, ptr = &servers[i]] {
        on_scope_exit {
          all_done.count_down();
        };
        try {
          ptr->server->ioctx().start_task();
          on_scope_failure(endtask) {
            ptr->server->ioctx().end_task();
          };
          ptr->server->run();
          endtask.no_longer_needed();
        } catch (std::exception& e) {
          HTTP2_LOG(ptr->server->m_impl->logctx(), ERROR, "cannot schedule `run` task: err: {}", e.what());
        }
      });
    }
  }
  auto& main_server = listen_server();
  main_server.server->ioctx().start_task();
  on_scope_failure(endtask) {
    main_server.server->ioctx().end_task();
  };
  main_server.server->run();
  endtask.no_longer_needed();
  assert(!stopping);
  all_done.arrive_and_wait();
}

void h2server_mt::request_stop() {
  auto do_request_stop = [](h2server_mt* self) mutable -> dd::task<void> {
    // run to listen thread to access to `running` only from one thread
    (void)co_await dd::jump_on(self->listen_server().server->ioctx());
    if (!self->running)
      co_return;
    if (self->stopping)
      co_return;  // prevent double stop
    self->stopping = true;
    on_scope_failure(term) {
      std::terminate();
    };
    // stop listen thread (0) first to avoid creating new sessions
    auto stop1 = [](local_server_ctx& c) -> dd::task<void> {
      (void)co_await dd::jump_on(c.server->ioctx());
      co_await c.server->shutdown();
      c.server->ioctx().end_task();  // allow stop .run
    };
    std::vector<dd::task<void>> tasks;
    for (size_t i = 1; i < self->servers.size(); ++i)
      tasks.push_back(stop1(self->servers[i]));
    co_await self->listen_server().server->shutdown();
    (void)co_await dd::when_all(std::move(tasks));
    (void)co_await dd::jump_on(self->listen_server().server->ioctx());
    self->stopping = false;
    self->listen_server().server->ioctx().end_task();  // allow stop .run
    term.no_longer_needed();
  };

  do_request_stop(this).start_and_detach();
}

}  // namespace hidi
