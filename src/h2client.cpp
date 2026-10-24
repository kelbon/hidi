

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include "hidi/h2client.hpp"
#include "hidi/asio/asio_executor.hpp"
#include "hidi/h2connection.hpp"
#include "hidi/h2connection_establishment.hpp"
#include "hidi/h2errors.hpp"
#include "hidi/h2protocol.hpp"
#include "hidi/h2send_frames.hpp"
#include "hidi/h2writer.hpp"
#include "hidi/logger.hpp"
#include "hidi/utils/macro.hpp"
#include "hidi/utils/reusable_buffer.hpp"
#include "hidi/asio/awaiters.hpp"

#include <hpack/hpack.hpp>
#include <zal/zal.hpp>

/*

Путь каждого запроса в h2client:

1. корутина send_request захватывает соединение через borrow_connection, при этом
может потребоваться вызвать start_connecting, на время соединения send_request
попадаёт в client.m_connectionWaiters. Note: При ошибке создания соединения,
запросы в m_connectionWaiters будут отменёны. В будущем эту политику можно
заменить на ещё одну попытку соединения и отмену только тех запросов, что по
таймауту уже не успевают
2. После захвата соединения `send_requst` создаёт стрим, инициализирует его
streamid и засыпает на `response_received`, который:
    * инициализирует stream.task хендлом корутины send_request
    * складывает стрим в connection.responses (для отправки писателем) и
connection.timers (для проверки на таймаут)
3. писатель берёт из очереди стрим, перекладывает его в connection.responses и
начинает писать серверу. Важно переложить в responses заранее, чтобы не потерять
никаких фреймов для этого стрима
4. читатель начинает получать фреймы для стрима, вызывая on_header /
on_data_part при чтении HEADERS/DATA фреймов соответственно. При исключении из
пользовательских калбеков читатель вызывает `finish_request_with_user_exception`

5. При получении фрейма с флагом END_STREAM читатель вызывает `finish_request`,
который корректно забывает (forget) стрим из всех контейнеров и делает
task.resume, будя корутину send_request

    Note: фреймом с END_STREAM может быть в том числе trailer HEADERS после DATA

На любом этапе может прийти фрейм RST_STREAM/Goaway или вызваться graceful_stop, это
также приведёт к `finish_request`
*/

namespace hidi {

void h2client::notify_connection_waiters(h2connection_ptr result) noexcept {
  // assume only i have access to waiters
  auto waiters = std::move(m_connectionWaiters);
  if (result)
    HTTP2_LOG_TRACE(result->logctx, "resuming connection waiters, count: {}", waiters.size());
  assert(m_connectionWaiters.empty());  // check boost really works as expected
  waiters.clear_and_dispose([&](noexport::waiter_of_connection* w) {
    assert(!w->result);
    w->result = result;
    assert(w->task);
    // ordering matters for getting correct stream id
    w->task.resume();
  });
}

// periodically invoked in connection.pingtimer
struct ping_callback {
  h2connection_ptr con = nullptr;
  stream_id_t lastid = 0;
  duration_t pingtimeout;
  h2client* client = nullptr;

  // precondition: c != nullptr, client != nullptr
  explicit ping_callback(h2connection_ptr c, h2client* clientptr, duration_t ping_timeout) {
    assert(c);
    assert(clientptr);
    con = std::move(c);
    client = std::move(clientptr);
    lastid = con->laststartedstreamid;
    pingtimeout = ping_timeout;
  }

  void operator()(bool canceled) {
    if (canceled)
      return;
    // send ping only if nothing happens since last iteration
    if (lastid != con->laststartedstreamid) {
      lastid = con->laststartedstreamid;
      return;
    }
    if (!con->pingdeadlinetimer.is_armed())
      con->pingdeadlinetimer.arm(pingtimeout);
    // assume will be ended before client dies (io_ctx)
    send_ping(con, PING_VALUE, /*request_pong=*/true).start_and_detach();
  }
};

dd::job h2client::start_connecting(h2client* self, deadline_t deadline) {
  assert(self);
  co_await std::suspend_always{};  // resumed when needed by creator

  if (self->m_connection || !self->m_connectionGate.try_enter()) {
    // соединение без свободных stream id (в том числе после graceful GOAWAY) ещё может доживать активные
    // запросы, но новые стримы на нём открывать нельзя. Ожидающие не получают это соединение, их разбудит
    // читатель, когда оно завершится: он переподключится (см. `connection_dropped`)
    if (!self->m_connection || !self->m_connection->is_out_of_streamids())
      self->notify_connection_waiters(self->m_connection);
    co_return;
  }
  on_scope_exit {
    self->m_connectionGate.leave();
  };
  if (self->stop_requested()) {
    HTTP2_LOG_TRACE(self->logctx(), "connection tries to create when stop requested, ignored");
    self->notify_connection_waiters(nullptr);
    co_return;
  }
  if (self->connecting()) {
    // connection awaiters will be awakened by connection when ends
    co_return;
  }
  h2connection_ptr new_connection = nullptr;

  try {
    // note: connection unlocked before notify, avoiding this:
    // * first request drops connection,
    // * starting new connection
    // * ignore new connection (connections locked)
    // * no new requests, all stopped.
    {
      // единственное зачем нужен этот "двойной" лок сейчас - избежание ситуации описанной выше
      auto lock = self->lock_connections();
      HTTP2_LOG_TRACE(self->logctx(), "creating connection");
      on_scope_exit {
        lock.release();
        // assume all connection waiters will observe new connection.
        // Note: writer/reader not yet created, but it should not be problem
        assert(!self->m_connection);
        self->m_connection = new_connection;
        self->notify_connection_waiters(new_connection);
      };
      any_connection_t tcpcon =
          co_await self->m_ioctx.create_connection_client({self->m_remote, self->m_local}, deadline);
      h2connection_ptr con = new h2connection(std::move(tcpcon), *&self->ioctx());

      con->logctx.lvl = self->m_options.logctx.lvl;
      con->logctx.dolog = self->m_options.logctx.dolog;

      any_timer timer = self->ioctx().create_timer();
      timer.arm(deadline.tp);
      timer.set_callback([con](bool canceled) {
        if (!canceled)
          con->shutdown(reqerr_e::TIMEOUT);
      });
      assert(!self->m_notYetReadyConnection);
      self->m_notYetReadyConnection = con;
      on_scope_exit {
        self->m_notYetReadyConnection = nullptr;
      };
      new_connection = co_await establish_http2_session_client(std::move(con), self->m_options);
      timer.cancel();
    }
    assert(new_connection);

    self->m_connection->writer.handle = nullptr;
    assert(self->m_options.max_continuation_len_bytes <= MAX_CONTINUATION_LEN);
    self->m_connection->max_continuation_len = self->m_options.max_continuation_len_bytes;
    self->m_connection->max_pending_reply_frames = self->m_options.max_pending_reply_frames;

    start_reader_for(self, new_connection);
    // writer itself sets writer handle in connection
    auto sleepcb = [self](duration_t d, io_error_code& ec) { return self->sleep(d, ec); };
    auto onnetworkerr = [self] { self->drop_connection(reqerr_e::NETWORK_ERR); };
    start_writer_for_client(new_connection, std::move(sleepcb), std::move(onnetworkerr),
                            self->get_options().force_disable_hpack, {});

    if (self->m_options.ping_interval != duration_t::max()) {
      new_connection->pingtimer.arm_periodic(self->m_options.ping_interval);
      new_connection->pingtimer.set_callback(
          ping_callback(new_connection, self, self->m_options.ping_timeout));
      // armed when ping sended, canceled when ping received
      new_connection->pingdeadlinetimer.set_callback([self](bool canceled) {
        if (!canceled)
          self->drop_connection(reqerr_e::TIMEOUT);
      });
    }
    // new_connection->timeout_warden_timer will be armed when requests will be added
    new_connection->timeout_warden_timer.set_callback([new_connection](bool canceled) {
      if (canceled)
        return;
      new_connection->drop_timeouted();
      if (!new_connection->timers.empty())
        new_connection->timeout_warden_timer.arm(new_connection->timers.top()->deadline.tp);
    });
  } catch (std::exception& e) {
    HTTP2_LOG(self->logctx(), ERROR, "exception while trying to connect: {}", e.what());
    // if we created connection, but failed when starting reader / writer - drop
    self->drop_connection(reqerr_e::UNKNOWN_ERR);
  }
}

// handles only utility frames (not DATA / HEADERS)
static void handle_utility_frame(h2frame frame, h2connection& con) {
  using enum frame_e;

  switch (frame.header.type) {
    case HEADERS:
    case DATA:
      unreachable();
    case SETTINGS:
      con.server_settings_changed(frame);
      return;
    case PING:
      handle_ping(ping_frame::parse(frame.header, frame.data), &con).start_and_detach();
      return;
    case RST_STREAM:
      if (!con.rststream_client(rst_stream::parse(frame.header, frame.data))) {
        HTTP2_LOG(con.logctx, INFO,
                  "server finished stream (id: {}) which is not exists (maybe timeout or canceled)",
                  frame.header.streamid);
      }
      return;
    case GOAWAY: {
      goaway_frame f = goaway_frame::parse(frame.header, frame.data);
      if (f.error_code != errc_e::NO_ERROR) {
        throw goaway_exception(f.last_streamid, f.error_code, std::move(f.debug_info));
      } else {
        con.server_requests_graceful_shutdown(f);
        return;
      }
    }
    case WINDOW_UPDATE:
      con.window_update(window_update_frame::parse(frame.header, frame.data));
      return;
    case PUSH_PROMISE:
      // https://datatracker.ietf.org/doc/html/rfc9113#section-6.6-9
      assert(!con.local_settings.enable_push);  // always setted to 0
      throw protocol_error(errc_e::PROTOCOL_ERROR,
                           "PUSH_PROMISE must not be sent, SETTINGS_ENABLE_PUSH is 0");
    case CONTINUATION:
      // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.10-8
      throw protocol_error(
          errc_e::PROTOCOL_ERROR,
          "CONTINUATION frame received without a preceding HEADERS without END_HEADERS flag");
    case PRIORITY:
      con.validate_priority_frame_header(frame);
      [[fallthrough]];
    case PRIORITY_UPDATE:
    default:
      // ignore
      return;
  }
}

// writer works on node with reader (window_update / rst_stream possible)
// also node may be cancelled or destroyed, so writer and reader must never
// cache node between co_awaits
dd::job h2client::start_reader_for(h2client* self, h2connection_ptr c) {
  using enum frame_e;
  assert(self && c);

  HTTP2_LOG_TRACE(c->logctx, "reader started {}", self->logctx().name);

  on_scope_exit {
    HTTP2_LOG_TRACE(c->logctx, "reader ended {}", self->logctx().name);
  };

  h2connection& con = *c;
  io_error_code ec;
  reusable_buffer buffer;
  h2frame frame;
  reqerr_e::values_e reason = reqerr_e::UNKNOWN_ERR;
  protocol_error goaway_info;

  try {
    while (!con.is_done_completely()) {
      if (con.is_dropped())
        goto connection_dropped;

      // read frame header

      frame.data = buffer.get_exactly(FRAME_HEADER_LEN);

      co_await con.read(frame.data, ec);

      if (ec)
        goto network_error;

      if (con.is_dropped())
        goto connection_dropped;

      // parse frame header

      frame.header = frame_header::parse(frame.data);
      frame.validate_header();
      con.validate_frame_max_size(frame.header);
      // read frame data

      frame.data = buffer.get_exactly(frame.header.length);
      co_await con.read(frame.data, ec);
      if (ec)
        goto network_error;

      if (con.is_dropped())
        goto connection_dropped;

      // handle frame

      try {
        switch (frame.header.type) {
          case HEADERS:
            if (frame.header.flags & flags::END_HEADERS) [[likely]] {
              con.client_receive_headers(frame);
            } else {
              co_await con.receive_headers_with_continuation(
                  frame, ec, [] {}, [&](h2frame frame) { con.client_receive_headers(frame); });
              if (ec)
                goto network_error;

              if (con.is_dropped())
                goto connection_dropped;
            }
            break;
          case DATA:
            con.client_receive_data(frame);
            break;
          default:
            handle_utility_frame(frame, con);
            break;
        }
      } catch (stream_error& _e) {
        // workaround windows ABI https://github.com/llvm/llvm-project/issues/153949
        auto& e = _e;
        // reuse finish request with 'user' exception to make sure user will know about error
        h2stream* node = con.find_response_by_streamid(e.streamid);
        if (node) {
          con.finish_request_with_user_exception(*node, std::current_exception());
        } else {
          // may be request ended by timeout
          send_rst_stream(&con, e.streamid, e.errc).start_and_detach();
        }
        // do not require connection close
      }
      con.validate_pending_reply_frames();

      // connection control flow (streamlevel in handle_frame)
      if (con.my_window_size < MAX_WINDOW_SIZE / 2)
        co_await update_window_to_max(nullptr, c);
    }
  } catch (hpack::protocol_error& e) {
    HTTP2_LOG(c->logctx, ERROR, "exception while decoding headers block (HPACK), err: {}", e.what());
    goaway_info.errc = errc_e::COMPRESSION_ERROR;
    goaway_info.dbginfo = e.what();
    goto protocol_error;
  } catch (protocol_error& e) {
    HTTP2_LOG(c->logctx, INFO, "exception: {}", e.what());
    goaway_info = std::move(e);
    goto protocol_error;
  } catch (goaway_exception& gae) {
    HTTP2_LOG(c->logctx, ERROR, "goaway received, {}", gae.what());
    reason = reqerr_e::SERVER_CANCELLED_REQUEST;
    goto drop_my_connection;
  } catch (std::exception& se) {
    HTTP2_LOG(c->logctx, INFO, "unexpected exception {}", se.what());
    reason = reqerr_e::UNKNOWN_ERR;
    goto drop_my_connection;
  } catch (...) {
    HTTP2_LOG(c->logctx, INFO, "unknown exception happens");
    reason = reqerr_e::UNKNOWN_ERR;
    goto drop_my_connection;
  }

  assert(con.is_done_completely());
  // must not resume anyone with 'done', because no pending requests (completely done)
  reason = reqerr_e::DONE;
  goto drop_my_connection;
protocol_error:
  reason = reqerr_e::PROTOCOL_ERR;
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8-7
  // last_stream_id относится к стримам, начатым получателем GOAWAY. Сервер стримы не начинает (push
  // отключён), поэтому всегда 0
  send_goaway(&con, 0, goaway_info.errc, std::move(goaway_info.dbginfo)).start_and_detach();
  goto drop_my_connection;
network_error:
  reason = ec == boost::asio::error::operation_aborted ? reqerr_e::CANCELLED : reqerr_e::NETWORK_ERR;
  if (reason == reqerr_e::NETWORK_ERR)
    HTTP2_LOG_TRACE(c->logctx, "reader drops connection after network err: {}", ec.message());
drop_my_connection:
  self->drop_connection(reason);
connection_dropped:
  if (!self->m_connectionWaiters.empty() && !self->connecting()) {
    HTTP2_LOG_TRACE(con.logctx, "client initiates reconnect after graceful shutdown or out of streams");
    co_await dd::this_coro::destroy_and_transfer_control_to(
        start_connecting(self, deadline_after(self->m_options.connection_timeout)).handle);
  }
  co_return;
}

h2client::~h2client() {
  HTTP2_LOG_TRACE(logctx(), "~h2client");
  cancel_all();
  // make sure client was closed correctly before destroy
  assert(!m_connection);
  assert(m_connectionWaiters.empty());
  assert(m_requestsInProgress == 0);
}

h2client::h2client(endpoint remote, h2client_options opts, any_io_context io)
    : m_remote(std::move(remote)), m_options(opts), m_ioctx(std::move(io)) {
  assert(m_ioctx);
  m_options.logctx.name.set_prefix(CLIENT_PREFIX);
  m_options.max_receive_frame_size = std::min(FRAME_LEN_MAX, m_options.max_receive_frame_size);
  m_options.max_continuation_len_bytes = std::min(m_options.max_continuation_len_bytes, MAX_CONTINUATION_LEN);
  HTTP2_LOG_TRACE(logctx(), "h2client created");
}

noexport::waiter_of_connection::~waiter_of_connection() {
  // in case when .destroy on handle called correctly cancels request
  if (is_linked())
    erase_byref(client->m_connectionWaiters, *this);
}

bool noexport::waiter_of_connection::await_ready() noexcept {
  if (!client->m_connection || client->m_connection->is_dropped() ||
      client->m_connection->is_out_of_streamids()) {
    return false;
  }
  result = client->m_connection;
  return true;
}

std::coroutine_handle<> noexport::waiter_of_connection::await_suspend(std::coroutine_handle<> h) noexcept {
  task = h;
  client->m_connectionWaiters.push_back(*this);
  if (client->connecting())
    return std::noop_coroutine();
  return client->start_connecting(client, deadline).handle;
}

[[nodiscard]] h2connection_ptr noexport::waiter_of_connection::await_resume() {
  if (!result || result->is_dropped() || client->stop_requested())
    return nullptr;
  assert(!result->is_out_of_streamids());
  return std::move(result);
}

void h2client::drop_connection(reqerr_e::values_e reason) noexcept {
  h2connection_ptr con = std::move(m_connection);
  if (!con)
    return;
  // note: i have shared ptr to con, so it will not be destroyed while shutting
  // down and resuming its reader/writer
  con->shutdown(reason);
}

dd::task<int> h2client::send_request(on_header_fn_ptr on_header, on_data_part_fn_ptr on_data_part,
                                     http_request request, deadline_t deadline) {
  // for CONNECT send_connect_request
  assert(request.method != http_method_e::CONNECT);
  if (stop_requested()) [[unlikely]]
    co_return reqerr_e::CANCELLED;
  if (deadline.is_reached()) [[unlikely]]
    co_return reqerr_e::TIMEOUT;
  ++m_requestsInProgress;
  on_scope_exit {
    --m_requestsInProgress;
  };
  h2connection_ptr con = co_await borrow_connection(deadline);
  if (deadline.is_reached())
    co_return reqerr_e::TIMEOUT;
  if (!con)
    co_return reqerr_e::NETWORK_ERR;
  if (stop_requested()) [[unlikely]]
    co_return reqerr_e::CANCELLED;
  assert(!request.path.empty());
  request.scheme = con->tcpcon->is_https() ? scheme_e::HTTPS : scheme_e::HTTP;
  stream_id_t streamid = con->next_streamid();
  HTTP2_LOG_TRACE(con->logctx, "sending http2 request, path: {}, method: {}, streamid: {}", request.path,
                  e2str(request.method), streamid);

  stream_ptr node = con->new_stream_node(std::move(request), deadline, on_header, on_data_part, streamid);

  co_return co_await con->response_received(*node);
}

dd::task<int> h2client::send_streaming_request(on_header_fn_ptr on_header, on_data_part_fn_ptr on_data_part,
                                               http_request request, stream_body_maker_t makebody,
                                               deadline_t deadline) {
  assert(request.body.data.empty());
  assert(makebody);
  if (stop_requested()) [[unlikely]]
    co_return reqerr_e::CANCELLED;
  if (deadline.is_reached()) [[unlikely]]
    co_return reqerr_e::TIMEOUT;
  ++m_requestsInProgress;
  on_scope_exit {
    --m_requestsInProgress;
  };
  h2connection_ptr con = co_await borrow_connection(deadline);
  if (deadline.is_reached())
    co_return reqerr_e::TIMEOUT;

  if (!con)
    co_return reqerr_e::NETWORK_ERR;

  if (stop_requested()) [[unlikely]]
    co_return reqerr_e::CANCELLED;

  assert(!request.path.empty());
  request.scheme = con->tcpcon->is_https() ? scheme_e::HTTPS : scheme_e::HTTP;
  stream_id_t streamid = con->next_streamid();
  HTTP2_LOG_TRACE(con->logctx, "sending http2 streaming request, path: {}, method: {}, streamid: {}",
                  request.path, e2str(request.method), streamid);

  stream_ptr node = con->new_streaming_stream_node(std::move(request), deadline, on_header, on_data_part,
                                                   streamid, std::move(makebody));

  co_return co_await con->response_received(*node);
}

[[noreturn]] static void throw_bad_status(int status) {
  assert(status < 0);
  using enum reqerr_e::values_e;
  switch (reqerr_e::values_e(status)) {
    case DONE:
      unreachable();
    case TIMEOUT:
      throw timeout_exception{};
    case NETWORK_ERR:
      throw network_exception{""};
    case PROTOCOL_ERR:
      throw protocol_error(errc_e::PROTOCOL_ERROR);
    case CANCELLED:
      throw std::runtime_error("HTTP client: request was canceled");
    case SERVER_CANCELLED_REQUEST:
      throw std::runtime_error("HTTP client: request was canceled by server");
    default:
    case UNKNOWN_ERR:
      throw std::runtime_error("HTTP client unknown error happens");
  }
}

dd::task<http_response> h2client::send_request(http_request request, deadline_t deadline) {
  http_response rsp;
  auto on_header = [&](std::string_view name, std::string_view value) {
    rsp.headers.emplace_back(std::string(name), std::string(value));
  };
  auto on_data_part = [&](std::span<const byte_t> bytes, bool /*last_part*/) {
    rsp.body.insert(rsp.body.end(), bytes.begin(), bytes.end());
  };
  rsp.status = co_await send_request(&on_header, &on_data_part, std::move(request), deadline);
  if (rsp.status < 0)
    throw_bad_status(rsp.status);

  co_return rsp;
}

dd::task<http_response> h2client::send_streaming_request(http_request request, stream_body_maker_t makebody,
                                                         deadline_t deadline) {
  assert(makebody);
  http_response rsp;
  auto on_header = [&](std::string_view name, std::string_view value) {
    rsp.headers.emplace_back(std::string(name), std::string(value));
  };
  auto on_data_part = [&](std::span<const byte_t> bytes, bool /*last_part*/) {
    rsp.body.insert(rsp.body.end(), bytes.begin(), bytes.end());
  };
  rsp.status = co_await send_streaming_request(&on_header, &on_data_part, std::move(request),
                                               std::move(makebody), deadline);
  if (rsp.status < 0)
    throw_bad_status(rsp.status);

  co_return rsp;
}

dd::task<int> h2client::send_connect_request(
    http_request request,
    move_only_fn<streaming_body_t(http_response, memory_queue_ptr, request_context)> makestream,
    deadline_t deadline) {
  assert(request.method == http_method_e::CONNECT);
  assert(request.body.data.empty());
  assert(makestream);
  if (stop_requested()) [[unlikely]]
    co_return reqerr_e::CANCELLED;
  if (deadline.is_reached()) [[unlikely]]
    co_return reqerr_e::TIMEOUT;
  ++m_requestsInProgress;
  on_scope_exit {
    --m_requestsInProgress;
  };
  h2connection_ptr con = co_await borrow_connection(deadline);
  if (deadline.is_reached())
    co_return reqerr_e::TIMEOUT;
  if (!con)
    co_return reqerr_e::NETWORK_ERR;
  if (stop_requested()) [[unlikely]]
    co_return reqerr_e::CANCELLED;
  request.scheme = con->tcpcon->is_https() ? scheme_e::HTTPS : scheme_e::HTTP;
  stream_id_t streamid = con->next_streamid();
  HTTP2_LOG_TRACE(con->logctx, "sending CONNECT request, streamid: {}", streamid);

  http_response rsp;

  stream_ptr node = con->new_stream_node(std::move(request), deadline, nullptr, nullptr, streamid);

  auto on_header = [&](std::string_view name, std::string_view value) {
    rsp.headers.emplace_back(std::string(name), std::string(value));
  };
  node->on_header_fn = &on_header;
  // marks `node` as streaming, so END_STREAM will not be set in HEADERS
  node->makebody = [](http_headers_t&, request_context) -> streaming_body_t {
    assert(false);
    std::terminate();
  };
  int status = co_await con->response_received(*node);
  if (status < 0)
    throw_bad_status(status);

  // server accepted connect request
  rsp.status = status;

  auto makechan = [rsp = std::move(rsp), mkstream = std::move(makestream)](http_headers_t&,
                                                                           request_context ctx) mutable {
    return mkstream(std::move(rsp), new memory_queue(*ctx.node), ctx);
  };
  node->makebody = std::move(makechan);

  auto sleepcb = [this, node](duration_t d, io_error_code& ec) -> dd::task<void> {
    if (node->finished() || !node->connection || node->connection->is_dropped())
      throw stream_error(errc_e::STREAM_CLOSED, node->streamid, "stream already canceled");
    return sleep(d, ec);
  };
  auto neterrcb = [] { /*noop*/ };

  co_await dd::suspend_and_t([&](dd::task<int>::handle_type me) {
    node->task = me;
    // do not wait this stream, instead waiting RST_STREAM / END_STREAM flag
    (void)write_stream_data</*IS_CLIENT=*/true>(node, con, new writer_callbacks(sleepcb, neterrcb));
  });
  co_return status;
}

dd::task<void> h2client::graceful_stop() {
  HTTP2_LOG_TRACE(logctx(), "h2client::graceful_stop started");
  on_scope_exit {
    HTTP2_LOG_TRACE(logctx(), "h2client::graceful_stop ended");
  };
  io_error_code ec;
  h2connection_ptr con = m_connection;  // prevent destroy for graceful shutdown.

  // waiting all requests finish

  // prevent new requests on this connection
  if (con && !con->graceful_shutdown_goaway_sended)
    con->initiate_graceful_shutdown(con->last_initiated_streamid());
  // wait all requests done
  while (m_requestsInProgress != 0)
    co_await sleep(std::chrono::nanoseconds(10), ec);
  // request stop
  ++m_stopRequested;
  on_scope_exit {
    --m_stopRequested;
  };
  // wait all 'connect' coroutines done
  auto closer = m_connectionGate.close();
  // m_notYetReadyConnection назначается только после создания tcp соединения,
  // т.е. возможна ситуация, что мы пропустили момент отмены соединения и остались ждать до таймаута
  // соединения которое сейчас идёт
  while (m_connectionGate.active_count() > 0) {
    if (m_notYetReadyConnection) {
      h2connection_ptr c = std::move(m_notYetReadyConnection);
      c->shutdown(reqerr_e::CANCELLED);
      break;
    }
    co_await sleep(std::chrono::nanoseconds(1000), ec);
  }
  co_await closer;
  assert(m_isConnecting == 0);
  // даём время последнему вызвавшему m_connectionGate::leave удалиться
  co_await yield_on_ioctx(*&ioctx());
  assert(!m_notYetReadyConnection);
  // notify all not started requests about stop
  notify_connection_waiters(nullptr);
  // drop our connection correctly if exists
  drop_connection(reqerr_e::CANCELLED);

  co_await yield_on_ioctx(*&ioctx());
  m_connectionGate.reopen();

  assert(!m_connection);
  assert(m_connectionWaiters.empty());
  assert(m_requestsInProgress == 0);
}

bool h2client::connected() const {
  return !!m_connection;
}

bool h2client::is_https() const noexcept {
  assert(m_connection);
  return m_connection.get()->tcpcon->is_https();
}

void h2client::set_remote(endpoint s) noexcept {
  m_remote = std::move(s);
}

void h2client::set_local(std::optional<internet_address> a) noexcept {
  m_local = a;
}

dd::task<bool> h2client::try_connect(deadline_t deadline) {
  if (stop_requested() || m_connectionGate.is_closed())
    co_return false;
  auto guard = m_connectionGate.hold();
  h2connection_ptr con = co_await borrow_connection(deadline);
  co_return !!con;
}

void h2client::cancel_all() noexcept {
  auto all_canceled = [&] {
    return !m_notYetReadyConnection && !m_connection && m_requestsInProgress == 0 &&
           m_connectionWaiters.empty();
  };
  while (!all_canceled()) {
    drop_connection(reqerr_e::CANCELLED);
    notify_connection_waiters(nullptr);
    if (m_notYetReadyConnection)
      m_notYetReadyConnection->shutdown(reqerr_e::CANCELLED);
    if (!ioctx().running_in_this_thread())
      ioctx().poll();  // do smth pending
  }
}

dd::task<void> h2client::sleep(duration_t d, io_error_code& ec) {
  any_timer timer = ioctx().create_timer();
  co_await net.sleep(timer, d, ec);
}

size_t h2client::count_active_requests() const noexcept {
  return m_requestsInProgress;
}

size_t h2client::max_count_requests_allowed() const noexcept {
  return m_connection ? m_connection->remote_settings.max_concurrent_streams : size_t(-1);
}

}  // namespace hidi
#pragma GCC diagnostic pop
