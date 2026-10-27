
#pragma once

#include "hidi/h2connection.hpp"
#include "hidi/h2connection_establishment.hpp"
#include "hidi/h2connection_fwd.hpp"
#include "hidi/h2errors.hpp"
#include "hidi/h2protocol.hpp"

#include <boost/intrusive/list_hook.hpp>

#include <kelcoro/gate.hpp>

namespace hidi {

struct h2server;
struct h2frame;

// Not RAII type, must be closed (request_terminate/shutdown + wait gate) before
// destroy
struct h2server_session : bi::list_base_hook<bi::link_mode<bi::safe_link>> {
  uint32_t refcount = 0;
  dd::gate responsegate;
  // for connection reader/writer
  dd::gate connection_parts_gate;
  // invariant: != nullptr
  h2connection_ptr connection;
  h2server_options options;
  h2server* server = nullptr;
  // reader increments this value for detecting client idle
  size_t framecount = 0;
  // changed only once from 'false' to 'true' when shutdown requested
  bool new_requests_forbiden = false;
  bool terminated = false;
  bool done = false;
  // used to check if goaway required when shutting down. Do not send goaway if session not established yet
  bool established = false;

  // precondition: con != nullptr
  h2server_session(h2connection_ptr con, h2server_options opts, h2server& server KELCORO_LIFETIMEBOUND);

  h2server_session(h2server_session&&) = delete;
  void operator=(h2server_session&&) = delete;

  ~h2server_session();

  [[nodiscard]] bool has_unfinished_requests() const noexcept {
    return !connection->requests.empty() || !connection->responses.empty();
  }
  [[nodiscard]] size_t requests_left_approx() const noexcept {
    return connection->requests.size() + connection->responses.size();
  }
  [[nodiscard]] size_t requests_left_exactly() const noexcept;

  // precondition: 'node' request completely assembled by server reader
  void on_request_ready(h2stream& node) noexcept;

  // forbids new requests, but existing request handling continues
  // session will be closed when open requests are handled or network error
  // occurs
  void request_shutdown() noexcept;

  // forbids new requests, cancels current requests
  // session will be closed in near future
  void request_terminate() noexcept;

  // used when request fully handled and response is sent
  void on_response_done() noexcept;

  // called when client sent RST_STREAM
  // returns false if no such stream
  bool rst_stream_server(rst_stream, bool skip_validation = false);

  void rst_stream_after_error(const stream_error&);

  // invoked when session completely done
  void on_session_done() noexcept;

  void receive_headers(h2frame frame);

  // precondition: `frame` is DATA
  void receive_data(h2frame frame);

  // marks client as not idle
  void received_frame() {
    ++framecount;
    if (connection->pingdeadlinetimer.is_armed()) [[unlikely]]  // client not idle
      connection->pingdeadlinetimer.cancel();
  }

  // creates new stream node, then server reader will collect request parts
  // until its ready then server will handle request and send response returns
  // reference to newly created node, which is alive until response sent /
  // request canceled there are 3 ways for created node:
  // * request assembled and then sent or canceled, in this case
  // `on_response_done` called by 'send_response'
  // * request not assembled and canceled, `on_response_done` called by
  // rst_stream_server()
  // * server terminates session, then `on_response_done` called by
  // h2server_session::request_terminate
  //
  // Note: may accept trailers headers too
  // второй аргумент - найденный уже существующий поток с этим id (либо nullptr)
  // нужен только для оптимизации двойного поиска
  void start_request_assemble(const h2frame& /*HEADERS frame*/, h2stream* existing);

  // after creation 3 hooks (requests, responses, timers) and 'task' left unused
  stream_ptr new_empty_stream_node(stream_id_t);

  // used when settings changed while connection active
  // may throw protocol error
  // precondition: newsettings is SETTINGS frame
  void client_settings_changed(h2frame newsettings);

  // used when server receives GOAWAY frame with NO_ERROR
  void client_requests_graceful_shutdown(goaway_frame);

  struct response_written_awaiter {
    h2connection* con = nullptr;
    h2stream* n = nullptr;

    bool await_ready() noexcept {
      // data part and header marker for writer, that this request must be
      // awaiken after sending
      assert(con && n);
      assert(!n->requests_hook.is_linked());
      if (con->is_dropped()) {
        n->status = reqerr_e::CANCELLED;
        return true;
      }
      // if not linked, request was canceled already, status is not DONE
      return !n->responses_hook.is_linked();
    }
    std::coroutine_handle<> await_suspend(dd::task<int>::handle_type h) noexcept {
      con->requests.push_back(*n);
      n->task = h;
      if (con->writer.handle)  // if writer waits job now
        return std::exchange(con->writer.handle, nullptr);

      return std::noop_coroutine();
    }
    [[nodiscard]] bool await_resume() noexcept {
      return n->status > 0;
    }
  };

  // pushes node into send queue and notifies writer about it.
  // resumes when writer writes 'node' content
  // returns 'true' if response sent, false if error occurs
  KELCORO_CO_AWAIT_REQUIRED response_written_awaiter response_written(h2stream& n) noexcept {
    return response_written_awaiter{connection.get(), &n};
  }

  // завершает запрос независимо от того собран он уже или нет
  // Вызывается для нештатного завершения,
  // для успешного завершения писатель вызывает connection.finish_request
  void finish_server_request(h2stream&, bool send_rst = true) noexcept;

  const log_context& logctx() const noexcept {
    return connection->logctx;
  }
};

inline void intrusive_ptr_add_ref(h2server_session* p) noexcept {
  ++p->refcount;
}

inline void intrusive_ptr_release(h2server_session* p) noexcept {
  --p->refcount;
  if (p->refcount == 0)
    delete p;
}

using server_session_ptr = boost::intrusive_ptr<h2server_session>;

}  // namespace hidi
