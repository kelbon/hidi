
#pragma once

#include "hidi/h2client_options.hpp"
#include "hidi/h2connection_fwd.hpp"
#include "hidi/http_base.hpp"
#include "hidi/request_context.hpp"
#include "hidi/asio/io.hpp"
#include "hidi/utils/boost_intrusive.hpp"
#include "hidi/utils/deadline.hpp"
#include "hidi/utils/unique_name.hpp"

#include <boost/intrusive/list.hpp>
#include <boost/intrusive/list_hook.hpp>
#include <boost/intrusive_ptr.hpp>

#include <kelcoro/job.hpp>
#include <kelcoro/task.hpp>
#include <kelcoro/gate.hpp>

#include <zal/zal.hpp>

namespace hidi {

struct h2client;

namespace noexport {

struct waiter_of_connection : bi::list_base_hook<link_option_t> {
  std::coroutine_handle<> task;
  h2client* client = nullptr;
  h2connection_ptr result = nullptr;
  deadline_t deadline;
  ZAL_PIN;

  explicit waiter_of_connection(h2client* c, deadline_t dl) noexcept : client(c), deadline(dl) {
  }

  ~waiter_of_connection();

  bool await_ready() noexcept;
  std::coroutine_handle<> await_suspend(std::coroutine_handle<>) noexcept;
  [[nodiscard]] h2connection_ptr await_resume();
};

// prevents new connections while alive
struct new_connection_guard {
 private:
  size_t* m_isConnecting;

 public:
  explicit new_connection_guard(size_t& b) noexcept : m_isConnecting(&b) {
    ++*m_isConnecting;
  }
  new_connection_guard(new_connection_guard&&) = delete;
  void operator=(new_connection_guard&&) = delete;

  void release() noexcept {
    if (m_isConnecting) {
      --*m_isConnecting;
      m_isConnecting = nullptr;
    }
  }
  ~new_connection_guard() {
    release();
  }
};

}  // namespace noexport
}  // namespace hidi

namespace hidi {

struct h2client {
 protected:
  friend noexport::waiter_of_connection;

  // on top bcs of destroy order
  // invariant: .has_value(), unchanged after creation
  any_io_context m_ioctx;
  endpoint m_remote;
  std::optional<internet_address> m_local;
  h2client_options m_options;
  h2connection_ptr m_connection;

  // while connection is not ready all new streams wait for it
  bi::list<noexport::waiter_of_connection, bi::cache_last<true>> m_connectionWaiters;
  size_t m_requestsInProgress = 0;
  size_t m_isConnecting = 0;  // if connection started to establish, but not established yet
  // present when m_isConnecting > 0. Used to drop in-flight connection when
  // stopping
  h2connection_ptr m_notYetReadyConnection = nullptr;
  size_t m_stopRequested = 0;
  //  used to correctly wait in 'stop' while all connect calls will end
  dd::gate m_connectionGate;

  // fills requests from raw HTTP/2 frames
  static dd::job start_reader_for(h2client*, h2connection_ptr);

  // postconditon: returns not null, !returned->dropped && returned->stream_id <= MAX_STREAM_ID
  // && !client.stop_requestedg
  [[nodiscard]] noexport::waiter_of_connection borrow_connection(deadline_t deadline) noexcept {
    return noexport::waiter_of_connection(this, deadline);
  }

  void notify_connection_waiters(h2connection_ptr result) noexcept;

  [[nodiscard]] noexport::new_connection_guard lock_connections() noexcept {
    return noexport::new_connection_guard(m_isConnecting);
  }

  // поддерживает инвариант: клиент либо не имеет соединения, либо оно в
  // процессе создания, либо оно создано, но не более одного
  [[nodiscard("this handle must be resumed")]] static dd::job start_connecting(h2client*, deadline_t);

  bool stop_requested() const noexcept {
    return m_stopRequested > 0;
  }

  dd::task<void> sleep(duration_t, io_error_code&);

 public:
  // 'remote' used for connecting when required
  // by default creates localhost client
  // creates non-tls client by default
  // example of creating tls client:
  //   h2client myclient(host, h2client_options{}, make_asio_tls_io_context());
  explicit h2client(endpoint remote = endpoint(asio::ip::address_v4::loopback()), h2client_options opts = {},
                    any_io_context = make_asio_io_context());

  h2client(h2client&&) = delete;
  void operator=(h2client&&) = delete;

  const endpoint& get_remote() const noexcept {
    return m_remote;
  }
  const std::optional<internet_address>& get_local() const noexcept {
    return m_local;
  }

  // if already connected applied only to next connection
  void set_remote(endpoint) noexcept;
  // if nullopt - returns to default
  void set_local(std::optional<internet_address>) noexcept;

  void set_connection_timeout(duration_t dur) noexcept {
    m_options.connection_timeout = dur;
  }
  const h2client_options& get_options() const noexcept {
    return m_options;
  }

  // pre: client is not connected / connecting
  void set_options(h2client_options opts) noexcept {
    assert(!connected() && !connecting());
    m_options = std::move(opts);
  }

  ~h2client();

  // rethrows exceptions from 'on_header' and 'on_data_part' to caller
  // if 'on_header' is nullptr, all headers ignored (status parsed)
  // if 'on_data_part' is nullptr, then DATA ignored
  // returns < 0 if error (reqerr_e), > 0 if 3-digit server response code
  // if client not connected yet, connects automatically
  // Note: если соединение уже устанавливается для другого запроса, ожидание ограничено дедлайном
  // того запроса, а не этого. Запрос не будет отправлен после своего дедлайна, но может завершиться
  // по таймауту позже него (не позже, чем завершится установка соединения)
  // precondition: request.method is not CONNECT ( for connect use send_connect_request)
  dd::task<int> send_request(on_header_fn_ptr on_header, on_data_part_fn_ptr on_data_part, http_request,
                             deadline_t deadline);

  // throws on errors
  dd::task<http_response> send_request(http_request, deadline_t);

  dd::task<http_response> send_request_with_trailers(http_request request, http_headers_t trailers,
                                                     deadline_t deadline) {
    stream_body_maker_t streambody = [body = std::move(request.body), t = std::move(trailers)](
                                         http_headers_t& trails,
                                         request_context) mutable -> streaming_body_t {
      co_yield std::span(body.data);
      trails = std::move(t);
    };
    return send_streaming_request(std::move(request), std::move(streambody), deadline);
  }

  // `makebody` will be called only once, but will be alive atleast until channel is done.
  // Channel may fill trailers if want to send them
  //
  // if client not connected yet, connects automatically
  // precondition: 'request.body.data` is empty,
  // makebody.has_value() == true
  // channel MUST NOT go to another thread
  dd::task<int> send_streaming_request(on_header_fn_ptr, on_data_part_fn_ptr, http_request request,
                                       stream_body_maker_t makebody, deadline_t);

  // `makebody` will be called only once, but will be alive atleast until channel is done.
  // Channel may fill trailers if want to send them
  //
  // if client not connected yet, connects automatically
  // precondition: 'request.body.data` is empty,
  // makebody.has_value() == true
  // channel MUST NOT go to another thread
  dd::task<int> send_streaming_request(on_header_fn_ptr on_header, on_data_part_fn_ptr on_data_part,
                                       http_request request, streaming_body_t streambody,
                                       deadline_t deadline) {
    return send_streaming_request(on_header, on_data_part, std::move(request),
                                  streaming_body_without_trailers(std::move(streambody)), deadline);
  }

  // throws on errors
  dd::task<http_response> send_streaming_request(http_request, stream_body_maker_t makebody, deadline_t);

  // throws on errors
  dd::task<http_response> send_streaming_request(http_request request, streaming_body_t streambody,
                                                 deadline_t deadline) {
    return send_streaming_request(std::move(request), streaming_body_without_trailers(std::move(streambody)),
                                  deadline);
  }

  // used for both connect and extented connect (websockets),
  // `makestream` will be invoked once with response and memory queue from which user can receive data
  // precondition: request.method == CONNECT && request.body.data.empty()
  // returns status of first response, < 0 if connection request was failed
  // если сервер отказал ответом без тела (END_STREAM в HEADERS, статус не 2xx), `makestream` не вызывается и
  // возвращается этот статус
  // if client not connected yet, connects automatically
  dd::task<int> send_connect_request(
      http_request request,
      move_only_fn<streaming_body_t(http_response, memory_queue_ptr, request_context)> makestream,
      deadline_t = deadline_t::never());

  bool connected() const;

  // returns true if client connected
  dd::task<bool> try_connect(deadline_t);

  // returns true if client connected
  dd::task<bool> try_connect(duration_t d) {
    return try_connect(deadline_after(d));
  }

  // returns true if client connected
  dd::task<bool> try_connect() {
    return try_connect(deadline_after(m_options.connection_timeout));
  }

  // precondition: !connected()
  dd::task<bool> try_connect(endpoint e, deadline_t d) {
    set_remote(e);
    return try_connect(d);
  }

  // ждёт завершения всех стримов и затем останавливается
  // postcondition: *this в состоянии как будто только конструктора, connected() == false
  dd::task<void> graceful_stop();

  // cancels all requests or active connections
  void cancel_all() noexcept;

  bool is_https() const noexcept;

  // postcondition: !m_connection. Mostly used by client itself
  void drop_connection(reqerr_e::values_e reason) noexcept;

  // returns true if client is now trying to connect
  [[nodiscard]] bool connecting() const noexcept {
    return m_isConnecting > 0;
  }

  any_io_context& ioctx() {
    return m_ioctx;
  }

  [[nodiscard]] const log_context& logctx() const noexcept {
    return m_options.logctx;
  }

  size_t count_active_requests() const noexcept;
  // how many active requests server allows (SETTINGS_MAX_CONCURRENT_STREAMS).
  // size_t(-1) if no connection or connecting now (e.g. after sending
  // request while there are no connection yet)
  size_t max_count_requests_allowed() const noexcept;
};

}  // namespace hidi
