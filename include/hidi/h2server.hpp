#pragma once

#include "hidi/asio/ssl_context.hpp"
#include "hidi/h2server_options.hpp"
#include "hidi/http_base.hpp"
#include "hidi/tcp_connection_options.hpp"
#include "hidi/request_context.hpp"

#include <kelcoro/task.hpp>
#include <kelcoro/thread_pool.hpp>

namespace hidi {

struct server_endpoint {
  internet_address addr;
  bool reuse_address = true;
};

// single threaded interface of server
// user must inherit h2server and implement virtual methods, then use h2server itself as
// signlethreaded or use hidi::h2server_mt as multithreaded
struct h2server {
 private:
  struct impl;
  std::unique_ptr<impl> m_impl;

  friend struct h2server_mt;
  // used by hidi::h2server_mt
  void set_accept_callback(move_only_fn<void(any_connection_t)>);

 public:
  // creates non-tls server
  // uses asio_io
  explicit h2server(h2server_options options = {});

  // pre: c.has_value() == true
  explicit h2server(h2server_options, any_io_context c);

  // creates non-tls server with tcp options (e.g. tcp_connection_options::buffer_writes)
  h2server(h2server_options, tcp_connection_options);

  // if ssl context ptr is nullptr, then its http server (not https)
  // uses asio_io/asio_tls_io
  explicit h2server(server_ssl_context_ptr, h2server_options = {}, tcp_connection_options = {});

  h2server(std::filesystem::path certificate, std::filesystem::path server_private_key,
           h2server_options opts = {})
      : h2server(make_ssl_context_for_server(std::move(certificate), std::move(server_private_key)),
                 std::move(opts)) {
  }

  h2server(h2server&&) = delete;
  void operator=(h2server&&) = delete;

  virtual ~h2server();

  // invoked when only headers for request received and data will be received
  // if `true` returned, `handle_request_stream` invoked instead of `handle_request`,
  // Note: request.body is empty, but body.content_type may be setted
  virtual bool answer_before_data(const http_request& r) const noexcept {
    return false;
  }

  // invoked only after `answer_before_data` returned true
  // request body.data.empty() == true
  // Note: request.body is empty, but body.content_type may be setted
  // returned response must not contain body data
  // if returned `stream_body_maker_t` is empty, just sends HEADERS, e.g. unaccepted websocket stream
  // Note: ctx.stream_response must not be used in this function
  virtual dd::task<std::pair<http_response, bistream_body_maker_t>> handle_request_stream(http_request,
                                                                                          memory_queue_ptr,
                                                                                          request_context) {
    assert(false);
    std::terminate();
  }

  // precondition: returned coro must not wait for sever shutdown / terminate (deadlock)
  // if exception thrown from 'handle_request', server will RST_STREAM (PROTOCOL_ERROR)
  // request_context lighweight object, easy to copy. It will be valid while request in progress, even if
  // .stream_response used
  // if hidi::stream_error thrown, its error code used in RST_STREAM
  virtual dd::task<http_response> handle_request(http_request, request_context) = 0;

  [[nodiscard]] size_t sessions_count() const noexcept;

  // returns binded address (useful e.g. if port 0 was used and OS setted real port number)
  internet_address listen(server_endpoint);

  // shutdown server softly, all responses will be sent after this method calling
  dd::task<void> shutdown();
  // server termination, stops server sessions without waiting for responses
  // but it can't stop response processing, and server are not going to send them
  dd::task<void> terminate();

  // used to run server tasks
  any_io_context& ioctx();

  void request_stop();

  // blocking wait until server stops. Must not be called from `handle_request`
  // server may be stopped only once!
  void stop();
  // similar to ioctx().run(), for common interface with h2server_mt
  void run();

  h2server_options& get_options() noexcept;
  const h2server_options& get_options() const noexcept;
};

// multithreaded version
struct h2server_mt {
 private:
  struct local_server_ctx {
    std::unique_ptr<h2server> server;
  };
  std::vector<local_server_ctx> servers;
  size_t last_selected_server = 0;
  std::optional<dd::thread_pool> pool;
  bool running = false;   // accessed only from `listen_server` thread
  bool stopping = false;  // if request_stop in progress

  // listen starts always on main thread io_context
  local_server_ctx& listen_server() {
    return servers[0];
  }

  local_server_ctx& next_server() noexcept {
    local_server_ctx& s = servers[last_selected_server];
    last_selected_server = (last_selected_server + 1) % servers.size();
    return s;
  }
  void initialize();

 public:
  // creates server with default thread count, constructs S(args...) on each thread
  template <std::derived_from<h2server> S, typename... Args>
  explicit h2server_mt(std::in_place_type_t<S> t, Args&&... args)
      : h2server_mt(std::thread::hardware_concurrency(), t, std::forward<Args>(args)...) {
  }

  template <std::derived_from<h2server> S>
  explicit h2server_mt(size_t threadcount, std::in_place_type_t<S>, auto&&... args) {
    if (threadcount == 0) {
      threadcount = std::thread::hardware_concurrency();
      if (threadcount == 0)
        threadcount = 1;
    }
    if (threadcount > 1)  // main thread also works
      pool.emplace(threadcount - 1);
    for (; threadcount; --threadcount) {
      // Note: not perfect forward
      servers.push_back(local_server_ctx(std::unique_ptr<h2server>(new S(args...))));
    }
    initialize();
  }

  h2server_mt(h2server_mt&&) = delete;
  void operator=(h2server_mt&&) = delete;

  ~h2server_mt() = default;

  // returns binded address (useful e.g. if port 0 was used and OS setted real port number)
  internet_address listen(server_endpoint);

  // runs until .stop called. Must not be invoked when `run` is active already
  // run may be called only once!
  void run();

  // prevents new requests and sessions, when requests on active sessions are done `run` call will end
  // server may be stopped only once!
  void request_stop();
};

}  // namespace hidi
