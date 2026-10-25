
#pragma once

#include "hidi/any_connection.hpp"
#include "hidi/h2connection_fwd.hpp"
#include "hidi/h2protocol.hpp"
#include "hidi/http_base.hpp"
#include "hidi/utils/any_io_context.hpp"
#include "hidi/utils/boost_intrusive.hpp"
#include "hidi/utils/deadline.hpp"
#include "hidi/utils/unique_name.hpp"
#include "hidi/utils/fn_ref.hpp"
#include "hidi/utils/merged_segments.hpp"
#include "hidi/asio/aio_context.hpp"

#include <span>

#include <boost/intrusive/list.hpp>
#include <boost/intrusive/list_hook.hpp>
#include <boost/intrusive/slist.hpp>
#include <boost/intrusive/treap_set.hpp>
#include <boost/intrusive/unordered_set.hpp>
#include <boost/intrusive_ptr.hpp>

#include <kelcoro/road.hpp>
#include <kelcoro/job.hpp>
#include <kelcoro/task.hpp>

namespace hidi {

struct h2frame {
  frame_header header;
  std::span<byte_t> data;

  void validate_header() const {
    if (header.length > FRAME_LEN_MAX || header.streamid > MAX_STREAM_ID)
      throw protocol_error(errc_e::PROTOCOL_ERROR, std::format("invalid frame header {}", header));
  }

  void validate_streamid() const {
    // SERVER_PUSH disabled always, so stream id must be odd
    if (header.streamid == 0 || (header.streamid % 2) == 0)
      throw protocol_error(errc_e::PROTOCOL_ERROR, std::format("invalid streamid, header: {}", header));
  }

  // returns false if incorrect frame
  // Note: not changes header.length, instead changes .data span. Its important
  // for control flow
  // makes sense only for DATA/HEADERS (they can be padded)
  void remove_padding() {
    if (header.flags & flags::PADDED) [[unlikely]] {
      // padding len in first data byte
      strip_padding(data);
      // set flag to 0, so next 'remove_padding' will not break frame
      header.flags &= flags_t(~flags::PADDED);
    }
  }

  // precondition: frame is HEADERS
  // throws on protocol error
  void ignore_deprecated_priority() {
    assert(header.type == frame_e::HEADERS);
    if (!(header.flags & flags::PRIORITY)) [[likely]]
      return;
    // options to disable priority is extension for protocol, it may not be
    // supported so i can receive it ignores
    //  [Exclusive (1)],
    //  [Stream Dependency (31)],
    //  [Weight (8)]
    static_assert(CHAR_BIT == 8);
    if (data.size() < 5) {
      throw protocol_error{
          errc_e::PROTOCOL_ERROR,
          std::format("invalid HEADERS frame with priority, data size < 5 ({})", data.size())};
    }
    uint32_t dependency;
    memcpy(&dependency, data.data(), sizeof(dependency));
    htonli(dependency);
    dependency &= uint32_t(0x7FFFFFFF);
    if (dependency == header.streamid) {
      throw protocol_error(errc_e::PROTOCOL_ERROR,
                           std::format("HEADER with priority depends on itself", header.streamid));
    }

    remove_prefix(data, 5);
    // set flag to 0, so next 'ignore_deprecated_priority' will not break frame
    header.flags &= flags_t(~flags::PRIORITY);
  }
};

// request starts in connection.requests, then goes into connection.responses
// Note: this type used in client when sending request
// and reused in server, in this case its response for sending in writer (.req
// field stores response)
struct h2stream {
  using requests_hook_type = bi::list_member_hook<link_option_t>;
  using responses_hook_type = bi::unordered_set_member_hook<link_option_t>;
  using timers_hooks_type = bi::bs_set_member_hook<link_option_t>;

  // used when request started in connection.requests and when its free in
  // connection.free_nodes
  requests_hook_type requests_hook;
  responses_hook_type responses_hook;
  timers_hooks_type timers_hook;
  int32_t refcount = 0;
  stream_id_t streamid;
  // local -> remote hope
  // inited from remote settings
  // how many octets local can send to remote
  cfint_t lr_streamlevel_windowsize;
  // remote -> local hope
  // inited from local settings
  // how many octets remote can send to local
  cfint_t rl_streamlevel_windowsize;
  // 'new_stream_node' fills req, deadline and initial stream window sizes
  http_request req;
  deadline_t deadline;
  dd::task<int>::handle_type task;  // setted by 'await_suspend' (requester)
  h2connection_ptr connection = nullptr;
  // received resonse (filled by 'reader' in connection)
  on_header_fn_ptr on_header_fn;
  on_data_part_fn_ptr on_data_part_fn;
  int status = reqerr_e::UNKNOWN_ERR;
  bool canceled_by_rststream = false;
  // true if already was in `on_response_done`
  // used to prevent bistreams handled in `on_response_done` twice (they `ended` twice)
  bool responded = false;
  bool answered_before_data = false;  // when server::answer_before_data() returned true
  bool end_stream_received = false;   // marks half-closed stream
  // filled if this a streaming request
  stream_body_maker_t makebody;
  // ignored for server streaming nodes (websocket etc, exchanging bytes)
  size_t used_bytes = 0;  // used only by server
  ZAL_PIN;

  // returns false if not allowed to use 'n' bytes
  [[nodiscard]] bool use_bytes(size_t n) noexcept;

  // connect request returns before END_STREAM when first HEADERS received and not send :path and :authority
  // client-side
  [[nodiscard]] bool is_connect_request() const noexcept {
    return req.method == http_method_e::CONNECT;
  }
  [[nodiscard]] bool is_output_streaming() const noexcept {
    return makebody.has_value();
  }
  // server side
  bool is_input_streaming() const noexcept {
    return on_data_part_fn != nullptr;
  }
  [[nodiscard]] bool has_body() const noexcept {
    return is_output_streaming() || !req.body.data.empty();
  }

  // precondition: started
  [[nodiscard]] bool finished() const noexcept {
    return task == nullptr;
  }

  // returns true if stream was received any frame with END_STREAM flag
  [[nodiscard]] bool is_half_closed() const noexcept {
    return end_stream_received;
  }

  // client side
  void receive_trailers_headers(hpack::decoder&, h2frame /*headers frame*/);

  // server side
  void receive_request_trailers(hpack::decoder&, h2frame /*headers frame*/);

  // client side
  // expects :status as first header
  // precondition: padding removed
  void receive_response_headers(hpack::decoder& decoder, h2frame frame);

  // client side
  // precondition: padding removed
  void receive_response_data(h2frame frame);

  // server side
  // expects required pseudoheaders like :path
  // precondition: padding removed
  void receive_request_headers(h2frame frame);

  // server side
  // adds frame data octets to request body
  // precondition: padding removed
  void receive_request_data(h2frame frame);

  struct equal_by_streamid {
    bool operator()(const stream_id_t& l, const stream_id_t& r) const noexcept {
      return l == r;
    }
  };
  struct key_of_value {
    using type = stream_id_t;
    const type& operator()(const h2stream& v) const noexcept {
      return v.streamid;
    }
  };
  struct hash_by_streamid {
    size_t operator()(stream_id_t s) const noexcept {
      // only grow (1, 3, 5...) so last bit is always 1, never intersects
      // uint32_t, so always less uint32_t max (high bits always false and
      // fixable by |, but i dont need it) proved as best possible hash for this
      // case in bench
      return s >> 1;
    }
  };
  struct compare_by_deadline {
    bool operator()(const h2stream& l, const h2stream& r) const noexcept {
      return l.deadline < r.deadline;  // less means higher priority
    }
  };

  const log_context& logctx() const noexcept;
};

// Note: shutdown must be called
struct h2connection {
  using requests_member_hook_t =
      bi::member_hook<h2stream, h2stream::requests_hook_type, &h2stream::requests_hook>;
  using responses_member_hook_t =
      bi::member_hook<h2stream, h2stream::responses_hook_type, &h2stream::responses_hook>;
  using timers_member_hook_t = bi::member_hook<h2stream, h2stream::timers_hooks_type, &h2stream::timers_hook>;

  using requests_t =
      bi::list<h2stream, bi::cache_last<true>, requests_member_hook_t, bi::constant_time_size<true>>;

  using responses_t =
      bi::unordered_set<h2stream, bi::constant_time_size<true>, responses_member_hook_t,
                        bi::key_of_value<h2stream::key_of_value>, bi::equal<h2stream::equal_by_streamid>,
                        bi::hash<h2stream::hash_by_streamid>, bi::power_2_buckets<true>>;

  using timers_t = bi::treap_multiset<h2stream, bi::constant_time_size<true>, timers_member_hook_t,
                                      bi::priority<h2stream::compare_by_deadline>,
                                      bi::compare<h2stream::compare_by_deadline>>;

  settings_t remote_settings;
  settings_t local_settings;
  // setted to `remote_settings` on client side and `local_settings` on server side
  const settings_t* server_settings = nullptr;
  any_connection_t tcpcon;
  hpack::encoder encoder;
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.2-2.2.1
  // Server may send SETTINGS frame with reduced hpack table size,
  // this means request for client encoder to send dynamic_size_update
  //
  // if true, new value in server_settings.header_table_size
  bool encodertablesizechangerequested = false;
  // правила для первого фрейма SETTINGS отличаются от правил для последующих
  bool first_settings_frame_received = false;
  hpack::decoder decoder;
  // odd, for client its last started stream, for server last stream started by client
  stream_id_t laststartedstreamid = 0;
  uint32_t refcount = 0;
  cfint_t my_window_size = INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL;
  cfint_t receiver_window_size = INITIAL_WINDOW_SIZE_FOR_CONNECTION_OVERALL;
  // no one frame must be between CONTINUATION frames
  dd::road continuation_gateway;
  // setted only when writer is suspended and nullptr when works
  dd::job writer = {};
  requests_t requests;

  static constexpr inline size_t initial_buckets_count = 2;

  // Note: must be before 'responses' because of destroy ordering
  // invariant: .size is always pow of 2
  std::vector<responses_t::bucket_type> buckets;
  responses_t responses;
  timers_t timers;
  bool dropped = false;  // setted ONLY in drop_connection
  // if goaway with NO_ERROR was already sended. This ensures, that we will
  // initiate goaway (in graceful_stop) OR server initiates goaway and we answered once
  bool graceful_shutdown_goaway_sended = false;
  // invariant: has_value()
  any_timer pingtimer;
  // invariant: has_value()
  any_timer pingdeadlinetimer;
  // invariant: has_value()
  any_timer timeout_warden_timer;
  bi::slist<h2stream, requests_member_hook_t, bi::constant_time_size<true>> free_nodes;
  // all done stream ids stored here (before adding or search / 2 to map 1 3 5 to 0 1 2)
  merged_segments closed_streams;
  log_context logctx;
  any_io_context_ref ioctx;
  // for supporting h2server_options::limit_requests_memory_usage_bytes
  size_t used_bytes = 0;
  size_t used_bytes_limit = size_t(-1);
  uint32_t max_continuation_len = uint32_t(-1);
  // число ещё не записанных PING ACK, SETTINGS ACK, RST_STREAM, WINDOW_UPDATE
  // Если пир шлёт кадры, требующие ответа, но не читает ответы, они копятся бесконечно
  uint32_t pending_reply_frames = 0;
  uint32_t max_pending_reply_frames = uint32_t(-1);

  explicit h2connection(any_connection_t&& c, any_io_context_ref);

  h2connection(h2connection&&) = delete;
  void operator=(h2connection&&) = delete;

  ~h2connection();

  // not coroutine, for perf. waits until its possible to write (not sending CONTINUATION)
#define HIDI_WAIT_WRITE(CON)                                 \
  {                                                          \
    while (!co_await (CON).continuation_gateway.wait_open()) \
      [[unlikely]];                                          \
  }

  void mark_stream_closed(stream_id_t id) noexcept {
    closed_streams.add_point(id / 2);
  }

  bool is_closed_stream(stream_id_t id) const noexcept {
    return closed_streams.has_point(id / 2);
  }

  // stream not yet started
  bool is_idle_stream(stream_id_t id) const noexcept {
    return id > laststartedstreamid;
  }

  [[nodiscard]] bool is_dropped() const noexcept {
    return dropped;
  }

  void start_drop() noexcept {
    dropped = true;
  }

  // used when client send request and waits for response
  // OR
  // when server assembles request (in this case 'responses' used as hash table)
  // or server writes response and inserts into responses to catch WINDOW_UPDATe / RST_STREAM
  void insert_response_node(h2stream& node) {
    responses.insert(node);
    if (responses.size() == buckets.size()) [[unlikely]] {
      // https://github.com/boostorg/intrusive/issues/96
      // workaround:
      // unordered set bucket copy(move) ctor does nothing, so .resize will be UB
      decltype(buckets) new_buckets(buckets.size() * 2);
      responses.rehash({new_buckets.data(), new_buckets.size()});
      buckets = std::move(new_buckets);
    }
  }

  // interface for writer only

  struct work_waiter {
    h2connection* connection = nullptr;
    ZAL_PIN;

    bool await_ready() const noexcept {
      return !connection->requests.empty() || connection->is_dropped();
    }
    void await_suspend(std::coroutine_handle<dd::job_promise> writer) noexcept {
      assert(connection->writer.handle == nullptr);
      connection->writer.handle = writer;
    }
    [[nodiscard]] bool await_resume() const noexcept {
      // resumer should set it to nullptr
      assert(connection->writer.handle == nullptr);
      return !connection->is_dropped();
    }
  };

  // postcondition: if returned true, then !requests.empty() && connection not dropped
  // Note: worker may be still has no right to work (too many streams)
  [[nodiscard]] work_waiter wait_work() noexcept {
    return work_waiter(this);
  }

  write_awaiter write(std::span<const byte_t> bytes, io_error_code& ec) {
    return write_awaiter{tcpcon, ec, bytes};
  }
  read_awaiter read(std::span<byte_t> buf, io_error_code& ec) {
    return read_awaiter{tcpcon, ec, buf};
  }

  // client side
  [[nodiscard]] size_t concurrent_streams_now() noexcept {
    return responses.size();
  }

  // interface for reader

  [[nodiscard]] bool is_out_of_streamids() const noexcept {
    return laststartedstreamid >= MAX_STREAM_ID;
  }

  void initiate_graceful_shutdown(stream_id_t laststreamid) noexcept;

  // новые стримы на соединении больше не открываются, уже начатые (в том числе ещё не отправленные
  // писателем) завершаются как обычно
  void forbid_new_streams() noexcept {
    laststartedstreamid = MAX_STREAM_ID;
  }

  // when streamid is max, connection is not broken, but required to stop
  [[nodiscard]] bool is_done_completely() const noexcept {
    return is_out_of_streamids() && requests.empty() && responses.empty();
  }

  void forget(h2stream& node) noexcept;

  // ALL streams must be finished by calling this function except when user
  // exception throwed from on_header/on_data_part callbacks
  // `send_rst` == false запрещает RST_STREAM при отмене / таймауте
  void finish_request(h2stream& node, int status, bool send_rst = true) noexcept;

  // client side
  // used only when user exception throwed from on_header/on_data_part callbacks
  // or if channel for streaming node throws
  // precondition: e != nullptr
  void finish_request_with_user_exception(h2stream& node, std::exception_ptr e) noexcept;

  // client side
  // вызывается когда корутина запроса уничтожается до завершения стрима (отмена через .destroy())
  // precondition: !node.finished()
  void cancel_request(h2stream& node) noexcept;

  // client side
  // returns false if no such stream
  [[nodiscard]] bool rststream_client(rst_stream rstframe);

  // client side
  void finish_request_by_timeout(h2stream& node) noexcept {
    // запрос ещё в очереди писателя, HEADERS не отправлены и для сервера стрим idle. RST_STREAM на idle стрим
    // - ошибка всего соединения https://www.rfc-editor.org/rfc/rfc9113.html#section-6.4-7
    bool sent = !node.requests_hook.is_linked();
    finish_request(node, reqerr_e::TIMEOUT, sent);
  }

  void finish_all_with_reason(reqerr_e::values_e reason);

  [[nodiscard]] h2stream* find_response_by_streamid(stream_id_t id) noexcept;

  void drop_timeouted();

  // used when window update received from remote endpoint
  void window_update(window_update_frame frame);

  // cancels all requests and responses etc, but not shutdowns tcp connection
  // returns true if first shutdown
  bool prepare_to_shutdown(reqerr_e::values_e reason) noexcept;

  void shutdown(reqerr_e::values_e reason) noexcept;

  // interface for send_request

  // postcondition: returns correct streamid (<= MAX_STREAM_ID)
  [[nodiscard]] stream_id_t next_streamid() noexcept {
    if (laststartedstreamid == 0) [[unlikely]] {
      laststartedstreamid = 1;
      return laststartedstreamid;
    }
    assert(laststartedstreamid <= MAX_STREAM_ID);
    assert((laststartedstreamid % 2) == 1);
    laststartedstreamid += 2;
    return laststartedstreamid;
  }

  // 0 if there are no streams
  [[nodiscard]] stream_id_t last_initiated_streamid() const noexcept {
    return laststartedstreamid;
  }

  // client side
  // after creation 3 hooks (requests, responses, timers) and 'task' left unused
  stream_ptr new_stream_node(http_request&& request, deadline_t deadline, on_header_fn_ptr on_header,
                             on_data_part_fn_ptr on_data_part, stream_id_t streamid);

  // client side
  stream_ptr new_streaming_stream_node(http_request&& request, deadline_t deadline,
                                       on_header_fn_ptr on_header, on_data_part_fn_ptr on_data_part,
                                       stream_id_t streamid, stream_body_maker_t makebody);

  void return_node(h2stream* ptr) noexcept;

  void ignore_frame(h2frame frame);

  // `remote_is_client` should be true on server side
  void settings_changed(h2frame newsettings, bool remote_is_client);

  // client side
  // used when settings changed while connection active
  // may throw protocol error
  // precondition: newsettings is SETTINGS frame
  void server_settings_changed(h2frame newsettings);

  // client side
  // used when client receives GOAWAY frame with NO_ERROR (or may be second
  // goaway from server) forbids creating new requests, sends goaway answer
  void server_requests_graceful_shutdown(goaway_frame);

  struct response_awaiter {
    h2connection* con = nullptr;
    h2stream* n = nullptr;

    static bool await_ready() noexcept {
      return false;
    }

    std::coroutine_handle<> await_suspend(dd::task<int>::handle_type h) noexcept {
      n->task = h;
      if (con->writer.handle)  // if writer waits job now
        return std::exchange(con->writer.handle, nullptr);
      return std::noop_coroutine();
    }

    [[nodiscard]] int await_resume() const noexcept {
      return n->status;
    }
  };

  // client side
  // Waits until response received (or h2stream finished somehow else)
  // and returns response status
  KELCORO_CO_AWAIT_REQUIRED response_awaiter response_received(h2stream& node) noexcept;

  void validate_priority_frame_header(const h2frame& h) {
    assert(h.header.type == frame_e::PRIORITY);
    assert(h.data.size() == h.header.length);
    if (h.header.length != 5 || h.header.streamid == 0)
      throw protocol_error(errc_e::PROTOCOL_ERROR, "invalid priority frame");
    uint32_t dependency;
    memcpy(&dependency, h.data.data(), sizeof(dependency));
    htonli(dependency);
    dependency &= uint32_t(0x7FFFFFFF);
    if (dependency == h.header.streamid) {
      throw protocol_error(errc_e::PROTOCOL_ERROR,
                           std::format("PRIORITY frame depends on itself", h.header.streamid));
    }
  }

  void validate_rst_frame(const rst_stream& r) {
    if (is_idle_stream(r.header.streamid)) {
      throw protocol_error(errc_e::PROTOCOL_ERROR,
                           std::format("RST_STREAM frame on a idle stream {}", r.header.streamid));
    }
  }

  // вызывается reader после обработки каждого кадра
  void validate_pending_reply_frames() const {
    if (pending_reply_frames > max_pending_reply_frames) [[unlikely]] {
      throw protocol_error(
          errc_e::ENHANCE_YOUR_CALM,
          std::format("peer does not read replies, frames waiting to be written: {}", pending_reply_frames));
    }
  }

  // работает для всех фреймов, но проверяет только максимальное ограничение размера
  void validate_frame_max_size(const frame_header& h) {
    using enum frame_e;
    assert(local_settings.max_frame_size >= MIN_MAX_FRAME_LEN);
    if (h.length > local_settings.max_frame_size) {
      throw protocol_error(errc_e::FRAME_SIZE_ERROR,
                           std::format("{} frame too big, max size: {}, frame size: {}", e2str(h.type),
                                       local_settings.max_frame_size, h.length));
    }
  }

  // used when SETTINGS_INITIAL_WINDOW_SIZE changed
  void adjust_window_for_all_streams(cfint_t old_window_size, cfint_t new_window_size);

  inline void start_headers_block(h2stream& node, bool force_disable_hpack, bytes_t& hdrs) {
    // https://www.rfc-editor.org/rfc/rfc9113.html#name-settings-synchronization
    if (encodertablesizechangerequested) [[unlikely]] {
      encodertablesizechangerequested = false;
      encoder.dyntab.set_user_protocol_max_size(remote_settings.header_table_size);
      // encoding dyntab size update also updates size
      if (force_disable_hpack) {
        encoder.encode_dynamic_table_size_update(0, std::back_inserter(hdrs));
      } else {
        // not sure if encoder required to send it, but its not error, so just set max size for new settings
        encoder.encode_dynamic_table_size_update(encoder.dyntab.user_protocol_max_size(),
                                                 std::back_inserter(hdrs));
      }
    } else if (node.streamid == 1 && force_disable_hpack) [[unlikely]] {
      encoder.encode_dynamic_table_size_update(0, std::back_inserter(hdrs));
    }
  }

  // collects HEADERS from many CONTINUATIONS and first HEADERS frame without END_HEADERS and passes it into
  // `when_done` invokes `oneachframe` when receives new frame header
  dd::task<void> receive_headers_with_continuation(h2frame frame, io_error_code& ec,
                                                   move_only_fn<void()> oneachframe,
                                                   move_only_fn<void(h2frame)> whendone);

  void client_receive_headers(h2frame frame);

  void client_receive_data(h2frame frame);
};

inline bool h2stream::use_bytes(size_t n) noexcept {
  // its safe to overflow, because its size_t
  if (connection->used_bytes + n > connection->used_bytes_limit) [[unlikely]]
    return false;
  connection->used_bytes += n;
  used_bytes += n;
  return true;
}

#ifdef HTTP2_ENABLE_TRACE
void trace_request_headers(h2stream const&, bool fromclient, const log_context& logctx);
#endif

}  // namespace hidi
