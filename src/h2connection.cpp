

#include "hidi/h2connection.hpp"

#include "hidi/h2send_frames.hpp"
#include "hidi/logger.hpp"

#include <unordered_set>
#include <zal/zal.hpp>

#ifdef HTTP2_ENABLE_TRACE

namespace hidi {

void trace_request_headers(const h2stream& node, bool fromclient, const log_context& logctx) {
  auto& req = node.req;
  std::string s;
  if (fromclient) {
    s += std::format(":path: {}\n:authority: {}\n:method: {}\n:scheme: {}\n", req.path,
                     req.authority.empty() ? "<unset>" : req.authority, e2str(req.method), e2str(req.scheme));
  } else {
    s += std::format(":status: {}\n", node.status);
  }
  if (!req.body.content_type.empty())
    s += std::format("content-type: {}\n", req.body.content_type);
  for (auto& h : req.headers)
    s += std::format("name: {}, value: {}\n", h.name(), h.value());
  HTTP2_LOG_TRACE(logctx, "{}", s);
}

}  // namespace hidi

#endif

namespace hidi {

void intrusive_ptr_add_ref(h2connection* p) noexcept {
  ++p->refcount;
}

void intrusive_ptr_release(h2connection* p) noexcept {
  --p->refcount;
  if (p->refcount == 0)
    delete p;
}

void intrusive_ptr_add_ref(h2stream* p) noexcept {
  ++p->refcount;
}

void intrusive_ptr_release(h2stream* p) noexcept {
  --p->refcount;
  if (p->refcount == 0) {
    p->connection->used_bytes -= p->used_bytes;
    p->connection->return_node(p);
  }
}

// декодирует блок до конца, даже если `visitor` бросил исключение: иначе таблица HPACK декодера разойдётся
// с таблицей собеседника на всё соединение
template <typename V>
void decode_headers_block_safe(hpack::decoder& dec, std::span<const byte_t> bytes, V&& visitor) {
  const byte_t* in = bytes.data();
  const byte_t* e = in + bytes.size();
  hpack::header_view header;
  while (in != e) {
    dec.decode_header(in, e, header);
    if (!header)  // dynamic table size update
      continue;
    try {
      visitor(header.name.str(), header.value.str());
    } catch (...) {
      hpack::ignore_headers_block(dec, in, e);  // если остаток битый, его ошибка заменит исключение колбека
      throw;
    }
  }
}

static void validate_trailer_header(std::string_view name, std::string_view value, stream_id_t streamid) {
  // https://www.rfc-editor.org/rfc/rfc7540#section-8.1.2.1
  // ( Pseudo-header fields MUST NOT appear in trailers )
  if (name.starts_with(':')) {
    throw protocol_error(
        errc_e::PROTOCOL_ERROR,
        std::format("trailers section must not include pseudo-headers, name: {}, streamid: {}", name,
                    streamid));
  }
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1 некорректные трейлеры - ошибка стрима
  if (std::optional<std::string> err = validate_header_name(name, value))
    throw stream_error(errc_e::PROTOCOL_ERROR, streamid, std::move(*err));
}

// :status уже разобран
static void validate_response_header(std::string_view name, std::string_view value, stream_id_t streamid) {
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.2 в ответе только один псевдозаголовок :status
  if (name.starts_with(':')) {
    throw stream_error(errc_e::PROTOCOL_ERROR, streamid,
                       std::format("unexpected pseudoheader in response, name: {}", name));
  }
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1 некорректный ответ - ошибка стрима
  if (std::optional<std::string> err = validate_header_name(name, value))
    throw stream_error(errc_e::PROTOCOL_ERROR, streamid, std::move(*err));
}

void h2stream::receive_trailers_headers(hpack::decoder& decoder, h2frame frame) {
  // may handle both request trailers and response trailers
  HTTP2_LOG_TRACE(logctx(), "received HEADERS (trailers): stream: {}, len: {}", frame.header.streamid,
                  frame.header.length);
  constexpr auto mask = flags::END_STREAM | flags::END_HEADERS;
  if (((frame.header.flags & mask) != mask))
    throw protocol_error(errc_e::STREAM_CLOSED, "trailers header without END_STREAM | END_HEADERS");
  // до колбеков: memory_queue по нему отличает END_STREAM от обрыва
  end_stream_received = true;
  decode_headers_block_safe(decoder, frame.data, [&](std::string_view name, std::string_view value) {
    HTTP2_LOG_TRACE(this->logctx(), "name: {}, value: {}", name, value);
    validate_trailer_header(name, value, frame.header.streamid);
    if (on_header_fn)
      (*on_header_fn)(name, value);
  });

  if (on_data_part_fn) {
    // pass empty DATA chunk, so user will know, that data is ended
    // its required, because when trailers present there are no
    // DATA frame with END_STREAM flag
    (*on_data_part_fn)({}, /*last chunk*/ true);
  }
}

void h2stream::receive_request_trailers(hpack::decoder& decoder, h2frame hdrs) {
  assert(hdrs.header.type == frame_e::HEADERS);
  auto old_on_header = on_header_fn;
  on_scope_exit {
    on_header_fn = old_on_header;
  };
  bool memory_limit_exceeded = false;
  auto onheader = [&](std::string_view name, std::string_view value) {
    // запрос bistream (answer_before_data) уже отдан пользователю, трейлеры клиента игнорируются
    if (answered_before_data)
      return;
    if (memory_limit_exceeded || !use_bytes(name.size() + value.size())) [[unlikely]] {
      // not throw, maintain dynamic table anyway
      memory_limit_exceeded = true;
      return;
    }
    req.headers.push_back(http_header_t(std::string(name), std::string(value)));
  };
  // server does not set 'on_header' / 'on_data_part' callbacks, but reuses this function for trailers
  on_header_fn = &onheader;
  receive_trailers_headers(decoder, hdrs);
  if (memory_limit_exceeded) {
    HTTP2_LOG(connection->logctx, WARN, "memory limit exceeded when parsing trailers for stream {}",
              streamid);
    throw stream_error(errc_e::ENHANCE_YOUR_CALM, streamid, "memory limit exceeded when parsing trailers");
  }
}

void h2stream::receive_response_headers(hpack::decoder& decoder, h2frame frame) {
  assert(frame.header.streamid == streamid);
  assert(frame.header.type == frame_e::HEADERS);
  HTTP2_LOG_TRACE(logctx(), "received HEADERS: stream: {}, len: {}", frame.header.streamid,
                  frame.header.length);
  // Note: this code decodes headers block or fails with protocol_error (ends connection)
  // thats why we dont care about `decode_headers_block` in fail branckes

  assert(frame.header.flags & flags::END_HEADERS);

  // 199 - last informational status. Informational responses are interim and cannot have trailer section
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1-4
  // Note: ignores END_STREAM flag for interim responses, not marks it as error
  if (status > 199) [[unlikely]]
    return receive_trailers_headers(decoder, frame);
  on_scope_exit {
    end_stream_received = frame.header.flags & flags::END_STREAM;
  };
  const byte_t* in = frame.data.data();
  const byte_t* e = in + frame.data.size();
  status = decoder.decode_response_status(in, e);
  // headers must be decoded to maintain HPACK dynamic table in correct state
  decode_headers_block_safe(decoder, std::span(in, e), [&](std::string_view name, std::string_view value) {
    HTTP2_LOG_TRACE(this->logctx(), "name: {}, value: {}", name, value);
    validate_response_header(name, value, streamid);
    if (on_header_fn)
      (*on_header_fn)(name, value);
  });
}

void h2stream::receive_response_data(h2frame frame) {
  assert(frame.header.streamid == streamid);
  assert(frame.header.type == frame_e::DATA);
  // до колбека: memory_queue по нему отличает END_STREAM от обрыва
  end_stream_received = frame.header.flags & flags::END_STREAM;
  count_received_data(frame);

  if (on_data_part_fn)
    (*on_data_part_fn)(frame.data, (frame.header.flags & flags::END_STREAM));

  HTTP2_LOG_TRACE(logctx(), "received DATA: stream: {}, len: {}, DATA: {}", frame.header.streamid,
                  frame.header.length, std::string_view((const char*)frame.data.data(), frame.data.size()));
}

void h2stream::receive_request_headers(h2frame frame) {
  assert(frame.header.streamid == streamid);
  assert(frame.header.type == frame_e::HEADERS);
  assert(frame.header.flags & flags::END_HEADERS);
  assert(req.headers.empty());

  on_scope_exit {
    end_stream_received = frame.header.flags & flags::END_STREAM;
  };

  HTTP2_LOG_TRACE(logctx(), "received HEADERS: stream: {}, len: {}", frame.header.streamid,
                  frame.header.length);

  parse_http2_request_headers(*this, frame.data);
#ifdef HTTP2_ENABLE_TRACE
  if (logctx().should_log(log_level_e::TRACE)) [[unlikely]]
    trace_request_headers(*this, /*from client=*/true, logctx());
#endif
}

void h2stream::receive_request_data(h2frame frame) {
  assert(frame.header.streamid == streamid);
  assert(frame.header.type == frame_e::DATA);

  on_scope_exit {
    end_stream_received = frame.header.flags & flags::END_STREAM;
  };

  HTTP2_LOG_TRACE(logctx(), "received DATA: stream: {}, len: {}, DATA: {}", streamid, frame.header.length,
                  std::string_view((const char*)frame.data.data(), frame.data.size()));

  count_received_data(frame);

  if (is_half_closed())
    throw stream_error(errc_e::STREAM_CLOSED, streamid, "stream already assembled");

  if (!is_input_streaming()) {
    if (!use_bytes(frame.data.size())) {
      HTTP2_LOG(connection->logctx, WARN, "memory limit exceeded while receiving DATA for stream {}",
                streamid);
      throw stream_error(errc_e::ENHANCE_YOUR_CALM, streamid, "too many bytes used");
    }
    req.body.data.insert(req.body.data.end(), frame.data.begin(), frame.data.end());
  } else {
    // до колбека: memory_queue по нему отличает END_STREAM от обрыва
    end_stream_received = frame.header.flags & flags::END_STREAM;
    (*on_data_part_fn)(frame.data, frame.header.flags& flags::END_STREAM);
  }
}

void h2stream::count_received_data(const h2frame& frame) {
  // Note: frame.header.length включает паддинг, он тоже учитывается в окне
  decrease_window_size(rl_streamlevel_windowsize, int32_t(frame.header.length), logctx());
  if (rl_streamlevel_windowsize < 0) [[unlikely]] {
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.1
    throw stream_error(errc_e::FLOW_CONTROL_ERROR, streamid,
                       std::format("DATA exceeds stream window by {} bytes", -rl_streamlevel_windowsize));
  }
  if (has_memory_queue() || (frame.header.flags & flags::END_STREAM))
    return;
  cfint_t window = connection->local_settings.initial_stream_window_size;
  if (rl_streamlevel_windowsize < window / 2)
    update_window_to_max(stream_ptr(this), connection, window).start_and_detach();
}

const log_context& h2stream::logctx() const noexcept {
  return connection ? connection->logctx : empty_log_context;
}

// h2connection methods

h2connection::h2connection(any_connection_t&& c, any_io_context_ref ctx)
    : tcpcon(std::move(c)),
      buckets(initial_buckets_count),
      responses({buckets.data(), buckets.size()}),
      pingtimer(ctx.create_timer()),
      pingdeadlinetimer(ctx.create_timer()),
      timeout_warden_timer(ctx.create_timer()),
      ioctx(ctx) {
  assert(pingtimer.has_value());
  assert(pingdeadlinetimer.has_value());
  assert(timeout_warden_timer.has_value());
}

h2connection::~h2connection() {
  assert(used_bytes == 0);  // all requests should be closed and memory unused
  free_nodes.clear_and_dispose([](h2stream* node) { delete node; });
}

void h2connection::settings_changed(h2frame newsettings, bool remote_is_client) {
  if (newsettings.header.flags & flags::ACK) {
    validate_settings_ack_frame(newsettings.header);
    // только после подтверждения настроек я действительно могу перейти на свои настройки
    // ведь до этого клиент/сервер мог посылать запросы/ответы по старому размеру динамической таблицы
    decoder.dyntab.set_user_protocol_max_size(local_settings.header_table_size);
    // RFC 7541 неоднозначен в том, обязан ли кодировщик пира сообщать об увеличении таблицы. nghttp2 считает,
    // что не обязан, и сразу увеличивает таблицу декодера. Если таблица декодера больше таблицы кодировщика,
    // индексы не расходятся, поэтому увеличивать безопасно
    if (local_settings.header_table_size > decoder.dyntab.max_size())
      decoder.dyntab.update_size(local_settings.header_table_size);
    return;
  }
  settings_t before = remote_settings;
  if (remote_is_client) {
    settings_frame::parse(newsettings.header, newsettings.data,
                          client_settings_visitor{remote_settings,
                                                  /*firstframe=*/!first_settings_frame_received});
  } else {
    settings_frame::parse(newsettings.header, newsettings.data,
                          server_settings_visitor{remote_settings,
                                                  /*firstframe=*/!first_settings_frame_received});
  }
  first_settings_frame_received = true;
  if (before.header_table_size != remote_settings.header_table_size) {
    HTTP2_LOG(logctx, INFO, "HPACK table resized: new size {}, old size: {}",
              remote_settings.header_table_size, before.header_table_size);
    encoder_table_size_changed();
  }
  // encoder обновится на основании новых настроек когда писатель увидит `encodertablesizerequested`
  adjust_window_for_all_streams(before.initial_stream_window_size,
                                remote_settings.initial_stream_window_size);
  // могли измениться окна стримов и MAX_CONCURRENT_STREAMS
  notify_blocked_writers();
  // then change all active streams window size
  send_settings_ack(this).start_and_detach();
}

void h2connection::server_settings_changed(h2frame newsettings) {
  settings_changed(newsettings, /*remote_is_client=*/false);
}

void h2connection::server_requests_graceful_shutdown(goaway_frame f) {
  HTTP2_LOG_TRACE(logctx, "graceful shutdown initiated: last stream id: {}", f.last_streamid);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8-14
  // Сервер может прислать несколько GOAWAY подряд: сначала с last_stream_id == MAX_STREAM_ID как
  // предупреждение, затем с реальным значением. Каждый обрабатывается, потому что стримы, которые сервер не
  // обработает (id > last_stream_id), нужно завершить сразу, чтобы запрос можно было повторить
  // Также это нужно когда graceful shutdown начал сам клиент (graceful_stop)
  initiate_graceful_shutdown(f.last_streamid);
  graceful_shutdown_goaway_sended = true;
  // do not drop connection, graceful_stop will do it or reader (its out of streams)
}

void h2connection::initiate_graceful_shutdown(stream_id_t laststreamid) noexcept {
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8-3
  // when GOAWAY with NO_ERROR received interpret it as shutdown initiation.
  // Receivers of a GOAWAY frame MUST NOT open additional streams on the
  // connection this state similar to state when connection is out of streams.
  // So, connection will work until all done and create new connection for new
  // streams. we will do all what requested, > last stream id will be ignored, <
  // last stream id will be handled
  forbid_new_streams();
  for (auto b = responses.begin(); b != responses.end();) {
    auto n = std::next(b);
    if (b->streamid > laststreamid)
      finish_request(*b, reqerr_e::SERVER_CANCELLED_REQUEST);
    b = n;
  }
  requests.clear_and_dispose([&](h2stream* r) { finish_request(*r, reqerr_e::SERVER_CANCELLED_REQUEST); });
}

void h2connection::forget(h2stream& node) noexcept {
  if (node.requests_hook.is_linked())
    erase_byref(requests, node);
  if (node.responses_hook.is_linked()) {
    assert(responses.count(node.streamid) == 1);
    erase_byref(responses, node);
  }
  if (node.timers_hook.is_linked())
    erase_byref(timers, node);
  // ждущий писатель этого стрима должен увидеть, что стрим завершён, а клиент - что освободился слот
  notify_blocked_writers();
}

void h2connection::finish_request(h2stream& node, int status, bool send_rst) noexcept {
  forget(node);
  if (!node.task)
    return;

  if (status <= 0) {
    HTTP2_LOG_TRACE(logctx, "stream {} finished, status: {}", node.streamid,
                    e2str(reqerr_e::values_e(status)));
  } else {
    HTTP2_LOG_TRACE(logctx, "stream {} finished, status: {}", node.streamid, status);
  }
  node.status = status;
  stream_ptr p = &node;  // hold node
  auto t = std::exchange(node.task, nullptr);
  if (node.has_memory_queue()) {
    // канал CONNECT читает данные из memory_queue и иначе ждал бы их вечно
    (*node.on_data_part_fn)({}, /*last chunk*/ true);
  }
  if (send_rst && (status == reqerr_e::CANCELLED || status == reqerr_e::TIMEOUT)) {
    // ignore possible bad alloc for coroutine
    send_rst_stream(this, node.streamid, errc_e::CANCEL).start_and_detach();
  }
  t.resume();
}

void h2connection::finish_request_with_user_exception(h2stream& node, std::exception_ptr e) noexcept {
  if (node.task)
    node.task.promise().set_exception(std::move(e));
  finish_request(node, reqerr_e::CANCELLED);
}

void h2connection::cancel_request(h2stream& node) noexcept {
  assert(!node.finished());
  HTTP2_LOG_TRACE(logctx, "stream {} canceled, request coroutine destroyed", node.streamid);
  // HEADERS ещё не отправлены, для сервера стрим idle
  bool sent = !node.requests_hook.is_linked();
  forget(node);
  // корутина уничтожается, её нельзя будить. Писатель увидит finished() и перестанет писать стрим
  node.task = nullptr;
  // колбеки могли жить в уничтоженной корутине
  node.on_header_fn = nullptr;
  if (node.has_memory_queue()) {
    // данные CONNECT читает канал пользователя из memory_queue, будим его, чтобы он не ждал вечно
    (*node.on_data_part_fn)({}, /*last chunk*/ true);
  } else {
    node.on_data_part_fn = nullptr;
  }
  if (sent)
    send_rst_stream(this, node.streamid, errc_e::CANCEL).start_and_detach();
}

bool h2connection::rststream_client(rst_stream rstframe) {
  validate_rst_frame(rstframe);
  auto* node = find_response_by_streamid(rstframe.header.streamid);
  if (!node)
    return false;
  node->canceled_by_rststream = true;
  finish_request(*node, reqerr_e::SERVER_CANCELLED_REQUEST);
  return true;
}

void h2connection::finish_all_with_reason(reqerr_e::values_e reason) {
  assert(is_dropped());  // must be called only while drop_connection()

  // assume only i have access to it
  auto reqs = std::move(requests);
  auto rsps = std::move(responses);
  // >= because request may not be inserted in 'timers' if deadline == never
  assert(reqs.size() + rsps.size() >= timers.size());
  // nodes in reqs or in rsps, timers do not own them
  timers.clear();
  if (!reqs.empty() || !rsps.empty()) {
    HTTP2_LOG_TRACE(logctx, "finish {} requests and {} responses, reason code: {}", reqs.size(), rsps.size(),
                    e2str(reason));
  }
  auto forget_and_resume = [&](h2stream* node) { finish_request(*node, reason); };
  reqs.clear_and_dispose(forget_and_resume);
  rsps.clear_and_dispose(forget_and_resume);
}

[[nodiscard]] h2stream* h2connection::find_response_by_streamid(stream_id_t id) noexcept {
  auto it = responses.find(id);
  return it != responses.end() ? &*it : nullptr;
}

void h2connection::drop_timeouted() {
  // prevent destruction of *this while resuming
  h2connection_ptr lock = this;
  while (!timers.empty() && timers.top()->deadline.is_reached()) {
    // node deleted from timers by forgetting
    finish_request_by_timeout(*timers.top());
  }
}

void h2connection::window_update(window_update_frame frame) {
  HTTP2_LOG_TRACE(logctx, "received window update, stream: {}, inc: {}", frame.header.streamid,
                  frame.window_size_increment);
  if (frame.header.streamid == 0) {
    increment_window_size(receiver_window_size, int32_t(frame.window_size_increment), 0);
    notify_blocked_writers();
    return;
  }
  h2stream* node = find_response_by_streamid(frame.header.streamid);
  if (!node) {
    HTTP2_LOG(logctx, WARN, "received window update for stream which not exist, streamid: {}",
              frame.header.streamid);
    if (is_idle_stream(frame.header.streamid)) {
      throw protocol_error(errc_e::PROTOCOL_ERROR,
                           std::format("WINDOW_UPDATE for idle frame, streamid: {}", frame.header.streamid));
    }
    return;
  }
  increment_window_size(node->lr_streamlevel_windowsize, int32_t(frame.window_size_increment),
                        frame.header.streamid);
  notify_blocked_writers();
}

bool h2connection::prepare_to_shutdown(reqerr_e::values_e reason) noexcept {
  if (is_dropped())
    return false;

  HTTP2_LOG_TRACE(logctx, "shutdown");

  // set flag for anyone who will be resumed while shutting down this connection
  start_drop();
  notify_blocked_writers();

  // prevents me to be destroyed while resuming writer/reader etc
  h2connection_ptr lock = this;

  pingtimer.cancel();
  pingtimer.set_callback({});  // delete prev callback and shared ptr to connection in it
  pingdeadlinetimer.cancel();
  pingdeadlinetimer.set_callback({});
  timeout_warden_timer.cancel();
  timeout_warden_timer.set_callback({});

  // firstly stop handling new data on connection
  if (writer.handle) {
    writer.handle.destroy();
    writer.handle = nullptr;
  } else {
    // writer not waits for work, but suspended (because we are in single thread
    // and working now)
    // == its in write/sleep
    // then writer must be canceled by socket.cancel() or shutdown
  }
  finish_all_with_reason(reason);
  return true;
}

static dd::job do_shutdown_connection(h2connection_ptr con) {
  assert(con);
  // держит шаред, автономно не трогая ничего другого, возможно в "бекграунде" останавливается
  co_await con->tcpcon->shutdown();
}

void h2connection::shutdown(reqerr_e::values_e reason) noexcept {
  if (!prepare_to_shutdown(reason))
    return;
  // возможный bad_alloc игнорируется
  (void)do_shutdown_connection(this);
}

stream_ptr h2connection::new_stream_node(http_request&& request, deadline_t deadline,
                                         on_header_fn_ptr on_header, on_data_part_fn_ptr on_data_part,
                                         stream_id_t id) {
  stream_ptr node;
  if (free_nodes.empty()) {
    node = new h2stream;
  } else {
    node = &free_nodes.front();
    free_nodes.pop_front();
  }
  node->lr_streamlevel_windowsize = remote_settings.initial_stream_window_size;
  node->rl_streamlevel_windowsize = local_settings.initial_stream_window_size;
  node->req = std::move(request);
  node->streamid = id;
  node->deadline = deadline;
  node->task = nullptr;
  node->connection = this;
  node->on_header_fn = on_header;
  node->on_data_part_fn = on_data_part;
  node->status = reqerr_e::UNKNOWN_ERR;
  node->canceled_by_rststream = false;
  node->responded = false;
  node->answered_before_data = false;
  node->end_stream_received = false;
  node->used_bytes = 0;

  assert(node->refcount == 1);
  assert(!node->requests_hook.is_linked());
  assert(!node->responses_hook.is_linked());
  assert(!node->timers_hook.is_linked());
  assert(!node->is_output_streaming());
  return node;
}

stream_ptr h2connection::new_streaming_stream_node(http_request&& request, deadline_t deadline,
                                                   on_header_fn_ptr on_header,
                                                   on_data_part_fn_ptr on_data_part, stream_id_t streamid,
                                                   stream_body_maker_t makebody) {
  stream_ptr node = new_stream_node(std::move(request), deadline, on_header, on_data_part, streamid);
  node->makebody = std::move(makebody);
  return node;
}

void h2connection::return_node(h2stream* ptr) noexcept {
  assert(ptr && ptr->connection);
  forget(*ptr);
  ptr->req = {};
  ptr->makebody.reset();
  // using always server settings, client creates requests, server controls
  if (free_nodes.size() >= server_settings->max_concurrent_streams) {
    delete ptr;
    return;
  }
  free_nodes.push_front(*ptr);
  // it may be last pointer to *this
  ptr->connection = nullptr;
}

h2connection::response_awaiter h2connection::response_received(h2stream& node) noexcept {
  assert(!node.timers_hook.is_linked());
  assert(!node.requests_hook.is_linked());
  assert(!node.responses_hook.is_linked());
  requests.push_back(node);
  // highly likely, that new value will be at end,
  // because new deadline will be greater then previous
  if (node.deadline != deadline_t::never()) {
    bool reschedule = timers.empty() || node.deadline < timers.top()->deadline;
    timers.insert(timers.end(), node);
    if (reschedule)
      timeout_warden_timer.arm(timers.top()->deadline.tp);
  }
  return response_awaiter{this, &node};
}

void h2connection::ignore_frame(h2frame frame) {
  HTTP2_LOG_TRACE(logctx, "ignoring frame, type: {}, stream: {}. len: {}", e2str(frame.header.type),
                  frame.header.streamid, frame.header.length);
  using enum frame_e;
  // here we assume, that there are no node with frame stream id (thats why it is ignored)

  // Note: sending frame for closed stream is only stream error, not protocol
  // because its possible that stream was canceled due timeout and then frame received
  switch (frame.header.type) {
    case HEADERS: {
      // до сдвига laststartedstreamid
      bool closed = is_closed_stream(frame.header.streamid);
      // even if we ignoring frame, stream is done
      laststartedstreamid = std::max(laststartedstreamid, frame.header.streamid);
      // decode before all to ensure decoder will be in correct state
      // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8-19
      hpack::ignore_headers_block(decoder, frame.data);

      if (closed) {
        throw stream_error(errc_e::STREAM_CLOSED, frame.header.streamid,
                           "HEADERS frame sent for closed stream");
      }
      return;
    }
    case DATA:
      // NOTE: not using data.size(), since padding should be counted as received
      // octets
      // ('data' does not contain padding)
      decrease_window_size(my_window_size, int32_t(frame.header.length), logctx);
      if (is_closed_stream(frame.header.streamid))
        throw stream_error(errc_e::STREAM_CLOSED, frame.header.streamid, "DATA frame sent for closed stream");
      if (is_idle_stream(frame.header.streamid)) {
        throw protocol_error(
            errc_e::PROTOCOL_ERROR,
            std::format("DATA frame sent for idle stream, streamid {}", frame.header.streamid));
      }
      return;
    default:
      return;
  }
}

void h2connection::adjust_window_for_all_streams(cfint_t old_window_size, cfint_t new_window_size) {
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.2-3
  //  When the value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST adjust the size of all stream
  //  flow-control windows that it maintains by the difference between the new value and the old value.
  if (old_window_size == new_window_size)
    return;
  // make sure every stream handled once
  std::unordered_set<h2stream*> handled;
  cfint_t increment = new_window_size - old_window_size;
  if (std::abs(increment) > std::numeric_limits<int32_t>::max()) {
    throw protocol_error(
        errc_e::FLOW_CONTROL_ERROR,
        std::format("SETTINGS_INITIAL_WINDOW_SIZE leads to control flow overflow, old: {}, new: {}",
                    old_window_size, new_window_size));
  }

  auto adjust_stream = [&](h2stream& x) {
    if (handled.contains(&x))
      return;
    try {
      increment_window_size(x.lr_streamlevel_windowsize, increment, x.streamid);
    } catch (const stream_error& e) {
      // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.2-7
      // "An endpoint MUST treat a change to SETTINGS_INITIAL_WINDOW_SIZE that causes any flow-control window
      // to exceed the maximum size as a connection error (Section 5.4.1) of type FLOW_CONTROL_ERROR"
      throw protocol_error(errc_e::FLOW_CONTROL_ERROR, e.what());
    }
    handled.insert(&x);
  };

  for (h2stream& x : requests)
    adjust_stream(x);
  for (h2stream& x : responses)
    adjust_stream(x);
}

dd::task<void> h2connection::receive_headers_with_continuation(h2frame frame, io_error_code& ec,
                                                               move_only_fn<void()> oneachframe,
                                                               move_only_fn<void(h2frame)> whendone) {
  assert(frame.header.type == frame_e::HEADERS);
  assert(!(frame.header.flags & flags::END_HEADERS));
  assert(oneachframe && whendone);

  frame.validate_streamid();
  frame.remove_padding();
  frame.ignore_deprecated_priority();

  frame_header startheader = frame.header;
  bytes_t bytes(frame.data.begin(), frame.data.end());

  on_scope_failure(decode_anyway) {
    try {
      hpack::ignore_headers_block(decoder, bytes);
    } catch (std::exception& e) {
      // may be part of data only received, error expectable
      HTTP2_LOG(logctx, WARN, "error while decoding CONTINUATIONS: {}", e.what());
    }
  };
  byte_t hdr[FRAME_HEADER_LEN];
  for (;;) {
    frame.data = hdr;

    co_await read(hdr, ec);

    if (ec || is_dropped())
      co_return;

    // parse frame header

    frame.header = frame_header::parse(hdr);
    frame.validate_header();
    validate_frame_max_size(frame.header);
    oneachframe();

    if (frame.header.type != frame_e::CONTINUATION || frame.header.streamid != startheader.streamid) {
      throw protocol_error(errc_e::PROTOCOL_ERROR,
                           std::format("expected CONTINUATION for stream {}, got {}", startheader.streamid,
                                       e2str(frame.header.type)));
    }
    if (frame.header.length + bytes.size() > max_continuation_len) {
      // protocol_error (GOAWAY), так как тело ещё не прочитано и читать мы его не хотим
      // если соединение не отбросить данные будут недочитаны и чтение следующего заголовка сломается
      throw protocol_error(errc_e::ENHANCE_YOUR_CALM,
                           std::format("CONTINUATION too big, limit: {} bytes", max_continuation_len));
    }
    // read frame data
    bytes.resize(bytes.size() + frame.header.length);
    co_await read(suffix(std::span(bytes), frame.header.length), ec);
    if (ec || is_dropped())
      co_return;
    if (frame.header.flags & flags::END_HEADERS) {
      // будто пришёл просто огромный HEADERS
      static_assert(std::numeric_limits<uint32_t>::max() > MAX_CONTINUATION_LEN);
      frame.data = bytes;
      frame.header = startheader;
      frame.header.flags |= flags::END_HEADERS;
      frame.header.length = bytes.size();
      decode_anyway.no_longer_needed();
      whendone(frame);
      co_return;
    }
  }
  unreachable();
}

void h2connection::client_receive_headers(h2frame frame) {
  assert(frame.header.type == frame_e::HEADERS);
  frame.validate_streamid();
  frame.remove_padding();
  frame.ignore_deprecated_priority();

  stream_ptr node = find_response_by_streamid(frame.header.streamid);
  if (!node) {
    ignore_frame(frame);
    return;
  }

  try {
    // sets end_stream_received flag
    node->receive_response_headers(decoder, frame);
  } catch (hpack::protocol_error&) {
    throw;
  } catch (protocol_error&) {
    throw;
  } catch (...) {
    // user-handling exception, do not drop connection
    finish_request_with_user_exception(*node, std::current_exception());
    return;
  }
  // ignore interim responses
  if (node->is_connect_request() && !node->end_stream_received && !(node->status > 99 && node->status < 200))
      [[unlikely]] {
    assert(node->task);
    std::exchange(node->task, nullptr).resume();
    return;
  }
  if (node->end_stream_received)
    finish_request(*node, node->status);
}

void h2connection::client_receive_data(h2frame frame) {
  assert(frame.header.type == frame_e::DATA);

  frame.validate_streamid();
  frame.remove_padding();
  stream_ptr node = find_response_by_streamid(frame.header.streamid);
  if (!node) {
    ignore_frame(frame);
    return;
  }
  // applicable only to data
  // Note: includes padding!
  decrease_window_size(my_window_size, frame.header.length, logctx);
  try {
    node->receive_response_data(frame);
  } catch (hpack::protocol_error&) {
    throw;
  } catch (protocol_error&) {
    throw;
  } catch (...) {
    // user-handling exception, do not drop connection
    finish_request_with_user_exception(*node, std::current_exception());
    return;
  }
  if (node->end_stream_received)  // setted in `receive_response_data`
    finish_request(*node, node->status);
}

}  // namespace hidi
