

#include "hidi/h2server_session.hpp"

#include "hidi/h2connection.hpp"
#include "hidi/h2protocol.hpp"
#include "hidi/h2send_frames.hpp"
#include "hidi/logger.hpp"
#include "hidi/asio/asio_executor.hpp"
#include "hidi/h2server.hpp"

#include <algorithm>
#include <utility>

#include <zal/zal.hpp>

/*

Путь каждого запроса внутри сессии сервера:

1. server_reader читает HEADERS фрейм от клиента
2. server_reader вызывает `start_request_assemble`, который создаёт стрим ноду и:
    * добавляет её в connection.responses (в сервере responses используются также для сборки запроса)
    * выставляет статус reqerr_e::REQUEST_CREATED чтобы обозначить, что запрос ещё не собран
    ** после выхода из `start_request_assemble` стрим остаётся без владельца
3. server_reader продолжает получать фреймы от клиента, собирая их в один внутри responses
и вызывает `on_request_ready`, когда приходит фрейм с флагом END_STREAM (это может быть самый первый фрейм
HEADERS)
4. on_request_ready
    * стартует корутину send_response перехватывает владение стримом
    * выставляет статус RESPONSE_IN_PROGRESS
    * вызывает пользовательский калбек для получения Response
  Важно: если стрим отменён на этом этапе, то send_response будет продолжать ждать Response от пользователя и
только потом удалится вместе с стримом .task в стриме ещё nullptr, чтобы не разбудить send_response во время
ожидания Response
5. После получения Response корутина send_response выставляет стрим.status и стрим.request, засыпает на
`response_written`, предварительно выставляя в стрим.task свой хендл и перенося стрим из connection.responses
в connection.requests (очередь на отправку для писателя)
6. Писатель забирает из очереди стрим с готовым для отправки Response и пишет его, после завершения вызывает
connection.finish_request

На любом из этапов стрим может быть отменён, например через получение фрейма RST_STREAM или
.request_terminate. Во время и для завершения учитываются stream.task, и владельцы (если стрим сейчас без
владельца, он уничтожается на месте) Удаление из контейнеров requests/responses (forget) предотвращает любое
получение фреймов для этого стрима в server_reader

  Важно: стрим всегда должен быть хотя бы в одном из контейнеров responses/requests, чтобы пришедшие фреймы
RST_STREAM и прочие могли на него повлиять


*/
namespace hidi {

// friend of Response
struct response_bro {
  static http_request torequest(http_response&& rsp) noexcept {
    http_request req;
    req.body.data = std::move(rsp.body);
    req.headers = std::move(rsp.headers);
    // must not contain ":status" or other pseudoheaders
    assert(std::find_if(req.headers.begin(), req.headers.end(),
                        [](http_header_t& h) { return h.name().starts_with(':'); }) == req.headers.end());
    return req;
  }
};

h2server_session::h2server_session(h2connection_ptr con, h2server_options opts, h2server& s)
    : connection(std::move(con)), options(opts), server(&s) {
  assert(connection);
  connection->used_bytes_limit = options.limit_requests_memory_usage_bytes;
  options.max_receive_frame_size = std::min(FRAME_LEN_MAX, options.max_receive_frame_size);
  options.max_continuation_len_bytes = std::min(options.max_continuation_len_bytes, MAX_CONTINUATION_LEN);
  connection->max_continuation_len = options.max_continuation_len_bytes;
  connection->max_pending_reply_frames = options.max_pending_reply_frames;
}

h2server_session::~h2server_session() {
  assert(connection->is_dropped() && connection->requests.empty() && connection->responses.empty() &&
         "server session was not closed before destroy");
  HTTP2_LOG_TRACE(logctx(), "session ended");
}

static dd::task<int> send_response(stream_ptr node, h2server_session& session) {
  assert(node);
  assert(node->status == reqerr_e::RESPONSE_IN_PROGRESS);
  HTTP2_LOG_TRACE(session.logctx(), "sending response for stream {}", node->streamid);
  on_scope_exit {
    HTTP2_LOG_TRACE(session.logctx(), "sent response for stream {}", node->streamid);
    session.on_response_done();
  };
  if (session.responsegate.is_closed() || session.connection->is_dropped() ||
      !node->responses_hook.is_linked()) {
    // already canceled
    co_return 0;
  }
  auto guard = session.responsegate.hold();

  // Note: здесь неявное предположение о том, что пользовательский калбек
  // не будет ждать .stop сервера (нарушение ведёт к вечному ожиданию)
  // и вернёт хоть когда-нибудь response (нарушение ведёт к зависанию стрима)
  http_response rsp;
  HTTP2_ASSUME_THREAD_UNCHANGED_START;
  try {
    if (!node->answered_before_data) {
      rsp = co_await session.server->handle_request(std::move(node->req), request_context(*node));
    } else {
      auto [brsp, maker] = co_await session.server->handle_request_stream(
          std::move(node->req), new memory_queue(*node), request_context(*node));
      assert(brsp.body.empty());            // function contract violated
      assert(!node->makebody.has_value());  // ctx.stream_response must not be used here
      rsp = std::move(brsp);
      node->makebody = [n = &*node, makeout = std::move(maker)](http_headers_t&, request_context) mutable {
        return makeout(request_context(*n));
      };
    }
  } catch (critical_stream_error& e) {
    HTTP2_LOG(session.logctx(), ERROR, "handle request failed: {}", e.what());
    HTTP2_ASSUME_THREAD_UNCHANGED_END;
    assert(e.streamid == node->streamid);
    session.request_shutdown();
    session.connection->shutdown(reqerr_e::SERVER_CANCELLED_REQUEST);
    co_return 0;
  } catch (stream_error& e) {
    // Note: catching stream error, so user can implement other protocol over HTTP/2 with additional
    // requirements
    HTTP2_LOG(session.logctx(), ERROR, "handle request failed: {}", e.what());
    HTTP2_ASSUME_THREAD_UNCHANGED_END;
    assert(e.streamid == node->streamid);
    send_rst_stream(session.connection, node->streamid, e.errc).start_and_detach();
    co_return 0;
  } catch (std::exception& e) {
    HTTP2_LOG(session.logctx(), ERROR, "request handling ended with error, streamid: {}, err: {}",
              node->streamid, e.what());
    HTTP2_ASSUME_THREAD_UNCHANGED_END;
    send_rst_stream(session.connection, node->streamid, errc_e::INTERNAL_ERROR).start_and_detach();
    co_return 0;
  }
  HTTP2_ASSUME_THREAD_UNCHANGED_END;
  assert(rsp.status > 0);
  node->status = (int)rsp.status;
  node->req = response_bro::torequest(std::move(rsp));

  bool written = co_await session.response_written(*node);
  // канал ответа завершился исключением (finish_request_with_user_exception): оно уже лежит в promise
  if ((co_await dd::this_coro::handle).promise().has_exception()) [[unlikely]]
    co_return dd::rvo;
  if (written)
    HTTP2_LOG_TRACE(session.logctx(), "response for stream {} successfully written", node->streamid);
  else
    HTTP2_LOG_TRACE(session.logctx(), "response for stream {} failed", node->streamid);
  co_return 0;
}

void h2server_session::on_request_ready(h2stream& n) noexcept {
  if (n.responded) [[unlikely]]
    return;
  else
    n.responded = true;
  // was detached before in `start_request_assemble`
  stream_ptr np(&n, /*add_ref=*/false);
  np->status = reqerr_e::RESPONSE_IN_PROGRESS;
  on_scope_failure(nodedone) {
    on_response_done();
  };
  if (!np->responses_hook.is_linked()) {
    // already canceled
    HTTP2_LOG_TRACE(logctx(), "stream {} response canceled due session shutdown", np->streamid);
    return;
  }
  stream_id_t streamid = np->streamid;

  try {
    send_response(std::move(np), *this).start_and_detach();
    nodedone.no_longer_needed();
  } catch (std::exception& e) {
    send_rst_stream(connection, streamid, errc_e::INTERNAL_ERROR).start_and_detach();
    HTTP2_LOG(logctx(), ERROR, "session cannot handle request {} due exception: {}", streamid, e.what());
  }
}

bool h2server_session::rst_stream_server(rst_stream rstframe, bool skip_validation) {
  if (!skip_validation)
    connection->validate_rst_frame(rstframe);
  h2stream* n = connection->find_response_by_streamid(rstframe.header.streamid);
  if (!n) {
    auto it =
        std::find_if(connection->requests.begin(), connection->requests.end(),
                     [streamid = rstframe.header.streamid](h2stream& rn) { return rn.streamid == streamid; });
    if (it != connection->requests.end())
      n = &*it;
    else
      return false;
  }
  n->canceled_by_rststream = true;
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-5.4.2-5 на RST_STREAM нельзя отвечать RST_STREAM
  // После своей ошибки стрима RST_STREAM с её кодом отправляет rst_stream_after_error
  finish_server_request(*n, /*send_rst=*/false);
  return true;
}

void h2server_session::rst_stream_after_error(const stream_error& e) {
  rst_stream rst;
  rst.header = rst.make_header(e.streamid);
  rst.error_code = e.errc;
  // reuse rst stream like if someone sent it
  rst_stream_server(rst, /*skip_validation=*/true);
  send_rst_stream(connection, e.streamid, e.errc).start_and_detach();
}

size_t h2server_session::requests_left_exactly() const noexcept {
  size_t count = 0;
  // some streams may be in .requests AND in .responses
  for (h2stream& n : connection->requests) {
    if (connection->find_response_by_streamid(n.streamid) == nullptr)
      ++count;
  }
  return count + connection->responses.size();
}

void h2server_session::request_shutdown() noexcept {
  if (!new_requests_forbiden) {
    new_requests_forbiden = true;
    if (established) {
      send_goaway(connection, connection->last_initiated_streamid(), errc_e::NO_ERROR, "graceful shutdown")
          .start_and_detach();
    }
  }

  if (!has_unfinished_requests())
    on_session_done();
}

void h2server_session::request_terminate() noexcept {
  if (terminated) {
    if (!has_unfinished_requests())
      on_session_done();
    return;
  }
  terminated = true;
  new_requests_forbiden = true;

  // до установки сессии GOAWAY слать нельзя: соединение ещё не HTTP/2 (а для TLS может идти handshake)
  if (established) {
    send_goaway(connection, connection->last_initiated_streamid(), errc_e::NO_ERROR, "graceful shutdown")
        .start_and_detach();
  }

  // forget requests (including not finished)
  auto doforget = [&](h2stream* n) {
    stream_ptr p = n;  // prevent node destroy
    finish_server_request(*n);
  };
  connection->responses.clear_and_dispose(doforget);
  connection->requests.clear_and_dispose(doforget);

  assert(connection->requests.empty() && connection->responses.empty() && connection->timers.empty());
  if (!has_unfinished_requests())
    on_session_done();
}

void h2server_session::on_response_done() noexcept {
  if (new_requests_forbiden && !has_unfinished_requests())
    on_session_done();
}

void h2server_session::on_session_done() noexcept {
  assert(new_requests_forbiden && !has_unfinished_requests());
  if (done)
    return;
  done = true;
  connection->shutdown(reqerr_e::CANCELLED);
}

stream_ptr h2server_session::new_empty_stream_node(stream_id_t id) {
  assert((id % 2) == 1);
  assert(id <= MAX_STREAM_ID);
  // server reader do not uses 'on_header' / 'on_data_part'
  return connection->new_stream_node({}, deadline_t::never(), nullptr, nullptr, id);
}

void h2server_session::start_request_assemble(const h2frame& frame, h2stream* existing) {
  assert(frame.header.type == frame_e::HEADERS);

  // if stream already exist, its trailers or error
  if (existing) [[unlikely]] {
    if (existing->is_half_closed()) {
      throw protocol_error(errc_e::PROTOCOL_ERROR,
                           std::format("client initiates stream, which was already open, streamid: {}",
                                       frame.header.streamid));
    } else {
      // trailer headers received
      existing->receive_request_trailers(connection->decoder, frame);
      assert(existing->end_stream_received);  // if not, it must be protocol error
      // Note: manages 'node' lifetime
      on_request_ready(*existing);
      return;
    }
  }

  if (frame.header.streamid <= connection->laststartedstreamid) {
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1.1-2
    // "identifier of a newly established stream MUST be numerically greater than all streams that the
    // initiating endpoint has opened"
    throw protocol_error(
        errc_e::PROTOCOL_ERROR,
        std::format("stream identifier that is not numerically greater than previous (new: {}, prev: {})",
                    frame.header.streamid, connection->laststartedstreamid));
  }

  // Note: before making a decision about a stream, to keep in mind the client's desire to create such stream
  connection->laststartedstreamid = frame.header.streamid;

  if (requests_left_approx() >= connection->local_settings.max_concurrent_streams) {
    size_t exactreq = requests_left_exactly();
    if (exactreq >= connection->local_settings.max_concurrent_streams) {
      // не ignore_frame: id уже учтён в laststartedstreamid и стрим выглядел бы закрытым (STREAM_CLOSED
      // вместо REFUSED_STREAM)
      hpack::ignore_headers_block(connection->decoder, frame.data);
      throw stream_error(errc_e::REFUSED_STREAM, frame.header.streamid,
                         std::format("refused due max concurrent streams exceeded, max count: {}, actual: {}",
                                     connection->local_settings.max_concurrent_streams, exactreq));
    }
  }

  stream_ptr n = new_empty_stream_node(frame.header.streamid);
  n->status = reqerr_e::REQUEST_CREATED;
  connection->insert_response_node(*n);
  // Note: после этого detach() стрим остаётся без владельца
  // это учитывается в `on_request_ready` и `finish_server_request`
  h2stream& node = *n.detach();
  node.receive_request_headers(frame);
  if (node.end_stream_received) {  // setted in `receive_request_headers`
    // Note: manages 'node' lifetime
    on_request_ready(node);
  } else if (server->answer_before_data(node.req)) {
    // should be setted only if data will be present
    node.answered_before_data = true;
    on_request_ready(node);
  }
}

void h2server_session::client_settings_changed(h2frame newsettings) {
  connection->settings_changed(newsettings, /*remote_is_client=*/true);
}

void h2server_session::client_requests_graceful_shutdown(goaway_frame f) {
  (void)f;
  HTTP2_LOG_TRACE(logctx(), "received goaway from client, laststreamid: {}, dbginfo: {}", f.last_streamid,
                  f.debug_info);
  // nothing to do, since server do not start streams
  // and client wants to work until all requests are done (ok just work, then
  // drop connection)
}

void h2server_session::finish_server_request(h2stream& n, bool send_rst) noexcept {
  if (n.on_data_part_fn) {
    // prevent endless waiting if client does not send anything etc
    (*n.on_data_part_fn)({}, /*last chunk*/ true);
  }
  if (n.status == reqerr_e::REQUEST_CREATED) {
    // request did not assembled yet
    assert(n.task == nullptr);
    connection->forget(n);
    HTTP2_LOG_TRACE(logctx(), "stream {} canceled before its asembled", n.streamid);
    // single owner, which was 'detach' in `start_request_assemble`
    intrusive_ptr_release(&n);
    on_response_done();
  } else {
    bool orphan = !n.task;
    connection->finish_request(n, reqerr_e::CANCELLED, send_rst);
    if (orphan)
      on_response_done();
  }
}

void h2server_session::receive_headers(h2frame frame) {
  assert(frame.header.type == frame_e::HEADERS);
  frame.validate_streamid();
  frame.remove_padding();
  frame.ignore_deprecated_priority();
  // graceful shutdown запрещает только новые стримы, трейлеры уже идущего стрима обрабатываются как обычно
  h2stream* existing = connection->find_response_by_streamid(frame.header.streamid);
  if (new_requests_forbiden && !existing) [[unlikely]] {
    connection->ignore_frame(frame);
    send_rst_stream(connection, frame.header.streamid, errc_e::REFUSED_STREAM).start_and_detach();
    return;
  }
  start_request_assemble(frame, existing);
}

void h2server_session::receive_data(h2frame frame) {
  assert(frame.header.type == frame_e::DATA);
  frame.validate_streamid();
  frame.remove_padding();
  h2stream* node = connection->find_response_by_streamid(frame.header.streamid);
  if (!node) {
    connection->ignore_frame(frame);
    return;
  }
  // applicable only to data
  // Note: includes padding!
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-4.2-1
  decrease_window_size(connection->my_window_size, int32_t(frame.header.length), logctx());
  node->receive_request_data(frame);
  if (node->end_stream_received) {  // setted in `receive_request_data`
    // Note: manages 'node' lifetime
    on_request_ready(*node);
  }
}

}  // namespace hidi
