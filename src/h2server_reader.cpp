

#include "hidi/h2server_reader.hpp"

#include "hidi/h2connection.hpp"
#include "hidi/h2protocol.hpp"
#include "hidi/h2send_frames.hpp"
#include "hidi/h2server_session.hpp"
#include "hidi/logger.hpp"
#include "hidi/utils/reusable_buffer.hpp"

#include <zal/zal.hpp>

namespace hidi {

// handles only utility frames (not DATA / HEADERS)
static void server_handle_utility_frame(h2frame frame, h2server_session& session) {
  using enum frame_e;

  h2connection& con = *session.connection;

  switch (frame.header.type) {
    case HEADERS:
    case DATA:
      unreachable();
    case SETTINGS:
      session.client_settings_changed(frame);
      return;
    case PING:
      handle_ping(ping_frame::parse(frame.header, frame.data), &con).start_and_detach();
      return;
    case RST_STREAM:
      if (!session.rst_stream_server(rst_stream::parse(frame.header, frame.data))) {
        HTTP2_LOG(session.logctx(), INFO, "client finished stream (id: {}) which is not exists",
                  frame.header.streamid);
      }
      return;
    case GOAWAY: {
      goaway_frame f = goaway_frame::parse(frame.header, frame.data);
      if (f.error_code != errc_e::NO_ERROR) {
        throw goaway_exception(f.last_streamid, f.error_code, std::move(f.debug_info));
      } else {
        session.client_requests_graceful_shutdown(f);
        return;
      }
    }
    case WINDOW_UPDATE:
      con.window_update(window_update_frame::parse(frame.header, frame.data));
      return;
    case PUSH_PROMISE:
      // https://datatracker.ietf.org/doc/html/rfc9113#section-6.6-9
      // push инициирует только сервер, клиент не может присылать PUSH_PROMISE
      throw protocol_error(errc_e::PROTOCOL_ERROR, "PUSH_PROMISE must not be sent by client");
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

dd::task<int> start_server_reader_for(h2server_session& session) try {
  auto guard = session.connection_parts_gate.hold();
  assert(session.connection);
  using enum frame_e;
  HTTP2_LOG_TRACE(session.logctx(), "reader started");
  on_scope_exit {
    HTTP2_LOG_TRACE(session.logctx(), "reader ended");
  };
  h2connection& con = *session.connection;
  io_error_code ec;
  reusable_buffer buffer;
  h2frame frame;

  for (;;) {
    if (con.is_dropped())
      co_return reqerr_e::DONE;

    // read frame header

    frame.data = buffer.get_exactly(FRAME_HEADER_LEN);

    co_await con.read(frame.data, ec);

    if (ec)
      co_return reqerr_e::NETWORK_ERR;

    if (con.is_dropped())
      co_return reqerr_e::DONE;

    // parse frame header
    session.received_frame();
    frame.header = frame_header::parse(frame.data);
    frame.validate_header();
    con.validate_frame_max_size(frame.header);

    // read frame data

    frame.data = buffer.get_exactly(frame.header.length);
    co_await con.read(frame.data, ec);
    if (ec)
      co_return reqerr_e::NETWORK_ERR;
    if (con.is_dropped())
      co_return reqerr_e::DONE;

    // handle frame

    try {
      switch (frame.header.type) {
        case HEADERS:
          if (frame.header.flags & flags::END_HEADERS) [[likely]] {
            session.receive_headers(frame);
          } else {
            co_await session.connection->receive_headers_with_continuation(
                frame, ec, [&] { session.received_frame(); },
                [&](h2frame frame) { session.receive_headers(frame); });
            if (ec)
              co_return reqerr_e::NETWORK_ERR;
            if (con.is_dropped())
              co_return reqerr_e::DONE;
          }
          break;
        case DATA:
          session.receive_data(frame);
          break;
        default:
          server_handle_utility_frame(frame, session);
          break;
      }
    } catch (stream_error& _e) {
      // workaround windows ABI https://github.com/llvm/llvm-project/issues/153949
      auto& e = _e;
      HTTP2_LOG(session.logctx(), ERROR, "stream exception in reader. err: {}", e.what());
      session.rst_stream_after_error(e);
      // do not require connection close
    }
    con.validate_pending_reply_frames();

    // connection control flow (streamlevel in server_handle_frame)
    if (con.my_window_size < MAX_WINDOW_SIZE / 2)
      co_await update_window_to_max(nullptr, &con);
  }
  unreachable();
} catch (hpack::protocol_error& e) {
  HTTP2_LOG(session.logctx(), ERROR, "hpack error happens in reader, err: {}", e.what());
  send_goaway(session.connection, session.connection->last_initiated_streamid(), errc_e::COMPRESSION_ERROR,
              e.what())
      .start_and_detach();
  co_return reqerr_e::PROTOCOL_ERR;
} catch (protocol_error& e) {
  HTTP2_LOG(session.logctx(), ERROR, "exception in reader. err: {}", e.what());
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-5.4.1-3
  // последний стрим клиента, который сервер начал обрабатывать, остальные клиент может безопасно повторить
  send_goaway(session.connection, session.connection->last_initiated_streamid(), e.errc, e.what())
      .start_and_detach();
  co_return reqerr_e::PROTOCOL_ERR;
} catch (goaway_exception& gae) {
  HTTP2_LOG(session.logctx(), ERROR, "goaway received, {}", gae.what());
  co_return reqerr_e::CANCELLED;
} catch (std::exception& se) {
  HTTP2_LOG(session.logctx(), INFO, "unexpected exception in reader {}", se.what());
  co_return reqerr_e::UNKNOWN_ERR;
} catch (...) {
  HTTP2_LOG(session.logctx(), INFO, "unknown exception happens in reader");
  co_return reqerr_e::UNKNOWN_ERR;
}

}  // namespace hidi
