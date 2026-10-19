

#include "hidi/h2send_frames.hpp"

#include "hidi/h2connection.hpp"

namespace hidi {

dd::task<bool> send_goaway(h2connection_ptr con, stream_id_t laststreamid, errc_e errc, std::string dbginfo) {
  if (!con || con->is_dropped())
    co_return false;

  HTTP2_LOG_TRACE(con->logctx, "sending goaway frame: errc: {}, laststreamid: {}, dbginfo: {}", e2str(errc),
                  laststreamid, dbginfo);
  if (errc == errc_e::NO_ERROR) {
    if (con->graceful_shutdown_goaway_sended)
      co_return true;
    con->graceful_shutdown_goaway_sended = true;
  }
  bytes_t bytes;
  goaway_frame::form(laststreamid, errc, std::move(dbginfo), std::back_inserter(bytes));
  HIDI_WAIT_WRITE(*con);
  io_error_code ec;
  co_await con->write(bytes, ec);
  if (ec) {
    if (!con->is_dropped()) {
      // ignore error if we dropped connection anyway
      HTTP2_LOG_TRACE(con->logctx, "err while sending GOAWAY: err: {}", ec.message());
    }
    co_return false;
  }
  co_return true;
}

dd::task<void> send_rst_stream(h2connection_ptr con, stream_id_t streamid, errc_e errc) {
  if (!con || con->is_dropped())
    co_return;

  HTTP2_LOG_TRACE(con->logctx, "sending rst stream: id: {}, errc: {}", streamid, e2str(errc));
  byte_t bytes[rst_stream::LEN];
  rst_stream::form(streamid, errc, bytes);
  HIDI_WAIT_WRITE(*con);
  io_error_code ec;
  co_await con->write(bytes, ec);
  if (ec) {
    if (!con->is_dropped()) {
      // ignore error if we dropped connection anyway
      HTTP2_LOG(con->logctx, ERROR, "cannot rst stream: ec: {}", ec.message());
    }
  }
}

dd::task<void> send_settings_ack(h2connection_ptr con) {
  if (!con || con->is_dropped())
    co_return;

  HTTP2_LOG_TRACE(con->logctx, "sending settings ack");
  bytes_t bytes;
  accepted_settings_frame().form(std::back_inserter(bytes));
  HIDI_WAIT_WRITE(*con);
  io_error_code ec;
  co_await con->write(bytes, ec);
  if (ec)
    HTTP2_LOG(con->logctx, ERROR, "cannot send settings ACK: err: {}", ec.message());
}

dd::task<bool> send_ping(h2connection_ptr con, uint64_t data, bool request_pong) {
  if (!con || con->is_dropped())
    co_return false;

  HTTP2_LOG_TRACE(con->logctx, "sending ping");
  io_error_code ec;
  byte_t buf[ping_frame::LEN];
  ping_frame::form(data, request_pong, buf);
  HIDI_WAIT_WRITE(*con);
  co_await con->write(buf, ec);
  co_return !ec;
}

dd::task<void> handle_ping(ping_frame ping, h2connection_ptr con) {
  HTTP2_LOG_TRACE(con->logctx, "received ping, data: {}", ping.get_data());
  if (ping.header.flags & flags::ACK) {
    if (ping.get_data() == PING_VALUE) {
      HTTP2_LOG_TRACE(con->logctx, "server DID respond ping frame");
      con->pingdeadlinetimer.cancel();
    }
    co_return;
  }
  if (!co_await send_ping(con, ping.get_data(),
                          /*request_pong=*/false)) {
    HTTP2_LOG(con->logctx, ERROR, "cannot handle ping");
  }
}

dd::task<bool> send_window_update(h2connection_ptr con, stream_id_t id, uint32_t inc) {
  if (!con || con->is_dropped())
    co_return false;

  byte_t buf[window_update_frame::LEN];
  window_update_frame::form(id, inc, buf);
  HTTP2_LOG_TRACE(con->logctx, "sending window update: stream: {}, inc: {}", id, inc);
  HIDI_WAIT_WRITE(*con);
  io_error_code ec;
  co_await con->write(std::span(buf), ec);
  co_return !ec;
}

dd::task<void> update_window_to_max(stream_ptr node, h2connection_ptr con) try {
  assert(con);
  stream_id_t streamid = node ? node->streamid : 0;
  cfint_t& size = node ? node->rl_streamlevel_windowsize : con->my_window_size;
  // its possible to have < 0 in such cases like
  // * sending DATA before settings exchange
  // * updating settings value SETTINGS_INITIAL_WINDOW_SIZE
  while (size < 0) {
    // avoid too big window size increment
    if (co_await send_window_update(con, streamid, MAX_WINDOW_SIZE))
      increment_window_size_trusted(size, MAX_WINDOW_SIZE);
    else
      co_return;

    if (con->is_dropped())
      co_return;
  }
  if (size != MAX_WINDOW_SIZE) [[likely]] {
    static_assert(std::numeric_limits<uint32_t>::max() > MAX_WINDOW_SIZE);
    uint32_t inc = uint32_t(MAX_WINDOW_SIZE - size);
    if (co_await send_window_update(con, streamid, inc))
      increment_window_size_trusted(size, int32_t(inc));
  }
} catch (std::exception& e) {
  // do not finish streams / send goaway. Will repeat try to update window later
  // anyway
  HTTP2_LOG(con->logctx, ERROR, "sending window update ended with error: {}", e.what());
}

}  // namespace hidi
