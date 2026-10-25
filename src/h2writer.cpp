

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wall"
#pragma GCC diagnostic ignored "-Wextra"
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wsign-compare"

#include "hidi/h2writer.hpp"
#include "hidi/h2connection.hpp"
#include "hidi/h2protocol.hpp"
#include "hidi/h2send_frames.hpp"
#include "hidi/http_base.hpp"
#include "hidi/http_body.hpp"
#include "hidi/asio/asio_executor.hpp"
#include "hidi/request_context.hpp"

#include <hpack/encoder.hpp>
#include <zal/zal.hpp>

#include <boost/asio/error.hpp>

namespace hidi {

constexpr inline auto H2FHL = FRAME_HEADER_LEN;

// client-side
static void generate_http2_connect_headers(const h2stream& node, hpack::encoder& encoder, bytes_t& bytes) {
  assert(node.req.method == http_method_e::CONNECT);

  auto& req = node.req;
  auto out = std::back_inserter(bytes);
  // https://datatracker.ietf.org/doc/html/rfc8441#section-4
  bool extended_connect = std::ranges::find(req.headers, std::string_view(":protocol"),
                                            &http_header_t::name) != req.headers.end();

  encoder.encode(hpack::static_table_t::method_get, "CONNECT", out);
  // does not check single value "websocket" for :protocol pseudoheader for future extensions
  // anyway server will check it
  if (extended_connect) {
    // pseudoheaders must be first!
    // do not handle / reorder user headers here to make sure
    // echo server will exactly copy what user writes in request
    assert(req.headers.front().name() == ":protocol");
    assert(req.body.content_type.empty());
    using hdrs = hpack::static_table_t::values;
    hdrs scheme = req.scheme == scheme_e::HTTPS ? hdrs::scheme_https : hdrs::scheme_http;
    encoder.encode_header_fully_indexed(scheme, out);
    if (!req.authority.empty())
      encoder.encode_with_cache(hdrs::authority, req.authority, out);
    encoder.encode_with_cache(hdrs::path, req.path, out);
  } else {
    // https://www.rfc-editor.org/rfc/rfc9113.html#name-the-connect-method
    // :path :scheme MUST be omitted, authority required
    assert(!req.authority.empty());  // must be setted, address for server TCP connection
    encoder.encode_with_cache(hpack::static_table_t::authority, req.authority, out);
  }
  for (auto& h : req.headers)
    encoder.encode(h.name(), h.value(), out);
}

template <bool IS_CLIENT>
static void generate_http2_headers_to(const h2stream& node, hpack::encoder& encoder, bytes_t& headers) {
  using hdrs = hpack::static_table_t::values;
  const auto& request = node.req;

  assert(!IS_CLIENT || !request.path.empty() || node.is_connect_request());

  auto out = std::back_inserter(headers);

  if constexpr (IS_CLIENT) {
    // Note: order
    // method, scheme, path, authority
    // to match grpc Call-Definition https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
    // (in case someone will implement grpc over this HTTP/2 impl)

    switch (request.method) {
      case http_method_e::GET:
        encoder.encode_header_fully_indexed(hdrs::method_get, out);
        break;
      case http_method_e::POST:
        encoder.encode_header_fully_indexed(hdrs::method_post, out);
        break;
      case http_method_e::CONNECT:
        if constexpr (IS_CLIENT) {
          generate_http2_connect_headers(node, encoder, headers);
          return;
        } else {
          [[fallthrough]];
        }
      default:
        encoder.encode_with_cache(hdrs::method_get, e2str(request.method), out);
    }
    hdrs scheme = request.scheme == scheme_e::HTTPS ? hdrs::scheme_https : hdrs::scheme_http;
    encoder.encode_header_fully_indexed(scheme, out);
    encoder.encode_with_cache(hdrs::path, request.path, out);
    if (!request.authority.empty())
      encoder.encode_with_cache(hdrs::authority, request.authority, out);
  } else {
    // server, required only :status
    assert(node.status > 0);
    encoder.encode_status(node.status, out);
  }

  if (!request.body.content_type.empty())
    encoder.encode_with_cache(hdrs::content_type, request.body.content_type, out);

  // custom headers

  for (auto& [name, value] : request.headers) {
    assert(is_lowercase(name) && "http2 requires headers to be in lowercase");
    encoder.encode_with_cache(name, value, out);
  }
}

// precondition: node.req.data is not empty
// forms new data frame
// also handles window size changes
// returns length of result DATA frame
// or 0 if cannot send because of control flow
// precondition: 'out' contains atleast 9 valid bytes
template <bool Streaming>
[[nodiscard]] static cfint_t fill_data_header(const h2stream& node, const h2connection& con,
                                              size_t unhandled_bytes, byte_t* out) noexcept {
  using enum frame_e;
  using namespace flags;

  assert(!node.req.body.data.empty());
  assert(node.req.body.data.size() >= unhandled_bytes);
  frame_header header;
  cfint_t len = std::min<int64_t>({int64_t(unhandled_bytes), con.remote_settings.max_frame_size,
                                   node.lr_streamlevel_windowsize, con.receiver_window_size});
  if (len <= 0) [[unlikely]]
    return len;
  header.length = len;
  header.type = DATA;
  if constexpr (!Streaming)
    header.flags = unhandled_bytes == header.length ? END_STREAM : EMPTY_FLAGS;
  else
    header.flags = EMPTY_FLAGS;
  header.streamid = node.streamid;
  header.form(out);

  return header.length;
}

template <bool Streaming>
static dd::task<void> write_data(stream_ptr work, h2connection_ptr con, writer_callbacks_ptr cbs,
                                 io_error_code& ec) try {
  assert(con && work && cbs && cbs->neterrcb && cbs->sleepcb);
  http_body_bytes& data = work->req.body.data;

  // uses guarantee about FRAME_LEN_BYTES before .data()
  static_assert(
      std::is_same_v<typename decltype(work->req.body.data)::allocator_type, detail::allocator_p9<byte_t>>);

  cfint_t framelen = 0;
  byte_t* in = data.data();
  byte_t* data_end = in + data.size();

  for (; in != data_end; in += framelen) {
    if (work->finished() || con->is_dropped())
      co_return;

    framelen = fill_data_header<Streaming>(*work, *con, std::distance(in, data_end), in - H2FHL);
    if (framelen <= 0) [[unlikely]] {
      HTTP2_LOG_TRACE(con->logctx,
                      "cannot send bytes now! unhandled: {}, max_frame_len: {}, "
                      "stream wsz {}, con wsz: {}",
                      std::distance(in, data_end), con->remote_settings.max_frame_size,
                      work->lr_streamlevel_windowsize, con->receiver_window_size);
      co_await cbs->sleepcb(std::chrono::nanoseconds(500), ec);
      if (ec) {
        HTTP2_LOG(con->logctx, ERROR, "something went wrong while sleeping, err: {}", ec.message());
        if (ec == boost::asio::error::operation_aborted)
          co_return;
        // continue, ignore sleep errors
      }
      framelen = 0;  // avoid in += framelen which is < 0
      continue;
    }
    HTTP2_LOG_TRACE(con->logctx,
                    "FRAME for stream {}, len: {}, unhandled: {}, rws: {}, "
                    "rs max frame max: {}, max_frame_size: {}, DATA: {}",
                    work->streamid, framelen, std::distance(in, data_end), con->receiver_window_size,
                    work->lr_streamlevel_windowsize, con->remote_settings.max_frame_size,
                    std::string_view((const char*)in, framelen));
    // send frame
    HIDI_WAIT_WRITE(*con);
    co_await con->write(std::span(in - H2FHL, framelen + H2FHL), ec);

    if (ec)
      co_return;
    // control flow
    decrease_window_size(con->receiver_window_size, framelen, con->logctx);           // connection
    decrease_window_size(work->lr_streamlevel_windowsize, framelen, work->logctx());  // stream
  }  // end loop
  HTTP2_LOG_TRACE(con->logctx, "DATA for stream {} successfully sended", work->streamid);
  co_return;
} catch (std::exception& e) {
  con->finish_request(*work, reqerr_e::UNKNOWN_ERR);
  send_rst_stream(con, work->streamid, errc_e::CANCEL).start_and_detach();
  HTTP2_LOG(con->logctx, ERROR, "writing DATA for stream {} ended with error, err: {}", work->streamid,
            e.what());
}

// блокирует запись. Разблокируется только после write_continuations
// pre: HIDI_WAIT_WRITE уже сделано
static void continuations_begin(h2connection& con) {
  con.continuation_gateway.close();
}
// noexcept на случай если пойдёт что-то не так. Лучше сделать terminate сразу
static void continuations_end(h2connection& con) noexcept {
  dd::any_executor_ref exe{con.ioctx};
  con.continuation_gateway.open(exe);
}

// writes CONTINUATION frames
// assumes first 9 bytes of `hdrs` are reserved for frame header
// pre: continuations_begin вызвано
// Note: не забудь вызвать continuations_end
static dd::task<void> write_continuations(h2connection_ptr con, stream_id_t streamid, size_t handled,
                                          bytes_t hdrs, io_error_code& ec) {
  assert(con);
  assert(handled < hdrs.size());
  assert(handled >= H2FHL);
  assert(con->continuation_gateway.closed());
  byte_t* b = hdrs.data() + handled;
  byte_t* e = hdrs.data() + hdrs.size();
  size_t framesz;
  for (; b != e; b += framesz) {
    framesz = std::min<size_t>(con->remote_settings.max_frame_size, e - b);
    frame_header h{
        .length = uint32_t(framesz),
        .type = frame_e::CONTINUATION,
        .flags = framesz == e - b ? flags::END_HEADERS : flags::EMPTY_FLAGS,
        .streamid = streamid,
    };
    h.form(b - H2FHL);
    HTTP2_LOG_TRACE(con->logctx, "writing CONTINUATION frame for stream {}, len: {}", streamid, framesz);
    co_await con->write(std::span(b - H2FHL, framesz + H2FHL), ec);

    if (ec || con->is_dropped())
      co_return;
  }
}

static dd::task<void> write_trailers(h2connection& con, stream_id_t streamid, http_headers_t headers,
                                     io_error_code& ec) {
  HTTP2_LOG_TRACE(con.logctx, "sendind trailers for stream {}", streamid);
  // reserve memory for frame header
  std::vector<byte_t> bytes(H2FHL);
  auto out = std::back_inserter(bytes);
  for (auto& [name, value] : headers) {
    assert(is_lowercase(name) && "http2 requires headers to be in lowercase");
    con.encoder.encode_with_cache(name, value, out);
  }
  size_t framelen = bytes.size() - H2FHL;
  frame_header fhdr;
  fhdr.length = std::min<uint32_t>(framelen, con.remote_settings.max_frame_size);
  bool one_frame = fhdr.length == framelen;
  fhdr.type = frame_e::HEADERS;
  fhdr.streamid = streamid;
  if (one_frame) [[likely]]
    fhdr.flags = flags::END_STREAM | flags::END_HEADERS;  // trailers
  else
    fhdr.flags = flags::END_STREAM;
  fhdr.form(bytes.data());
  HIDI_WAIT_WRITE(con);
  if (!one_frame) [[unlikely]]
    continuations_begin(con);
  on_scope_exit {
    if (!one_frame)
      continuations_end(con);
  };
  co_await con.write(std::span(bytes.data(), fhdr.length + H2FHL), ec);
  if (!one_frame) [[unlikely]]
    co_await write_continuations(&con, streamid, fhdr.length + H2FHL, std::move(bytes), ec);
}

template <bool IS_CLIENT>
dd::job write_stream_data(stream_ptr node, h2connection_ptr con, writer_callbacks_ptr cbs) try {
  assert(node && node->is_output_streaming());

  h2stream& snode = *node;
  assert(!!snode.makebody);

  io_error_code ec;

  // channel may fill trailers to send them
  http_headers_t trailers;

  // Note: order. `chan` destroyed before `makebody` (which destroyed in `return_node`)
  streaming_body_t chan = snode.makebody(trailers, request_context(*node));

  on_scope_exit {
    snode.req.body = {};
    snode.makebody.reset();
  };
  // if !IS_CLIENT request finished on each code path
  // create 'b' before loop to handle exception after loop
  HTTP2_ASSUME_THREAD_UNCHANGED_START;
  auto b = co_await chan.begin();
  for (; b != chan.end(); (void)(co_await (++b))) {
    HTTP2_ASSUME_THREAD_UNCHANGED_END;
    std::span<const byte_t> chunk = *b;
    if (snode.finished() || con->is_dropped())
      co_return;
    if (chunk.empty())
      continue;
    snode.req.body.data.resize(chunk.size(), uninitialized_byte);
    memcpy(snode.req.body.data.data(), chunk.data(), chunk.size());
    HTTP2_LOG_TRACE(con->logctx, "sendind DATA part for stream {}, len: {}, bodystr: \"{}\"", snode.streamid,
                    snode.req.body.data.size(), snode.req.body.strview());
    co_await write_data</*Streaming=*/true>(node, con, cbs, ec);

    if (ec)
      goto end;
  }

  if (std::exception_ptr e = chan.take_exception()) {
    con->finish_request_with_user_exception(*node, std::move(e));
    HTTP2_LOG(con->logctx, ERROR, "writing streaming data for stream {} ended with user exception",
              node->streamid);
    co_return;
  }

  if (snode.finished() || con->is_dropped())
    co_return;

  if (!trailers.empty()) {
    co_await write_trailers(*con, node->streamid, std::move(trailers), ec);

    if (snode.finished() || con->is_dropped())
      co_return;
    if (ec)
      goto end;
  } else {
    // write empty DATA with END_STREAM
    byte_t bytes[H2FHL];
    data_frame::end_stream_marker(node->streamid).form(+bytes);
    HIDI_WAIT_WRITE(*con);
    co_await con->write(bytes, ec);

    if (snode.finished() || con->is_dropped())
      co_return;
    if (ec)
      goto end;
  }
  if constexpr (!IS_CLIENT) {
    con->finish_request(snode, snode.status);
  } else {
    // client sends all what it need, do not want to receive anything
    if (snode.is_connect_request())
      con->finish_request(snode, snode.status);
  }
  co_return;
end:
  con->finish_request(
      snode, ec != boost::asio::error::operation_aborted ? reqerr_e::NETWORK_ERR : reqerr_e::CANCELLED);
  cbs->neterrcb();
} catch (std::exception& e) {
  con->finish_request(*node, reqerr_e::UNKNOWN_ERR);
  send_rst_stream(con, node->streamid, errc_e::CANCEL).start_and_detach();
  HTTP2_LOG(con->logctx, ERROR, "writing streaming DATA for stream {} ended with error, err: {}",
            node->streamid, e.what());
}

template dd::job write_stream_data<true>(stream_ptr node, h2connection_ptr con, writer_callbacks_ptr cbs);
template dd::job write_stream_data<false>(stream_ptr node, h2connection_ptr con, writer_callbacks_ptr cbs);

template <bool IS_CLIENT>
dd::job start_writer_for(h2connection_ptr con, writer_sleepcb_t sleepcb, writer_on_network_err_t neterrcb,
                         bool forcedisablehpack, dd::gate::holder) {
  assert(con && sleepcb && neterrcb);
  // make callbacks easy to copy into write_pending_frames for future use
  writer_callbacks_ptr cbs = new writer_callbacks(std::move(sleepcb), std::move(neterrcb));

  HTTP2_LOG_TRACE(con->logctx, "writer started");
  on_scope_exit {
    HTTP2_LOG_TRACE(con->logctx, "writer ended");
  };

  io_error_code ec;
  bytes_t headers;
  headers.reserve(128);
  for (;;) {
    // waiting for job or connection shutdown

    if (!co_await con->wait_work())
      goto end;

    assert(!con->requests.empty());

    while (!con->requests.empty()) {
      if constexpr (IS_CLIENT) {
        // запрос ждёт слот, оставаясь в requests: так при таймауте он завершится без RST_STREAM (см.
        // finish_request_by_timeout), а при разрыве соединения - в finish_all_with_reason
        while (con->concurrent_streams_now() >= con->remote_settings.max_concurrent_streams) [[unlikely]] {
          HTTP2_LOG_TRACE(con->logctx, "too many streams, waiting (max is {})",
                          con->remote_settings.max_concurrent_streams);
          co_await yield_on_ioctx(con->ioctx);
          if (con->is_dropped())
            goto end;
        }
        // все ожидавшие запросы могли завершиться по таймауту
        if (con->requests.empty())
          break;
      }
      stream_ptr node = &con->requests.front();

      con->requests.pop_front();
      con->insert_response_node(*node);

      // send headers

      headers.resize(H2FHL);  // reserve for frame header

      con->start_headers_block(*node, forcedisablehpack, headers);

      generate_http2_headers_to<IS_CLIENT>(*node, con->encoder, headers);
      using namespace flags;
      size_t hdrslen = headers.size() - H2FHL;
      frame_header fhdr;
      fhdr.length = std::min<uint32_t>(con->remote_settings.max_frame_size, hdrslen);
      bool one_frame = hdrslen == fhdr.length;
      fhdr.type = frame_e::HEADERS;
      fhdr.streamid = node->streamid;
      if (one_frame) [[likely]]
        fhdr.flags = flags_t(node->has_body() ? END_HEADERS : (END_HEADERS | END_STREAM));
      else
        fhdr.flags = flags_t(node->has_body() ? EMPTY_FLAGS : END_STREAM);
      fhdr.form(headers.data());
      HTTP2_LOG_TRACE(con->logctx, "sending headers block: stream {}, block size: {}", node->streamid,
                      headers.size() - H2FHL);
#ifdef HTTP2_ENABLE_TRACE
      if (con->logctx.should_log(log_level_e::TRACE)) [[unlikely]]
        trace_request_headers(*node, IS_CLIENT, con->logctx);
#endif
      HIDI_WAIT_WRITE(*con);
      if (!one_frame)
        continuations_begin(*con);
      co_await con->write(std::span(headers.data(), fhdr.length + H2FHL), ec);

      if (ec || con->is_dropped()) {
        if (!one_frame)
          continuations_end(*con);
        // otherwise will be finished by drop_connection with
        // reqerr_e::cancelled
        if (ec != boost::asio::error::operation_aborted)
          con->finish_request(*node, reqerr_e::NETWORK_ERR);

        goto end;
      }

      if (!one_frame) [[unlikely]] {
        on_scope_failure(unlockcon) {
          continuations_end(*con);
        };
        co_await write_continuations(con, node->streamid, fhdr.length + H2FHL, std::move(headers), ec);
        unlockcon.use_and_forget();
        if (ec || con->is_dropped()) {
          if (ec != boost::asio::error::operation_aborted)
            con->finish_request(*node, reqerr_e::NETWORK_ERR);

          goto end;
        }
      }

      // send data
      if (!node->req.body.data.empty()) {
        co_await write_data</*Streaming=*/false>(node, con, cbs, ec);

        if (ec || con->is_dropped()) {
          if (ec != boost::asio::error::operation_aborted)
            con->finish_request(*node, reqerr_e::NETWORK_ERR);

          goto end;
        }
        if constexpr (!IS_CLIENT)
          con->finish_request(*node, node->status);
      } else if (!node->is_output_streaming()) {
        // request has no body
        if constexpr (!IS_CLIENT)
          con->finish_request(*node, node->status);
      } else if constexpr (IS_CLIENT) {
        if (!node->is_connect_request())
          (void)write_stream_data<IS_CLIENT>(node, con, cbs);
      } else {
        // stream finished in write_stream-data
        (void)write_stream_data<IS_CLIENT>(node, con, cbs);
      }
    }
  }  // end loop handling requests
end:
  cbs->neterrcb();
}

dd::job start_writer_for_client(h2connection_ptr con, writer_sleepcb_t sleepcb,
                                writer_on_network_err_t neterrcb, bool forcedisablehpack,
                                dd::gate::holder guard) {
  return start_writer_for</*IS_CLIENT=*/true>(std::move(con), std::move(sleepcb), std::move(neterrcb),
                                              forcedisablehpack, std::move(guard));
}

dd::job start_writer_for_server(h2connection_ptr con, writer_sleepcb_t sleepcb,
                                writer_on_network_err_t neterrcb, bool forcedisablehpack,
                                dd::gate::holder guard) {
  return start_writer_for</*IS_CLIENT=*/false>(std::move(con), std::move(sleepcb), std::move(neterrcb),
                                               forcedisablehpack, std::move(guard));
}

}  // namespace hidi
#pragma GCC diagnostic pop
