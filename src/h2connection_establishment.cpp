

#include "hidi/h2connection_establishment.hpp"
#include "hidi/h2connection.hpp"
#include "hidi/h2send_frames.hpp"
#include "hidi/utils/reusable_buffer.hpp"

namespace hidi {

// https://www.rfc-editor.org/rfc/rfc9113.html#section-4.2
// первый SETTINGS отправляется до обмена настройками, поэтому ограничен начальным SETTINGS_MAX_FRAME_SIZE
static void validate_first_settings_len(const frame_header& header) {
  if (header.length > MIN_MAX_FRAME_LEN) {
    throw protocol_error(errc_e::FRAME_SIZE_ERROR,
                         std::format("first SETTINGS frame is too big, len: {}", header.length));
  }
}

static void validate_first_server_frame_header(const frame_header& header, const log_context& logctx) {
  if (header.type != frame_e::SETTINGS || header.length > FRAME_LEN_MAX) {
    HTTP2_LOG(logctx, ERROR, "first server frame is not settings, frame: {}", header);
    throw protocol_error(errc_e::CONNECT_ERROR,
                         std::format("first server frame is not settings, frame: {}", header));
  }
  if (header.flags & flags::ACK) {
    HTTP2_LOG(logctx, ERROR, "invalid server preface SETTINGS with ACK flag");
    throw protocol_error(errc_e::CONNECT_ERROR, "invalid server preface SETTINGS with ACK flag");
  }
  validate_first_settings_len(header);
}

static void validate_client_magic(std::span<byte_t> magic, const log_context& logctx) {
  if (!std::ranges::equal(magic, std::span(CONNECTION_PREFACE))) {
    HTTP2_LOG(logctx, ERROR, "invalid client magic, expected: {}, received: {}",
              std::string_view((const char*)CONNECTION_PREFACE, std::size(CONNECTION_PREFACE)),
              std::string_view((const char*)magic.data(), magic.size()));
    throw protocol_error(
        errc_e::PROTOCOL_ERROR,
        std::format("invalid client magic, expected: {}, received: {}",
                    std::string_view((const char*)CONNECTION_PREFACE, std::size(CONNECTION_PREFACE)),
                    std::string_view((const char*)magic.data(), magic.size())));
  }
}

dd::task<h2connection_ptr> establish_http2_session_client(h2connection_ptr con, h2client_options options) {
  using enum frame_e;

  constexpr auto H2FHL = FRAME_HEADER_LEN;

  assert(con);
  assert(options.max_receive_frame_size <= FRAME_LEN_MAX);
  con->server_settings = &con->remote_settings;
  con->logctx.name.set_prefix(CLIENT_CONNECTION_PREFIX);
  con->local_settings = settings_t{
      .header_table_size = options.force_disable_hpack ? 0 : options.hpack_dyntab_size,
      .enable_push = false,
      .initial_stream_window_size = MAX_WINDOW_SIZE,
      // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.2-2.10.2
      .max_frame_size = std::max(options.max_receive_frame_size, MIN_MAX_FRAME_LEN),
      .deprecated_priority_disabled = true,
  };
  con->decoder = hpack::decoder(con->local_settings.header_table_size);
  con->laststartedstreamid = 0;

  io_error_code ec;

  {
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-3.4-4
    // "The client sends the client connection preface as the first application
    // data octets of a connection"

    bytes_t connection_request;
    form_connection_initiation(con->local_settings, std::back_inserter(connection_request));
    HTTP2_LOG_TRACE(con->logctx, "sending client preface");
    co_await con->write(connection_request, ec);
    if (ec) {
      HTTP2_LOG(con->logctx, ERROR, "cannot write HTTP/2 client connection preface, err: {}", ec.message());
      throw network_exception("cannot write HTTP/2 client connection preface, err: {}", ec.message());
    }
  }
  if (options.allow_requests_before_server_settings) {
    // server settings and settings ACK will be handled later
    co_return con;
  }
  // read server connection preface (settings frame)

  // read server preface
  //
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-3.4-6
  // "potentially empty SETTINGS frame (Section 6.5) that MUST be the first
  // frame the server sends in the HTTP/2 connection. The SETTINGS frames
  // received from a peer as part of the connection preface MUST be acknowledged
  // (see Section 6.5.3) after sending the connection preface."

  // So order MUST BE settings (NOT ACK) + settings (ACK)

  byte_t buf[H2FHL];
  co_await con->read(std::span(buf, H2FHL), ec);

  if (ec) {
    HTTP2_LOG(con->logctx, ERROR, "cannot read HTTP/2 server preface, {}", ec.message());
    throw network_exception("cannot read HTTP/2 server preface, {}", ec.message());
  }

  frame_header header = frame_header::parse(buf);

  validate_first_server_frame_header(header, con->logctx);

  bytes_t bytes(header.length);
  co_await con->read(bytes, ec);
  if (ec) {
    HTTP2_LOG(con->logctx, ERROR, "cannot read accepted settings frame from server");
    throw network_exception(ec);
  }
  settings_frame::parse(header, bytes, server_settings_visitor(con->remote_settings, /*first frame*/ true));

  // initialize remote settings-based things

  // https://www.rfc-editor.org/rfc/rfc7541#section-4.2
  // кодировщик начинает с размера по умолчанию и сообщает новый размер в первом блоке заголовков
  if (con->encoder_table_size() != settings_t{}.header_table_size)
    con->encoder_table_size_changed();
  con->remote_settings.max_frame_size =
      std::min(con->remote_settings.max_frame_size, options.max_send_frame_size);

  // answer settings ACK "as soon as possible"

  accepted_settings_frame().form(buf);
  HTTP2_LOG_TRACE(con->logctx, "sending settings ACK");
  co_await con->write(std::span(buf, H2FHL), ec);
  if (ec)
    throw network_exception("cannot send accepted settings frame to server, {}", ec.message());

  // SETTINGS frame with ACK flag will be handled later in
  // 'h2connection::server_settings_changed' as regular frame

  HTTP2_LOG_TRACE(con->logctx, "connection successfully established, decoder size: {}",
                  con->remote_settings.header_table_size);

  co_return con;
}

dd::task<h2connection_ptr> establish_http2_session_server(h2connection_ptr con, h2server_options options) {
  assert(con);
  io_error_code ec;
  constexpr size_t MAGIC_SZ = std::size(CONNECTION_PREFACE);
  con->server_settings = &con->local_settings;
  assert(options.max_receive_frame_size <= FRAME_LEN_MAX);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-3.4-4
  // client MUST start its connection with a connection preface
  // client-preface == client magic bytes + settings, which MAY be empty
  // this guararntees, that server can just read and validate preface +
  // settings, then send its own settings and settings ACK

  reusable_buffer buf;
  {  // read client magic
    std::span magic = buf.get_exactly(MAGIC_SZ);
    co_await con->read(magic, ec);
    if (ec) {
      HTTP2_LOG(con->logctx, ERROR, "client session establishment failed: reading preface, err: {}",
                ec.message());
      throw network_exception(ec);
    }
    validate_client_magic(magic, con->logctx);
  }
  frame_header settingsheader;
  {  // read settings frame
    std::span settingsframe = buf.get_exactly(FRAME_HEADER_LEN);
    co_await con->read(settingsframe, ec);
    if (ec) {
      HTTP2_LOG(con->logctx, ERROR,
                "client session establishment failed: reading client settings header, err: {}", ec.message());
      throw network_exception(ec);
    }
    settingsheader = frame_header::parse(settingsframe);
  }
  validate_settings_not_ack_frame(settingsheader);
  validate_first_settings_len(settingsheader);

  {  // read settings data
    std::span settingsdata = buf.get_exactly(settingsheader.length);
    co_await con->read(settingsdata, ec);
    if (ec) {
      HTTP2_LOG(con->logctx, ERROR,
                "client session establishment failed: reading client settings data, err: {}", ec.message());
      throw network_exception(ec);
    }
    settings_frame::parse(settingsheader, settingsdata,
                          client_settings_visitor(con->remote_settings, /*first frame*/ true));
  }

  // write ACK and my settiings

  con->local_settings.header_table_size = options.force_disable_hpack ? 0 : options.hpack_dyntab_size;
  con->local_settings.max_concurrent_streams =
      std::clamp(options.max_concurrent_streams, {1}, settings_t::MAX_MAX_CONCURRENT_STREAMS);
  con->local_settings.initial_stream_window_size = MAX_WINDOW_SIZE;
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.2-2.10.2
  con->local_settings.max_frame_size = std::max(options.max_receive_frame_size, MIN_MAX_FRAME_LEN);
  con->local_settings.enable_connect_protocol = options.supports_websocket;
  con->local_settings.deprecated_priority_disabled = true;
  {
    std::vector<byte_t> bytes;
    settings_frame::form(con->local_settings, std::back_inserter(bytes));
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5-5
    // "The SETTINGS frames received from a peer as part of the connection
    // preface MUST be acknowledged after sending the connection preface" server
    // preface == settings
    accepted_settings_frame().form(std::back_inserter(bytes));
    co_await con->write(bytes, ec);
    if (ec) {
      HTTP2_LOG(con->logctx, ERROR,
                "client session establishment failed: cannot send ACK frame to client, err: {}",
                ec.message());
      throw network_exception(ec);
    }
  }
  // до момента ACK настроек от клиента нельзя создавать декодер с локально известными настройками, потому что
  // клиент может начать слать запросы с размером таблицы по умолчанию, что приведёт к ошибке
  // con->decoder = hpack::decoder(con->local_settings.header_table_size);
  // https://www.rfc-editor.org/rfc/rfc7541#section-4.2
  // кодировщик начинает с размера по умолчанию и сообщает новый размер в первом блоке заголовков
  if (con->encoder_table_size() != settings_t{}.header_table_size)
    con->encoder_table_size_changed();
  // client settings ACK will be handled by server reader

  HTTP2_LOG_TRACE(con->logctx, "client session successfully established");
  co_return con;
}

}  // namespace hidi
