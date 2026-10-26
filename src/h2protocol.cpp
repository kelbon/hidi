

#include "hidi/h2protocol.hpp"

#include "hidi/http_base.hpp"
#include "hidi/h2connection.hpp"

#include <hpack/hpack.hpp>
#include <strswitch/strswitch.hpp>

namespace hidi {

static void validate_initial_window_size(setting_t s) {
  assert(s.identifier == SETTINGS_INITIAL_WINDOW_SIZE);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.2-2.8.3
  if (s.value > MAX_WINDOW_SIZE) {
    throw protocol_error(errc_e::FLOW_CONTROL_ERROR,
                         std::format("SETTINGS_INITIAL_WINDOW_SIZE > max, max: {}, value: {}",
                                     MAX_WINDOW_SIZE, uint32_t(s.value)));
  }
}

static void validate_max_frame_size(setting_t s) {
  assert(s.identifier == SETTINGS_MAX_FRAME_SIZE);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.2-2.10.2

  // The value advertised by an endpoint MUST be between this initial value and the maximum
  // allowed frame size (2^24-1 or 16,777,215 octets), inclusive
  if (s.value < MIN_MAX_FRAME_LEN || s.value > 16'777'215) {
    throw protocol_error(
        errc_e::PROTOCOL_ERROR,
        std::format("invalid MAX_FRAME_SIZE, must be in range [16'384, 16`777`215], value: {}",
                    uint32_t(s.value)));
  }
}

static void validate_norfc7540_priority(setting_t s, bool firstframe, bool oldvalue) {
  assert(s.identifier == SETTINGS_NO_RFC7540_PRIORITIES);
  /*
Senders MUST NOT change the SETTINGS_NO_RFC7540_PRIORITIES value after the
first SETTINGS frame. Receivers that detect a change MAY treat it as a
connection error of type PROTOCOL_ERROR.
*/
  if (s.value > 1 || (!firstframe && s.value != oldvalue)) {
    throw protocol_error(
        errc_e::PROTOCOL_ERROR,
        "MUST NOT change the SETTINGS_NO_RFC7540_PRIORITIES value after the first SETTINGS frame");
  }
}

static void validate_enable_push_from_client(setting_t s) {
  assert(s.identifier == SETTINGS_ENABLE_PUSH);
  if (s.value > 1) {
    throw protocol_error(errc_e::PROTOCOL_ERROR,
                         std::format("invalid client settings enable_push value: {}", uint32_t(s.value)));
  }
}

static void validate_enable_connect_protocol_from_server(setting_t s) {
  assert(s.identifier == SETTINGS_ENABLE_CONNECT_PROTOCOL);
  if (s.value > 1) {
    throw protocol_error(
        errc_e::PROTOCOL_ERROR,
        std::format("invalid server SETTINGS_ENABLE_CONNECT_PROTOCOL value: {}", uint32_t(s.value)));
  }
}

static void validate_enable_connect_protocol_from_client(setting_t s) {
  assert(s.identifier == SETTINGS_ENABLE_CONNECT_PROTOCOL);
  if (s.value > 0) {
    throw protocol_error(
        errc_e::PROTOCOL_ERROR,
        std::format("invalid client SETTINGS_ENABLE_CONNECT_PROTOCOL value: {}", uint32_t(s.value)));
  }
}

static void validate_enable_push_from_server(setting_t s) {
  assert(s.identifier == SETTINGS_ENABLE_PUSH);
  // server MUST NOT send i
  if (s.value > 0) {
    throw protocol_error(errc_e::PROTOCOL_ERROR,
                         std::format("invalid server settings enable push, value: {}", uint32_t(s.value)));
  }
}

static void validate_rst_stream(const frame_header& h) {
  assert(h.type == frame_e::RST_STREAM);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.4-6
  if (h.streamid == 0) {
    throw protocol_error(errc_e::PROTOCOL_ERROR,
                         std::format("RST_STREAM frame with streamid == 0 ({})", h.streamid));
  }
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.4-8
  if (h.length != 4) {
    throw protocol_error(errc_e::FRAME_SIZE_ERROR,
                         std::format("RST_STREAM frame with invalid len != 4 ({})", h.length));
  }
}

static void validate_ping(const frame_header& h) {
  assert(h.type == frame_e::PING);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.7-8
  if (h.streamid != 0) {
    throw protocol_error(errc_e::PROTOCOL_ERROR,
                         std::format("PING frame with streamid != 0 ({})", h.streamid));
  }
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.7-9
  if (h.length != 8) {
    throw protocol_error(errc_e::FRAME_SIZE_ERROR,
                         std::format("PING frame with invalid len != 8 ({})", h.length));
  }
}

static void validate_goaway(const frame_header& h) {
  assert(h.type == frame_e::GOAWAY);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8-11
  if (h.streamid != 0) {
    throw protocol_error(errc_e::PROTOCOL_ERROR,
                         std::format("GOAWAY frame with streamid != 0 ({})", h.streamid));
  }
  // must be atleast last stream id and error code both 32 bit
  if (h.length < 8) {
    throw protocol_error(errc_e::FRAME_SIZE_ERROR,
                         std::format("GOAWAY frame with invalid len < 8 ({})", h.length));
  }
}

static void validate_window_update(const frame_header& h) {
  assert(h.type == frame_e::WINDOW_UPDATE);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9-12
  if (h.length != 4) {
    throw protocol_error(errc_e::FRAME_SIZE_ERROR,
                         std::format("invalid WINDOW_UPDATE len != 4 ({})", h.length));
  }
}

static void validate_window_update_increment(const frame_header& h, cfint_t increment) {
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9-6
  if (increment >= cfint_t(1u << 31)) {
    throw protocol_error(errc_e::FLOW_CONTROL_ERROR,
                         std::format("invalid frame {}, window size increment too big ({})", h, increment));
  }
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9-9
  // (but now both stream and connection related errors are connection error, not stream error)
  if (increment == 0) {
    if (h.streamid != 0) {
      throw stream_error(errc_e::PROTOCOL_ERROR, h.streamid,
                         std::format("invalid window update frame, increment == 0"));
    } else {
      throw protocol_error(
          errc_e::PROTOCOL_ERROR,
          std::format("invalid window update frame, increment == 0, streamid == 0", h.streamid));
    }
  }
}

std::string_view e2str(frame_e e) noexcept {
  switch (e) {
    case frame_e::DATA:
      return "DATA";
    case frame_e::HEADERS:
      return "HEADERS";
    case frame_e::PRIORITY:
      return "PRIORITY";
    case frame_e::RST_STREAM:
      return "RST_STREAM";
    case frame_e::SETTINGS:
      return "SETTINGS";
    case frame_e::PUSH_PROMISE:
      return "PUSH_PROMISE";
    case frame_e::PING:
      return "PING";
    case frame_e::GOAWAY:
      return "GOAWAY";
    case frame_e::WINDOW_UPDATE:
      return "WINDOW_UPDATE";
    case frame_e::CONTINUATION:
      return "CONTINUATION";
    case frame_e::PRIORITY_UPDATE:
      return "PRIORITY_UPDATE";
  }
  return "UNKNOWN_FRAME";
}

void server_settings_visitor::operator()(setting_t s) {
  switch (s.identifier) {
    case SETTINGS_HEADER_TABLE_SIZE:
      settings.header_table_size = s.value;
      return;
    case SETTINGS_ENABLE_PUSH:
      validate_enable_push_from_server(s);
      settings.enable_push = s.value;
      return;
    case SETTINGS_MAX_CONCURRENT_STREAMS:
      settings.max_concurrent_streams = s.value;
      return;
    case SETTINGS_INITIAL_WINDOW_SIZE:
      validate_initial_window_size(s);
      settings.initial_stream_window_size = s.value;
      return;
    case SETTINGS_MAX_FRAME_SIZE:
      validate_max_frame_size(s);
      settings.max_frame_size = s.value;
      return;
    case SETTINGS_MAX_HEADER_LIST_SIZE:
      settings.max_header_list_size = s.value;
      return;
    case SETTINGS_ENABLE_CONNECT_PROTOCOL:
      validate_enable_connect_protocol_from_server(s);
      settings.enable_connect_protocol = s.value;
      return;
    case SETTINGS_NO_RFC7540_PRIORITIES:
      validate_norfc7540_priority(s, firstframe, settings.deprecated_priority_disabled);
      settings.deprecated_priority_disabled = s.value;
      return;
    default:
        // ignore if dont know
        ;
  }
}

void client_settings_visitor::operator()(setting_t s) {
  switch (s.identifier) {
    case SETTINGS_HEADER_TABLE_SIZE:
      settings.header_table_size = s.value;
      return;
    case SETTINGS_ENABLE_PUSH:
      validate_enable_push_from_client(s);
      settings.enable_push = s.value;
      return;
    case SETTINGS_MAX_CONCURRENT_STREAMS:
      settings.max_concurrent_streams = s.value;
      return;
    case SETTINGS_INITIAL_WINDOW_SIZE:
      validate_initial_window_size(s);
      settings.initial_stream_window_size = s.value;
      return;
    case SETTINGS_MAX_FRAME_SIZE:
      validate_max_frame_size(s);
      settings.max_frame_size = s.value;
      return;
    case SETTINGS_MAX_HEADER_LIST_SIZE:
      settings.max_header_list_size = s.value;
      return;
    case SETTINGS_ENABLE_CONNECT_PROTOCOL:
      validate_enable_connect_protocol_from_client(s);
      settings.enable_connect_protocol = s.value;
      return;
    case SETTINGS_NO_RFC7540_PRIORITIES:
      validate_norfc7540_priority(s, firstframe, settings.deprecated_priority_disabled);
      settings.deprecated_priority_disabled = s.value;
      return;
    default:
        // ignore if dont know
        ;
  }
}

rst_stream rst_stream::parse(frame_header h, std::span<const byte_t> bytes) {
  validate_rst_stream(h);
  assert(h.length == bytes.size());

  rst_stream frame(h);
  memcpy(&frame.error_code, bytes.data(), 4);
  htonli(frame.error_code);
  return frame;
}

ping_frame ping_frame::parse(frame_header h, std::span<const byte_t> bytes) {
  validate_ping(h);
  assert(h.length == bytes.size());

  ping_frame f(h);
  memcpy(f.data, bytes.data(), 8);
  return f;
}

goaway_frame goaway_frame::parse(frame_header header, std::span<const byte_t> bytes) {
  validate_goaway(header);
  assert(header.length == bytes.size());

  goaway_frame frame;
  memcpy(&frame.last_streamid, bytes.data(), 4);
  memcpy(&frame.error_code, bytes.data() + 4, 4);
  htonli(frame.last_streamid);
  htonli(frame.error_code);
  // игнорирование зарезервированного бита
  frame.last_streamid &= stream_id_t(0x7FFFFFFF);
  frame.debug_info =
      std::string_view((const char*)bytes.data() + 8, (const char*)bytes.data() + bytes.size());
  return frame;
}

window_update_frame window_update_frame::parse(frame_header header, std::span<const byte_t> bytes) {
  assert(header.length == bytes.size());
  validate_window_update(header);

  window_update_frame frame{.header = header};
  std::memcpy(&frame.window_size_increment, bytes.data(), 4);
  htonli(frame.window_size_increment);
  // игнорирование зарезервированного бита
  frame.window_size_increment &= uint32_t(0x7FFFFFFF);
  validate_window_update_increment(header, frame.window_size_increment);
  return frame;
}

// its protocol error, because client encoder somehow encoded headers
// and we throw error BEFORE decode all headers. So, we must end connection
// before our decoder will be in not same state as client`s encoder
// otherwise we may see incorrect headers(indexes) in following requests
static protocol_error duplicated_pseudoheader(std::string_view name) {
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3-5
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1-3
  // Malformed requests or responses that are detected MUST be treated
  // as a stream error (Section 5.4.2) of type PROTOCOL_ERROR.
  return protocol_error(errc_e::PROTOCOL_ERROR,
                        std::format("pseudoheader {} appeared on the list twice", name));
}

std::optional<std::string> validate_header_name(std::string_view str, std::string_view value) {
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1-3.1
  for (unsigned char c : str) {
    switch (c) {
      default:
        continue;
      case 0x00 ... 0x20:
      case 0x41 ... 0x5a:
      case 0x7f ... 0xff:
      case ':':
        // websocket, handled here for better hot path
        if (str != ":protocol") {
          return std::format("forbidden character 0x{:x} in header name \"{}\")", c, str);
        }
    }
  }
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2-1
  bool connection_specific =
      ss::string_switch<bool>(str)
          .cases("te", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", true)
          .or_default(false);
  if (connection_specific) [[unlikely]] {
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2-2
    if (str != "te")
      return std::format("connection specific header forbidden in HTTP/2, header name: {}", str);
    if (value != "trailers")
      return std::format("TE header with value other than \"trailers\", actual value: {}", value);
  }
  return std::nullopt;
}

// эта функция должна гарантировать что обработала все хедера, либо бросила protocol_error (GOAWAY)
// иначе декодер окажется в невалидном состоянии
void parse_http2_request_headers(h2stream& s, std::span<const hpack::byte_t> bytes) {
  const auto* in = bytes.data();
  const auto* e = in + bytes.size();
  hpack::header_view header;

  // parse required pseudoheaders
  http_request& req = s.req;
  hpack::decoder& d = s.connection->decoder;
  bool scheme_parsed = false;
  bool path_parsed = false;
  bool method_parsed = false;
  bool authority_parsed = false;
  bool contenttype_parsed = false;

  auto checkrequired = [&](std::string_view hdrname, bool parsed) {
    if (!parsed) [[unlikely]] {
      throw stream_error(errc_e::PROTOCOL_ERROR, s.streamid,
                         std::format("required header {} not present", hdrname));
    }
  };

  while (in != e) {
    d.decode_header(in, e, header);
    if (!header)  // skip dynamic size updates
      continue;
    std::string_view hval = header.value.str();
    if (header.name == ":path") {
      if (path_parsed)
        throw duplicated_pseudoheader(":path");
      path_parsed = true;
      if (!s.use_bytes(hval.size())) [[unlikely]]
        goto memory_limit_exceeded;
      req.path = hval;
      if (req.path.empty())
        throw protocol_error(errc_e::PROTOCOL_ERROR, ":path header is empty");
    } else if (header.name == ":method") {
      if (method_parsed)
        throw duplicated_pseudoheader(":method");
      method_parsed = true;
      if (!s.use_bytes(hval.size())) [[unlikely]]
        goto memory_limit_exceeded;
      (void)efromstr(hval, req.method);
    } else if (header.name == ":scheme") {
      if (scheme_parsed)
        throw duplicated_pseudoheader(":scheme");
      scheme_parsed = true;
      if (!s.use_bytes(hval.size())) [[unlikely]]
        goto memory_limit_exceeded;
      (void)efromstr(hval, req.scheme);
    } else if (header.name == ":authority") {
      if (authority_parsed)
        throw duplicated_pseudoheader(":authority");
      authority_parsed = true;
      if (!s.use_bytes(hval.size())) [[unlikely]]
        goto memory_limit_exceeded;
      req.authority = hval;
    } else if (header.name == "content-type") {
      if (contenttype_parsed)
        throw duplicated_pseudoheader("content-type");
      contenttype_parsed = true;
      if (!s.use_bytes(hval.size())) [[unlikely]]
        goto memory_limit_exceeded;
      req.body.content_type = hval;
    } else if (header.name == ":protocol") {  // RFC 8441: Extended CONNECT
      if (!s.use_bytes(hval.size())) [[unlikely]]
        goto memory_limit_exceeded;
      req.headers.push_back(http_header_t(":protocol", std::string(hval)));
    } else {
      goto push_header;
    }
  }
  while (in != e) {
    d.decode_header(in, e, header);
    if (!header)
      continue;
  push_header:
    if (std::optional<std::string> err = validate_header_name(header.name.str(), header.value.str())) {
      hpack::ignore_headers_block(d, in, e);
      throw stream_error(errc_e::PROTOCOL_ERROR, s.streamid, std::move(*err));
    }
    if (!s.use_bytes(header.name.str().size() + header.value.str().size())) [[unlikely]]
      goto memory_limit_exceeded;
    req.headers.push_back(http_header_t(std::string(header.name.str()), std::string(header.value.str())));
  }

  checkrequired(":method", method_parsed);
  if (req.method != http_method_e::CONNECT) [[likely]] {
    checkrequired(":path", path_parsed);
    checkrequired(":scheme", scheme_parsed);
  }
  // authority not checked, since its possible to not receive authority (client not required to sent it)
  return;
memory_limit_exceeded:
  HTTP2_LOG(s.logctx(), WARN, "memory limit exceeded while parsing http request for stream {}", s.streamid);
  hpack::ignore_headers_block(d, in, e);
  throw stream_error(errc_e::ENHANCE_YOUR_CALM, s.streamid,
                     "memory limit exceeded when parsing request headers");
}

}  // namespace hidi
