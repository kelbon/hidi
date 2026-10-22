#include "test_connection.hpp"

#include <source_location>
#include <utility>

#include <format>

#include "hidi/logger.hpp"

#include "fuzzer.hpp"

#define FAKE_HTTP2_LOG(TYPE, STR, ...)       \
  HTTP2_LOG(this->con->logctx, TYPE,         \
            STR                              \
            " in {} "                        \
            "{}" __VA_OPT__(, ) __VA_ARGS__, \
            __func__, "[FAKE]")

namespace hidi {

std::string sourceloc_str(std::source_location loc) {
  return std::format("{}:{}:{}", loc.file_name(), loc.line(), loc.column());
}

void remove_padding_etc(h2test_frame& f) {
  assert(f.hdr.type == frame_e::HEADERS || f.hdr.type == frame_e::DATA);
  h2frame frame(f.hdr, f.data);
  REQUIRE_NOTHROW(frame.validate_streamid(), frame.remove_padding());
  if (f.hdr.type == frame_e::HEADERS)
    frame.ignore_deprecated_priority();
  if (f.data.size() != frame.data.size()) {
    f.hdr = frame.header;
    f.data.assign(frame.data.begin(), frame.data.end());
  }
}

}  // namespace hidi

namespace hidi {

test_h2connection::test_h2connection(h2connection_ptr ccon, bool client) noexcept
    : con(std::move(ccon)), is_client_con(client) {
  if (is_client())
    con->logctx.name.set_prefix(CLIENT_CONNECTION_PREFIX);
  else
    con->logctx.name.set_prefix(SERVER_SESSION_PREFIX);
}

dd::task<void> test_h2connection::receive_goaway(stream_id_t last_streamid, errc_e error_code, ping_e ping,
                                                 deadline_t deadline, std::source_location loc) {
  FAKE_HTTP2_LOG(INFO, "");

  h2test_frame f = co_await next_frame(deadline, ping, window_e::SKIP, loc);
  REQUIRE(f.hdr.type == frame_e::GOAWAY);
  goaway_frame gf;
  REQUIRE_NOTHROW(gf = goaway_frame::parse(f.hdr, f.data));
  REQUIRE(gf.error_code == error_code);
  REQUIRE(gf.last_streamid == last_streamid);
}

dd::task<void> test_h2connection::send_goaway(stream_id_t last_streamid, errc_e errc,
                                              std::string_view debug_info) {
  FAKE_HTTP2_LOG(INFO, "");

  std::vector<byte_t> bytes;
  goaway_frame::form(last_streamid, errc, std::string(debug_info), std::back_inserter(bytes));

  return send_raw_frame(std::move(bytes));
}

dd::task<void> test_h2connection::send_rst_stream(stream_id_t streamid, errc_e errc) {
  FAKE_HTTP2_LOG(INFO, "");

  std::vector<byte_t> bytes;
  rst_stream::form(streamid, errc, std::back_inserter(bytes));

  return send_raw_frame(std::move(bytes));
}

dd::task<void> test_h2connection::receive_rst_stream(stream_id_t streamid, errc_e error, deadline_t deadline,
                                                     std::source_location sl) {
  FAKE_HTTP2_LOG(INFO, "");

  h2test_frame f = co_await next_frame(deadline, ping_e::RESPONSE, window_e::SKIP, sl);

  REQUIRE(f.hdr.type == frame_e::RST_STREAM);
  REQUIRE(f.hdr.streamid == streamid);
  rst_stream rf;
  REQUIRE_NOTHROW(rf = rst_stream::parse(f.hdr, f.data));
  REQUIRE(rf.error_code == error);
}

dd::task<void> test_h2connection::receive_settings_ack(deadline_t deadline, std::source_location loc) {
  h2test_frame f = co_await next_frame(deadline, ping_e::RESPONSE, window_e::RETURN, loc);

  REQUIRE(f.hdr.type == frame_e::SETTINGS);
  REQUIRE(f.hdr.flags & flags::ACK);
}

dd::task<void> test_h2connection::send_settings_ack() {
  return send_frame({accepted_settings_frame()});
}

dd::task<h2test_frame> test_h2connection::receive_settings(deadline_t deadline, std::source_location loc) {
  FAKE_HTTP2_LOG(INFO, "");

  h2test_frame f = co_await next_frame(deadline, ping_e::RESPONSE, window_e::RETURN, loc);

  // for test purpose apply settings before receiving ACK to make code easier
  settings_frame::parse(f.hdr, f.data, [&](setting_t s) {
    if (s.identifier == SETTINGS_HEADER_TABLE_SIZE) {
      assert(con->encoder.dyntab.current_size() == 0 && "receiving settings when connection already used");
      con->encoder.dyntab.set_user_protocol_max_size(s.value);
    }
  });
  REQUIRE(f.hdr.type == frame_e::SETTINGS);
  REQUIRE(!(f.hdr.flags & flags::ACK));

  co_return f;
}

dd::task<void> test_h2connection::receive_and_check_settings(std::map<setting_id_e, stream_id_t> expected,
                                                             std::set<setting_id_e> unexpected,
                                                             deadline_t deadline, std::source_location loc) {
  h2test_frame f = co_await receive_settings(deadline, loc);

  settings_frame::parse(f.hdr, f.data, [&](setting_t s) {
    if (expected.contains(s.identifier)) {
      REQUIRE(expected.at(s.identifier) == s.value);
      expected.erase(s.identifier);
    }
    REQUIRE(!unexpected.contains(s.identifier));
  });

  REQUIRE(expected.empty());
}

dd::task<void> test_h2connection::send_settings() {
  FAKE_HTTP2_LOG(INFO, "");

  settings_t settings;
  settings.max_concurrent_streams = 0x7fffffff;
  settings.max_frame_size = m_maxFrameSize;
  settings.deprecated_priority_disabled = true;
  if (m_headerTabSize.has_value())
    settings.header_table_size = *m_headerTabSize;

  std::vector<byte_t> bytes;
  settings_frame::form(settings, std::back_inserter(bytes));

  return send_raw_frame(std::move(bytes));
}

dd::task<uint64_t> test_h2connection::receive_ping(deadline_t deadline, std::source_location loc) {
  FAKE_HTTP2_LOG(INFO, "");

  h2test_frame f;
  for (;;) {
    f = co_await receive_frame(deadline, loc);
    switch (f.hdr.type) {
      case frame_e::WINDOW_UPDATE:
        continue;
      case frame_e::PING:
        goto end;
      default:
        FAIL(std::format("unexpected frame {}, loc: {}", f.hdr, sourceloc_str(loc)));
    }
  }
end:
  ping_frame pf;
  REQUIRE_NOTHROW(pf = ping_frame::parse(f.hdr, f.data));
  REQUIRE(!(f.hdr.flags & flags::ACK));

  co_return pf.get_data();
}

dd::task<void> test_h2connection::send_ping(uint64_t opaque_data) {
  FAKE_HTTP2_LOG(INFO, "");
  std::vector<byte_t> bytes;
  ping_frame::form(opaque_data, /*request_answer=*/true, std::back_inserter(bytes));
  return send_raw_frame(std::move(bytes));
}

dd::task<void> test_h2connection::send_pong(uint64_t opaque_data) {
  FAKE_HTTP2_LOG(INFO, "");
  std::vector<byte_t> bytes;
  ping_frame::form(opaque_data, /*request_answer=*/false, std::back_inserter(bytes));
  return send_raw_frame(std::move(bytes));
}

dd::task<h2test_frame> test_h2connection::receive_data(stream_id_t streamid, deadline_t deadline) {
  FAKE_HTTP2_LOG(INFO, "");

  h2test_frame f = co_await next_frame(deadline, ping_e::RESPONSE, window_e::SKIP);

  REQUIRE(f.hdr.type == frame_e::DATA);
  if (streamid)
    REQUIRE(f.hdr.streamid == streamid);
  remove_padding_etc(f);

  co_return f;
}

dd::task<hdrs_and_data> test_h2connection::receive_req(deadline_t deadline, std::source_location loc) {
  FAKE_HTTP2_LOG(INFO, "");
  hdrs_and_data hd;
  h2test_frame f = co_await next_frame(deadline, ping_e::RESPONSE, window_e::SKIP, loc);
  REQUIRE(f.hdr.type == frame_e::HEADERS);
  REQUIRE(f.hdr.flags & flags::END_HEADERS);
  hd.streamid = f.hdr.streamid;
  remove_padding_etc(f);

  auto decode_headers = [&](std::span<const byte_t> input, std::vector<header>& out) {
    hpack::decode_headers_block(con->decoder, input, [&](std::string_view name, std::string_view value) {
      out.push_back(
          {std::string(name), std::string(value), con->decoder.dyntab.find(name, value).value_indexed});
    });
  };

  decode_headers(std::span(f.data.begin(), f.data.end()), hd.headers);
  hd.end_stream = f.hdr.flags & flags::END_STREAM;

  if (!hd.end_stream) {
    f = co_await next_frame(deadline, ping_e::RESPONSE, window_e::SKIP, loc);
    if (f.hdr.type == frame_e::HEADERS) {
      // трейлеры после хедеров
      decode_headers(std::span(f.data.begin(), f.data.end()), hd.trailers.emplace());
      hd.end_stream = f.hdr.flags & flags::END_STREAM;
      REQUIRE(hd.end_stream == true);
      REQUIRE(f.hdr.streamid == hd.streamid);
    } else {
      REQUIRE(f.hdr.type == frame_e::DATA);
      REQUIRE(hd.streamid == f.hdr.streamid);
      hd.body = std::move(f.data);
      hd.end_stream = f.hdr.flags & flags::END_STREAM;
      if (!hd.end_stream) {
        // трейлеры после данных
        f = co_await next_frame(deadline, ping_e::RESPONSE, window_e::SKIP, loc);
        REQUIRE(f.hdr.type == frame_e::HEADERS);
        REQUIRE(f.hdr.streamid == hd.streamid);
        decode_headers(std::span(f.data.begin(), f.data.end()), hd.trailers.emplace());
        hd.end_stream = f.hdr.flags & flags::END_STREAM;
        REQUIRE(hd.end_stream == true);
      }
    }
  }

  co_return hd;
}

dd::task<std::unordered_map<stream_id_t, hdrs_and_data>> test_h2connection::receive_streams(
    size_t count, deadline_t deadline, std::source_location loc) {
  FAKE_HTTP2_LOG(INFO, "");

  auto decode_headers = [&](std::span<const byte_t> input, std::vector<header>& out) {
    hpack::decode_headers_block(con->decoder, input, [&](std::string_view name, std::string_view value) {
      out.push_back(
          {std::string(name), std::string(value), con->decoder.dyntab.find(name, value).value_indexed});
    });
  };

  std::unordered_map<stream_id_t, hdrs_and_data> pending;
  std::unordered_map<stream_id_t, hdrs_and_data> done;

  while (done.size() < count) {
    h2test_frame f =
        co_await next_frame(deadline, ping_e::RESPONSE, window_e::SKIP, loc, /*answer_window_update=*/true);
    stream_id_t streamid = f.hdr.streamid;
    remove_padding_etc(f);

    auto it = pending.find(streamid);

    if (it == pending.end()) {
      // Новый стрим обязан начинаться с HEADERS (уже завершённые
      // стримы повторно появляться не должны).
      REQUIRE(!done.contains(streamid));
      REQUIRE(f.hdr.type == frame_e::HEADERS);
      REQUIRE(f.hdr.flags & flags::END_HEADERS);

      hdrs_and_data hd;
      hd.streamid = streamid;
      decode_headers(std::span(f.data.begin(), f.data.end()), hd.headers);
      hd.end_stream = f.hdr.flags & flags::END_STREAM;

      if (hd.end_stream)
        done.emplace(streamid, std::move(hd));
      else
        pending.emplace(streamid, std::move(hd));
      continue;
    }

    hdrs_and_data& hd = it->second;

    if (f.hdr.type == frame_e::HEADERS) {
      // трейлеры
      REQUIRE(f.hdr.flags & flags::END_HEADERS);
      decode_headers(std::span(f.data.begin(), f.data.end()), hd.trailers.emplace());
      hd.end_stream = f.hdr.flags & flags::END_STREAM;
      REQUIRE(hd.end_stream == true);
      done.emplace(streamid, std::move(hd));
      pending.erase(it);
    } else {
      REQUIRE(f.hdr.type == frame_e::DATA);
      hd.body.insert(hd.body.end(), f.data.begin(), f.data.end());
      hd.end_stream = f.hdr.flags & flags::END_STREAM;
      if (hd.end_stream) {
        done.emplace(streamid, std::move(hd));
        pending.erase(it);
      }
    }
  }

  co_return done;
}

dd::task<void> test_h2connection::send_rsp(stream_id_t streamid, std::vector<header> headers,
                                           http_body_bytes body, bool endstream) {
  FAKE_HTTP2_LOG(INFO, "");
  h2test_frame hdrs;

  for (auto&& [name, value, _] : headers)
    con->encoder.encode(name, value, std::back_inserter(hdrs.data));
  // hope hdrs size < max frame size in tests
  hdrs.hdr.length = uint32_t(hdrs.data.size());
  hdrs.hdr.flags = flags::END_HEADERS;
  hdrs.hdr.type = frame_e::HEADERS;
  hdrs.hdr.streamid = streamid;
  if (body.empty() && endstream)
    hdrs.hdr.flags |= flags::END_STREAM;
  co_await send_frame(std::move(hdrs));
  if (body.empty())
    co_return;
  h2test_frame data;
  REQUIRE(body.size() <= FRAME_LEN_MAX);
  data.hdr.length = stream_id_t(body.size());
  data.hdr.type = frame_e::DATA;
  if (endstream)
    data.hdr.flags = flags::END_STREAM;
  data.hdr.streamid = streamid;
  data.data = std::move(body);
  co_await send_frame(std::move(data));
}

dd::task<void> test_h2connection::send_headers(stream_id_t streamid, std::vector<header> headers,
                                               bool endstream) {
  FAKE_HTTP2_LOG(INFO, "");
  // reuse `send_req`, which will only send one HEADERS frame
  return send_rsp(streamid, std::move(headers), {}, endstream);
}

dd::task<void> test_h2connection::send_req(stream_id_t streamid, std::vector<header> headers,
                                           http_body_bytes body, bool endstream) {
  REQUIRE(is_client());
  return send_rsp(streamid, std::move(headers), std::move(body), endstream);
}

dd::task<void> test_h2connection::send_raw_hdr(stream_id_t streamid, std::span<const byte_t> headers,
                                               bool end_stream, bool split) {
  FAKE_HTTP2_LOG(INFO, "");
  if (split) {
    fuzzing::fuzzer fuz;
    bool first = true;
    for (std::span chunk : fuz.chunks(headers)) {
      h2test_frame f;
      f.hdr.length = uint32_t(chunk.size());
      f.hdr.streamid = streamid;
      f.hdr.type = first ? frame_e::HEADERS : frame_e::CONTINUATION;
      if (first && end_stream)
        f.hdr.flags |= flags::END_STREAM;
      // stuped msvc stl asserts when comparting iterators from different spans
      // even if they are to same array
      //  chunk.end() == headers.end()
      if (chunk.data() + chunk.size() == headers.data() + headers.size())  // last chunk
        f.hdr.flags |= flags::END_HEADERS;
      first = false;
      f.data.assign(chunk.begin(), chunk.end());

      co_await send_frame(std::move(f));
    }
  } else {  // !split
    h2test_frame f;
    f.hdr.length = uint32_t(headers.size());
    f.hdr.type = frame_e::HEADERS;
    f.hdr.flags = flags::END_HEADERS;
    f.hdr.streamid = streamid;
    if (end_stream)
      f.hdr.flags |= flags::END_STREAM;
    f.data.assign(headers.begin(), headers.end());

    co_await send_frame(std::move(f));
  }
}

dd::task<void> test_h2connection::send_raw_continuation(stream_id_t streamid, std::span<byte_t> headers,
                                                        bool end_headers) {
  FAKE_HTTP2_LOG(INFO, "");
  h2test_frame f;
  f.hdr = {
      .length = uint32_t(headers.size()),
      .type = frame_e::CONTINUATION,
      .flags = end_headers ? flags::END_HEADERS : flags::EMPTY_FLAGS,
      .streamid = streamid,
  };
  f.data.assign(headers.begin(), headers.end());

  co_await send_frame(std::move(f));
}

std::vector<byte_t> test_h2connection::encode_headers(std::vector<header> hdrs) {
  std::vector<byte_t> bytes;
  for (auto& h : hdrs)
    if (h.indexed)
      con->encoder.encode</*Cache=*/true>(h.name, h.value, std::back_inserter(bytes));
    else
      con->encoder.encode_header_without_indexing(h.name, h.value, std::back_inserter(bytes));
  return bytes;
}

dd::task<void> test_h2connection::send_data(stream_id_t streamid, std::string_view body, bool end_stream) {
  FAKE_HTTP2_LOG(INFO, "");

  uint32_t body_size = static_cast<uint32_t>(body.size());
  REQUIRE(body_size);  // check data
  h2test_frame f;
  f.hdr.type = frame_e::DATA;
  f.hdr.length = uint32_t(body.size());
  f.hdr.streamid = streamid;
  f.hdr.flags = end_stream ? flags::END_STREAM : flags::EMPTY_FLAGS;
  f.data.assign(body.begin(), body.end());
  return send_frame(std::move(f));
}

dd::task<void> test_h2connection::send_window_size_increment(stream_id_t streamid, uint32_t increment) {
  FAKE_HTTP2_LOG(INFO, "");

  std::vector<byte_t> bytes;
  window_update_frame::form(streamid, increment, std::back_inserter(bytes));

  return send_raw_frame(std::move(bytes));
}

dd::task<h2test_frame> test_h2connection::next_frame(deadline_t d, ping_e pingbehavior,
                                                     window_e windowbehavior, std::source_location loc,
                                                     bool answer_window_update) {
  FAKE_HTTP2_LOG(INFO, "");
  do {
    h2test_frame frame;

    frame = co_await receive_frame(d, loc);

    if (frame.hdr.type == frame_e::PING) {
      switch (pingbehavior) {
        case ping_e::RESPONSE:
          if (!(frame.hdr.flags & flags::ACK)) {
            frame.hdr.flags &= flags::ACK;
            co_await send_frame(std::move(frame));
          }
          continue;
        case ping_e::ERROR:
          FAIL("Ping frame received, but not expected");
          unreachable();
        default:
          FAIL("invalid ping_e");
          unreachable();
      }
    } else if (frame.hdr.type == frame_e::WINDOW_UPDATE) {
      switch (windowbehavior) {
        case window_e::RETURN:
          co_return frame;
        case window_e::SKIP:
          // ignores control flow etc
          continue;
      }
    } else {
      if (answer_window_update && frame.hdr.type == frame_e::DATA) {
        // соединение
        co_await send_window_size_increment(0, frame.hdr.length);
        // поток
        co_await send_window_size_increment(frame.hdr.streamid, frame.hdr.length);
      }
      co_return frame;
    }
  } while (true);
}

dd::task<void> test_h2connection::receive_client_magic(std::source_location) {
  FAKE_HTTP2_LOG(INFO, "");
  byte_t buf[sizeof(CONNECTION_PREFACE)];
  io_error_code ec;
  co_await con->read(buf, ec);
  REQUIRE(!ec);
  REQUIRE(memcmp(buf, CONNECTION_PREFACE, sizeof(CONNECTION_PREFACE)) == 0);
}

dd::task<void> test_h2connection::send_frame(h2test_frame frame) {
  FAKE_HTTP2_LOG(INFO, "sending frame {}", frame.hdr);
  assert(frame.data.size() == frame.hdr.length);
  if (frame.data.capacity() == 0)
    frame.data.reserve(1);  // force use special allocator p9
  auto* b = frame.data.data() - FRAME_HEADER_LEN;
  frame.hdr.form(b);
  io_error_code ec;
  if (frame.data.size() == 0)
    co_await con->write({b, FRAME_HEADER_LEN}, ec);
  else
    co_await con->write({b, frame.data.data() + frame.data.size()}, ec);
  REQUIRE(!ec);
}

dd::task<void> test_h2connection::send_raw_frame(std::vector<byte_t> bytes) {
  FAKE_HTTP2_LOG(INFO, "sending raw frame: {} bytes", bytes.size());
  io_error_code ec;
  co_await con->write(bytes, ec);
}

dd::task<h2test_frame> test_h2connection::receive_frame(deadline_t d, std::source_location loc) {
  bool done = false;  // avoid dangling

  auto f = [&](test_h2connection& self) -> dd::task<h2test_frame> {
    on_scope_exit {
      done = true;
    };
    h2test_frame frame;
    std::array<byte_t, FRAME_HEADER_LEN> hdr;
    io_error_code ec;
    co_await self.con->read(hdr, ec);
    REQUIRE(!ec);
    frame.hdr = frame_header::parse(hdr);
#ifdef HTTP2_ENABLE_TRACE
    if (frame.hdr.type != frame_e::GOAWAY)
      FAKE_HTTP2_LOG(TRACE, "receive frame: {}", frame.hdr);
#endif
    REQUIRE(frame.hdr.length <= self.m_maxFrameSize);
    frame.data.resize(frame.hdr.length);
    co_await self.con->read(frame.data, ec);
    REQUIRE(!ec);
#ifdef HTTP2_ENABLE_TRACE
    if (frame.hdr.type == frame_e::GOAWAY) {
      auto gf = goaway_frame::parse(frame.hdr, frame.data);
      FAKE_HTTP2_LOG(TRACE, "receive GOAWAY frame, ec: {}, debug_info: {}", e2str(gf.error_code),
                     gf.debug_info);
    }
#endif
    co_return frame;
  };
  any_timer timer = con->ioctx.create_timer();
  timer.arm(d);
  timer.set_callback([&](bool canceled) {
    if (canceled)
      return;
    FAKE_HTTP2_LOG(ERROR, "receive_frame: deadline reached {}", sourceloc_str(loc));
    con->shutdown(reqerr_e::TIMEOUT);
  });
  h2test_frame res = co_await f(*this);
  timer.cancel();
  co_return res;
}

dd::task<void> test_h2connection::send_client_magic() {
  FAKE_HTTP2_LOG(INFO, "");
  io_error_code ec;
  co_await con->write(CONNECTION_PREFACE, ec);
  REQUIRE(!ec);
}

dd::task<void> test_h2connection::wait_connection_dropped(deadline_t deadline, std::source_location loc) {
  FAKE_HTTP2_LOG(INFO, "");
  any_timer timer = con->ioctx.create_timer();
  timer.arm(deadline);
  bool timedout = false;
  timer.set_callback([&](bool canceled) {
    if (!canceled) {
      timedout = true;
      con->shutdown(reqerr_e::TIMEOUT);
    }
  });
  io_error_code ec;
  byte_t buf[512];
  while (!ec && !timedout)
    co_await con->read(buf, ec);
  REQUIRE(!timedout);
}

void test_h2connection::close() {
  if (con) {
    FAKE_HTTP2_LOG(INFO, "");
    con->shutdown(reqerr_e::values_e::CANCELLED);
  }
}

}  // namespace hidi
