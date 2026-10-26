#include "hidi/request_context.hpp"

#include "hidi/h2connection.hpp"

namespace hidi {

stream_id_t request_context::streamid() const noexcept {
  return node->streamid;
}

bool request_context::canceled() const noexcept {
  return node->canceled_by_rststream || node->connection->is_dropped();
}

http_response request_context::stream_response(int status, http_headers_t hdrs,
                                               stream_body_maker_t makebody) {
  assert(status > 0);
  assert(makebody);
  assert(node);
  http_response rsp;
  rsp.status = status;
  rsp.headers = std::move(hdrs);
  node->makebody = std::move(makebody);

  return rsp;
}

dd::task<void> request_context::send_interim_response(int status, http_headers_t hdrs) {
  assert(status >= 100 && status <= 199);
  assert(node);
  if (!node->connection)
    co_return;
  HTTP2_LOG_TRACE(node->connection->logctx, "sending interim response with status {}", status);
  HIDI_WAIT_WRITE(*node->connection);
  bytes_t bytes(FRAME_HEADER_LEN);
  node->connection->start_headers_block(*node, /*force_disable_hpack=(unknown here)*/ false, bytes);
  auto out = std::back_inserter(bytes);
  auto& encoder = node->connection->encoder;
  encoder.encode_status(status, out);
  // ignore if CONTINUATION required (hope no one will send such a big interim, hope even no one use
  // send_interim_response not in tests)
  for (auto& h : hdrs)
    encoder.encode_auto(h.name(), h.value(), out);
  frame_header hdr;
  hdr.length = bytes.size() - FRAME_HEADER_LEN;
  hdr.streamid = node->streamid;
  hdr.type = frame_e::HEADERS;
  hdr.flags = flags::END_HEADERS;
  hdr.form(bytes.data());
  io_error_code ec;
  co_await node->connection->write(bytes, ec);
  if (ec) {
    if (ec != boost::asio::error::operation_aborted)
      HTTP2_LOG(node->connection->logctx, ERROR, "cannot send interim response, err: {}", ec.message());
  }
}

any_io_context_ptr request_context::owner_ioctx() const {
  assert(node);
  if (!node->connection)
    return nullptr;
  return &node->connection->ioctx;
}

}  // namespace hidi
