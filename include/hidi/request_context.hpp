#pragma once

#include "hidi/asio/aio_context.hpp"
#include "hidi/h2connection_fwd.hpp"
#include "hidi/h2errors.hpp"
#include "hidi/http_base.hpp"
#include "hidi/utils/any_io_context.hpp"
#include "hidi/utils/memory_queue.hpp"

#include <kelcoro/task.hpp>

namespace hidi {

// Note: its NOT thread safe to copy on other thread
struct request_context {
 private:
  stream_ptr node = nullptr;

  friend struct h2client;

 public:
  explicit request_context(h2stream& n) noexcept : node(&n) {
  }

  explicit operator bool() const noexcept {
    return node != nullptr;
  }

  stream_id_t streamid() const noexcept;
  // true if remote endpoint already sent RST_STREAM for this request
  // or connection dropped already
  bool canceled() const noexcept;

  // must be returned from `handle_request` to send stream response.
  // For example if server want to send big file. Also can send trailers (by settings headers passed into
  // channel)
  // precondition: makebody.has_value(), status > 0
  [[nodiscard("return it")]] http_response stream_response(int status, http_headers_t,
                                                           stream_body_maker_t makebody);

  [[nodiscard("return it")]] http_response stream_response(int status, http_headers_t hdrs,
                                                           streaming_body_t body) {
    return stream_response(status, std::move(hdrs), streaming_body_without_trailers(std::move(body)));
  }

  // precondition: status is informational (in range [100, 199])
  dd::task<void> send_interim_response(int status, http_headers_t hdrs = {});

  any_io_context_ptr owner_ioctx() const;
};

struct client_request_context {
 private:
  stream_ptr node = nullptr;

  friend struct h2client;

 public:
  client_request_context() = default;

  // `send_request` хранит ссылку на контекст
  client_request_context(client_request_context&&) = delete;
  void operator=(client_request_context&&) = delete;

  // true, пока запрос выполняется
  explicit operator bool() const noexcept {
    return node != nullptr;
  }

  // 0 - хедеров ещё не получали
  // 1хх - какой-то гений решил ответить промежуточным ответом, советую игнорировать
  // остальное - ответ сервера
  int status() const noexcept;

  // собеседник завершил стрим (получен END_STREAM)
  // В `on_header` true означает, что это трейлеры
  bool end_stream_received() const noexcept;

  stream_id_t streamid() const noexcept;

  // true if remote endpoint already sent RST_STREAM for this request
  // or connection dropped already
  bool canceled() const noexcept;

  any_io_context_ptr owner_ioctx() const;
};

}  // namespace hidi
