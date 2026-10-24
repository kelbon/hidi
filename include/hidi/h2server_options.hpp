#pragma once

#include "hidi/h2protocol.hpp"
#include "hidi/utils/deadline.hpp"
#include "hidi/utils/unique_name.hpp"

namespace hidi {

// server drops connection if client inactive this amount of time
constexpr inline duration_t SERVER_DEFAULT_IDLE_TIMEOUT = std::chrono::seconds(25);
// timeout for sending client preface
constexpr inline duration_t SERVER_DEFAULT_CONNECTION_TIMEOUT = std::chrono::seconds(5);

struct h2server_options {
  uint32_t hpack_dyntab_size = 4096;
  // Note: disabling hpack from global config has higher priority
  bool force_disable_hpack = false;
  uint32_t max_receive_frame_size = FRAME_LEN_MAX;
  // how many streams client may run concurrently, default: max possible
  uint32_t max_concurrent_streams = uint32_t(-1);
  duration_t connection_timeout = SERVER_DEFAULT_CONNECTION_TIMEOUT;
  // when drop client if it does not send anything
  duration_t idle_timeout = SERVER_DEFAULT_IDLE_TIMEOUT;
  // if false, server will not declare websocket support for clients
  bool supports_websocket = false;
  // Как много байт может быть использовано одной клиент-сервер сессией единовременно для сборки и обработки
  // запросов.
  // Не даёт клиенту забить память сервера посылкой больших запросов без отправки END_STREAM
  // Note: лимит выставляется на все запросы сессии вместе, а не на один
  size_t limit_requests_memory_usage_bytes = size_t(-1);
  // При превышении лимита новые соединения будут отброшены
  size_t limit_clients_count = size_t(-1);
  // cannot be > 1 GB
  uint32_t max_continuation_len_bytes = uint32_t(-1);
  // Сколько кадров, отправляемых в ответ на кадры клиента (PING ACK, SETTINGS ACK, RST_STREAM,
  // WINDOW_UPDATE), может одновременно ждать записи. Если клиент шлёт такие кадры, но не читает ответы, они
  // копятся в памяти
  // При превышении соединение закрывается
  uint32_t max_pending_reply_frames = 1000;
  log_context logctx = {};
};

}  // namespace hidi
