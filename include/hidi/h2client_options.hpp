
#pragma once

#include "hidi/h2protocol.hpp"
#include "hidi/utils/deadline.hpp"
#include "hidi/utils/unique_name.hpp"

namespace hidi {

struct h2client_options {
  // may be used to handle requests while sending big frames, such as files data
  // must not be 0
  uint32_t max_send_frame_size = 8 * 1024;  // 8 KB
  uint32_t max_receive_frame_size = uint32_t(-1);
  uint32_t hpack_dyntab_size = 4096;  // default value from rfc
  bool force_disable_hpack = false;   // if true, forces disabling hpack both for server and client
  // sends ping when there are no requests(for keeping alive).
  // duration_t::max() means disable pings
  // Note: its not recommended to disable pings
  duration_t ping_interval = std::chrono::seconds(5);
  duration_t connection_timeout = std::chrono::seconds(1);
  // If the server does not respond to ping within this time, drops connection
  duration_t ping_timeout = std::chrono::seconds(10);
  // can significantly speed up the first requests on connection,
  // but not all servers correctly support it
  bool allow_requests_before_server_settings = true;
  // cannot be > 1 GB
  uint32_t max_continuation_len_bytes = uint32_t(-1);
  // Сколько кадров, отправляемых в ответ на кадры сервера (PING ACK, SETTINGS ACK, RST_STREAM,
  // WINDOW_UPDATE), может одновременно ждать записи. Если сервер шлёт такие кадры, но не читает ответы, они
  // копятся в памяти
  // При превышении соединение закрывается
  uint32_t max_pending_reply_frames = 1000;
  // SETTINGS_INITIAL_WINDOW_SIZE: сколько байт тела собеседник может прислать в стрим без подтверждения
  // Note: ограничивает скорость одного стрима величиной окно / RTT
  uint32_t stream_window_size = MAX_WINDOW_SIZE;
  log_context logctx = {};
};

}  // namespace hidi
