
#pragma once

#include "hidi/h2connection_fwd.hpp"
#include "hidi/h2protocol.hpp"

#include <kelcoro/task.hpp>

namespace hidi {

// returns false is goaway was not sended
dd::task<bool> send_goaway(h2connection_ptr con, stream_id_t laststreamid, errc_e errc, std::string dbginfo);

dd::task<void> send_rst_stream(h2connection_ptr con, stream_id_t streamid, errc_e errc);

dd::task<void> send_settings_ack(h2connection_ptr con);

// returns false if ping was not sended
dd::task<bool> send_ping(h2connection_ptr con, uint64_t data, bool request_pong);

// random value, selected to determine if receiver of ping correctly responds
constexpr inline uint64_t PING_VALUE = 33333;

dd::task<void> handle_ping(ping_frame ping, h2connection_ptr con);

// returns false, is window update was not sended
dd::task<bool> send_window_update(h2connection_ptr con, stream_id_t id, uint32_t inc);

// sends WINDOW_UPDATE correctly to set window size to max; node=nullptr for connection-level
dd::task<void> update_window_to_max(stream_ptr node, h2connection_ptr con);

}  // namespace hidi
