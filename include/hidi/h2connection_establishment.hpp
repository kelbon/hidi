// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include "hidi/h2client_options.hpp"
#include "hidi/h2connection_fwd.hpp"
#include "hidi/h2server_options.hpp"

#include <kelcoro/task.hpp>

namespace hidi {

// creates client connection with server
// accepts unestablished session 'con' and returns established connection or
// exception
dd::task<h2connection_ptr> establish_http2_session_client(h2connection_ptr con, h2client_options options);

// creates server connection with client
// accepts unestablished session 'con' and returns established connection or
// exception
dd::task<h2connection_ptr> establish_http2_session_server(h2connection_ptr con, h2server_options);

}  // namespace hidi
