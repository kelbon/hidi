// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include <kelcoro/task.hpp>

namespace hidi {

struct h2server_session;

// precondition: session.connection != nullptr
// 'onrequest' will be called when request fully received, it stored in node.req
// do not throws (except bad_alloc for coroutine)
// 'session' must be alive until coro ended
// returns status on fail (reqerr_e)
dd::task<int> start_server_reader_for(h2server_session& session);

}  // namespace hidi
