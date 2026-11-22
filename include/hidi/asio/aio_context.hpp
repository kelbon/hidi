// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

// all used asio headers with Windows.h garbage

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ip/tcp.hpp>

#undef ERROR
#undef NO_ERROR
#undef Yield
#undef NO_DATA
#undef socket
#undef DELETE

namespace hidi {
namespace asio = boost::asio;
}
