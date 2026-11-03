
#pragma once

#include "hidi/asio/ssl_context.hpp"
#include "hidi/utils/any_io_context.hpp"
#include "hidi/tcp_connection_options.hpp"

namespace hidi {

// контекст на asio. TLS и параметры TCP задаёт создающий соединения клиент или сервер

any_io_context make_asio_io_context();

// creates 'ref' version (do not own 'ctx')
any_io_context make_asio_io_context(asio::io_context& ctx);

}  // namespace hidi
