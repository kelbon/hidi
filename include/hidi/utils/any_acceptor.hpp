// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include <anyany/anyany_macro.hpp>
#include <anyany/anyany.hpp>

#include <kelcoro/task.hpp>

#include "hidi/any_connection.hpp"
#include "hidi/errors.hpp"
#include "hidi/utils/address.hpp"

namespace hidi {

anyany_method2_n(get_local_endpoint_m, get_local_endpoint,
                 (const& self) requires(self.get_local_endpoint())->internet_address);

// returns local address after binding
anyany_method2_n(listen_m, listen, (&self) requires(self.listen())->internet_address);

anyany_method2_n(accept_m, accept,
                 (&self, io_error_code& ec) requires(self.accept(ec))->dd::task<any_connection_t>);

anyany_method2_n(close_m, close, (&self) requires(self.close())->void);

// movable because of SooS == 0
using any_acceptor =
    aa::basic_any_with<aa::default_allocator, /*SooS=*/0, get_local_endpoint_m, listen_m, accept_m, close_m>;

}  // namespace hidi
