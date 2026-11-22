// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include "hidi/utils/fn_ref.hpp"
#include "hidi/utils/memory.hpp"

#include <span>
#include <string_view>

#include <boost/intrusive_ptr.hpp>

namespace hidi {

struct h2stream;

void intrusive_ptr_add_ref(h2stream* p) noexcept;
void intrusive_ptr_release(h2stream* p) noexcept;

using stream_ptr = boost::intrusive_ptr<h2stream>;

struct h2connection;

void intrusive_ptr_add_ref(h2connection*) noexcept;
void intrusive_ptr_release(h2connection*) noexcept;

using h2connection_ptr = boost::intrusive_ptr<h2connection>;

using on_header_fn_ptr = fn_ptr<void(std::string_view name, std::string_view value)>;

using on_data_part_fn_ptr = fn_ptr<void(std::span<const byte_t> bytes, bool last_part)>;

}  // namespace hidi
