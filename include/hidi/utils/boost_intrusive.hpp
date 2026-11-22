// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include <boost/intrusive/link_mode.hpp>
#include <boost/intrusive/options.hpp>
#include <boost/intrusive/trivial_value_traits.hpp>
#include <kelcoro/executor_interface.hpp>

namespace bi = boost::intrusive;

namespace hidi {

template <typename INTRUSIVE_CONTAINER>
static void erase_byref(INTRUSIVE_CONTAINER& c, typename INTRUSIVE_CONTAINER::value_type& node) noexcept {
  if constexpr (requires { INTRUSIVE_CONTAINER::s_iterator_to(node); })
    c.erase(INTRUSIVE_CONTAINER::s_iterator_to(node));
  else
    c.erase(c.iterator_to(node));
}
// need to know if node is linked or not, so always use safe_link (container's
// erase will reset node)
constexpr inline bi::link_mode_type DEFAULT_LINK_MODE = bi::safe_link;

using link_option_t = bi::link_mode<DEFAULT_LINK_MODE>;

}  // namespace hidi
