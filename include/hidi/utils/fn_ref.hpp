#pragma once

#include <anyany/anyany.hpp>

namespace hidi {

using aa::copyable_fn;
using aa::fn_cref;
using aa::fn_ref;
using aa::move_only_fn;

template <typename SIGNATURE>
using fn_ptr = aa::ptr<aa::call<SIGNATURE>>;

template <typename SIGNATURE>
using fn_cptr = aa::cptr<aa::call<SIGNATURE>>;

// move_only_fn, который всегда хранит функцию в куче (SooS == 0): sizeof меньше (используется в h2stream)
template <typename Signature>
using heap_move_only_fn = aa::basic_any_with<aa::default_allocator, 0, aa::call<Signature>>;

}  // namespace hidi
