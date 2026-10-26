#pragma once

#include <anyany/anyany_macro.hpp>

#include "hidi/utils/deadline.hpp"
#include "hidi/utils/fn_ref.hpp"

namespace hidi {

// arms timer to execute callback after 'd'
// never executes callback immediately
// if timer was armed, its canceled first
// implementation uses atmost one callback and one arm at one time
anyany_method2_n(arm_m, arm, (&self, deadline_t d) requires(self.arm(d))->void);
// arms timer after 'd' and repeats this each 'd'
// period counts from the previous tick, not from the end of the callback
// if timer was armed, its canceled first
anyany_method2_n(arm_periodic_m, arm_periodic, (&self, duration_t d) requires(self.arm_periodic(d))->void);
// returns 'true' if timer was armed before 'cancel'
// do not touches setted callback
anyany_method2_n(cancel_m, cancel, (&self) requires(self.cancel())->bool);

anyany_method2_n(is_armed_m, is_armed, (const& self) requires(self.is_armed())->bool);

using timer_callback_t = move_only_fn<void(bool /*canceled*/)>;
// if callback.empty do not invokes it
// never executes callback immediately
anyany_method2_n(set_timer_callback_m, set_callback,
                 (&self, timer_callback_t cb) requires(self.set_callback(std::move(cb)))->void);

// for using in single thread!
// non-movable
using any_timer = aa::any_with<arm_m, arm_periodic_m, is_armed_m, set_timer_callback_m, cancel_m>;

}  // namespace hidi
