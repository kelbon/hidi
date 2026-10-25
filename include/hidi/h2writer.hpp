
#pragma once

#include "hidi/errors.hpp"
#include "hidi/h2connection_fwd.hpp"
#include "hidi/utils/deadline.hpp"
#include "hidi/utils/fn_ref.hpp"

#include <kelcoro/job.hpp>
#include <kelcoro/task.hpp>
#include <kelcoro/gate.hpp>

namespace hidi {

using writer_on_network_err_t = move_only_fn<void() noexcept>;

struct writer_callbacks {
  writer_on_network_err_t neterrcb;
  size_t refcount = 0;
};

inline void intrusive_ptr_add_ref(writer_callbacks* p) noexcept {
  ++p->refcount;
}

inline void intrusive_ptr_release(writer_callbacks* p) noexcept {
  --p->refcount;
  if (p->refcount == 0)
    delete p;
}

using writer_callbacks_ptr = boost::intrusive_ptr<writer_callbacks>;

template <bool IS_CLIENT>
dd::job write_stream_data(stream_ptr node, h2connection_ptr con, writer_callbacks_ptr cbs);

extern template dd::job write_stream_data<true>(stream_ptr node, h2connection_ptr con,
                                                writer_callbacks_ptr cbs);
extern template dd::job write_stream_data<false>(stream_ptr node, h2connection_ptr con,
                                                 writer_callbacks_ptr cbs);

// creates writer associated with connection.
// Writer uses con->writer when awaiting new job
// con->requests is a writer job. Writer grabs nodes from 'con->requests' one by
// one and writes them into 'con'. handles control flow on sending side Note:
// when server uses this function, pseudoheaders in requests are ignored and
// 'status' from node used as required pseudoheader
//
// 'onnetworkerr' used when network error happens (before closing writer)
// 'forcedisablehpack' forces writer to update HPACK dynamic table to zero size
// when first request sent
//
// precondition: con && onnetworkerr. Callbacks should not throw and
// behave as values, not references
dd::job start_writer_for_client(h2connection_ptr con, writer_on_network_err_t, bool forcedisablehpack,
                                dd::gate::holder);

dd::job start_writer_for_server(h2connection_ptr con, writer_on_network_err_t, bool forcedisablehpack,
                                dd::gate::holder);

}  // namespace hidi
