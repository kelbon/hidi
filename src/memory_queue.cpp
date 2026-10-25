#include "hidi/utils/memory_queue.hpp"
#include "hidi/h2connection.hpp"

namespace hidi {

memory_queue::memory_queue(h2stream& node) noexcept {
  assert(!node.on_data_part_fn);
  node.on_data_part_fn = this;
  n = &node;
  // on server side memory queue must be created after receiving HEADERS, before any DATA
  // on client side must be created only in send_connect_request, no data is sent for it
  assert(node.req.body.data.empty());
}

void memory_queue::operator()(std::span<const byte_t> b, bool lastframe) {
  // Note: order: set EOF, then push,
  // so if push will wait data again it will produce empty data (EOF marker)
  if (lastframe) {
    eof = true;
    // при END_STREAM флаг выставлен до вызова, а EOF при завершении стрима без него означает обрыв
    aborted_eof = !n->end_stream_received;
  }
  bytes.insert(bytes.end(), b.begin(), b.end());
  if (waiter)
    std::exchange(waiter, nullptr).resume();
}

memory_queue::~memory_queue() {
  n->on_data_part_fn = nullptr;
}

}  // namespace hidi
