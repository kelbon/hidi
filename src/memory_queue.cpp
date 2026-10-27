#include "hidi/utils/memory_queue.hpp"
#include "hidi/h2connection.hpp"
#include "hidi/h2send_frames.hpp"

namespace hidi {

memory_queue::memory_queue(h2stream& node) noexcept {
  assert(!node.on_data_part_fn);
  node.on_data_part_fn = this;
  n = &node;
  // on server side memory queue must be created after receiving HEADERS, before any DATA
  // on client side must be created only in send_connect_request, no data is sent for it
  assert(node.req.body.data.empty());
}

bool memory_queue::aborted() const noexcept {
  return eof && !n->end_stream_received;
}

void memory_queue::operator()(std::span<const byte_t> b, bool lastframe) {
  // Note: order: set EOF, then push,
  // so if push will wait data again it will produce empty data (EOF marker)
  if (lastframe) {
    eof = true;
  }
  bytes.insert(bytes.end(), b.begin(), b.end());
  if (waiter)
    std::exchange(waiter, nullptr).resume();
}

// окно возвращается только пока собеседник ещё может слать данные в этот стрим
static bool may_receive_data(const h2stream& s) noexcept {
  return !s.end_stream_received && s.connection && !s.connection->is_dropped() &&
         s.responses_hook.is_linked();
}

void memory_queue::on_data_read(size_t sz) noexcept {
  if (!may_receive_data(*n))
    return;
  read_not_credited += uint32_t(sz);
  // если настройки обновятся и сделают initial_stream_window_size больше, то в стрим добавится окно
  // поэтому не будет дедлока
  if (read_not_credited < n->connection->local_settings.initial_stream_window_size / 2)
    return;
  uint32_t inc = std::exchange(read_not_credited, 0);
  increment_window_size_trusted(n->rl_streamlevel_windowsize, int32_t(inc));
  send_window_update(n->connection, n->streamid, inc).start_and_detach();
}

bytes_t memory_queue::poll_data() noexcept {
  bytes_t res = std::move(bytes);
  if (!res.empty())
    on_data_read(res.size());
  return res;
}

memory_queue::~memory_queue() {
  n->on_data_part_fn = nullptr;
  if (!may_receive_data(*n))
    return;
  cfint_t window = n->connection->local_settings.initial_stream_window_size;
  if (n->rl_streamlevel_windowsize < window / 2)
    update_window_to_max(n, n->connection, window).start_and_detach();
}

}  // namespace hidi
