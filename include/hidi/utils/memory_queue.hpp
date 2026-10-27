#pragma once

#include <memory>
#include <coroutine>

#include <boost/intrusive_ptr.hpp>

#include "hidi/h2connection_fwd.hpp"
#include "hidi/utils/macro.hpp"
#include "hidi/http_body.hpp"

namespace hidi {

struct memory_queue {
 private:
  size_t refcount = 0;
  bytes_t bytes;
  std::coroutine_handle<> waiter = nullptr;
  stream_ptr n = nullptr;
  // прочитано пользователем, но ещё не возвращено собеседнику через WINDOW_UPDATE
  uint32_t read_not_credited = 0;
  bool eof = false;  // true if last data frame was received
  ZAL_PIN;

  struct data_awaiter {
    memory_queue* q;

    bool await_ready() const noexcept {
      return !q->bytes.empty() || q->eof;
    }

    void await_suspend(std::coroutine_handle<> h) noexcept {
      assert(!q->waiter);
      q->waiter = h;
    }

    [[nodiscard]] bytes_t await_resume() const noexcept {
      return q->poll_data();
    }
  };

  void on_data_read(size_t n) noexcept;

 public:
  // creates memory queue associated with `n`, it will receive all data for `n`
  explicit memory_queue(h2stream& n) noexcept;
  ~memory_queue();

  bool has_data() const noexcept {
    return !bytes.empty();
  }

  // returns empty bytes if no data available
  // returns by copy to avoid invalidate after `push_data`
  [[nodiscard]] bytes_t poll_data() noexcept;

  // returns awaiters
  // await returns empty data only in case EOF
  // only one reader at one time allowed
  auto next_chunk() {
    return data_awaiter(this);
  }

  [[nodiscard]] bool last_chunk_received() const noexcept {
    return eof;
  }

  // true, если данные оборваны: стрим завершился без END_STREAM от собеседника (RST_STREAM, разрыв
  // соединения, таймаут, отмена). Тогда EOF не нормальный конец данных, и канал может закрыть свою сторону
  // аварийно (например RST вместо FIN у сокета, в который он перекладывает данные)
  [[nodiscard]] bool aborted() const noexcept;

  // for using with function ref
  void operator()(std::span<const byte_t> b, bool lastframe);

  friend void intrusive_ptr_add_ref(memory_queue* p) noexcept {
    ++p->refcount;
  }

  friend void intrusive_ptr_release(memory_queue* p) noexcept {
    --p->refcount;
    if (p->refcount == 0)
      delete p;
  }
};

using memory_queue_ptr = boost::intrusive_ptr<memory_queue>;

}  // namespace hidi
