#include "hidi/asio/io.hpp"
#include "hidi/buffered_connection.hpp"

#include <moko3/moko3.hpp>

#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <vector>

using namespace hidi;
namespace error = boost::asio::error;

// Подставное внутреннее соединение: на что как ответить, решает тест. Запоминает первое нарушение гарантий
// buffered_connection
struct scripted_inner {
  // как tls_connection: при неполной записи try_write возвращает 0, остаток уже не данные писателя, а свой
  // `unsent`, его и пишет start_write
  bool tls_like = false;
  // сколько примет следующий try_write и ответит ли ошибкой, решает тест
  std::function<size_t(size_t)> accept;
  std::function<bool()> fail_now;
  // противодавление: пока outbuf не меньше лимита, запись ждёт, поэтому за раз пишется меньше лимита плюс
  // одна запись
  size_t max_write_size = size_t(-1);

  std::vector<byte_t> sent;
  std::vector<byte_t> unsent;
  bool must_start_write = false;
  writer_node* pending_write = nullptr;
  std::coroutine_handle<> pending_read;
  io_error_code* read_ec = nullptr;
  bool shut = false;
  std::string violation;

  void check(bool ok, const char* what) {
    if (!ok && violation.empty())
      violation = what;
  }
  bool try_read(std::span<byte_t>&) noexcept {
    check(!pending_read, "try_read during start_read");
    return false;
  }
  void start_read(std::coroutine_handle<> h, std::span<byte_t>, io_error_code& ec) {
    check(!pending_read, "two start_read");
    pending_read = h;
    read_ec = &ec;
  }
  size_t try_write(std::span<const byte_t> buf, io_error_code& ec) noexcept {
    check(!must_start_write, "try_write after partial try_write");
    check(!pending_write, "try_write during start_write");
    check(!shut, "try_write after shutdown");
    check(buf.size() < max_write_size, "outbuf exceeds limit");
    if (fail_now()) {
      ec = error::broken_pipe;
      return 0;
    }
    size_t n = accept(buf.size());
    sent.insert(sent.end(), buf.begin(), buf.begin() + n);
    must_start_write = n != buf.size();
    if (must_start_write && tls_like) {
      unsent.assign(buf.begin() + n, buf.end());
      return 0;
    }
    return n;
  }
  void start_write(writer_node* n) {
    check(must_start_write, "start_write without partial try_write");
    check(!pending_write, "two start_write");
    must_start_write = false;
    pending_write = n;
  }
  dd::task<void> shutdown() noexcept {
    shut = true;
    co_return;
  }
  static constexpr bool is_https = false;
};

using connection = buffered_connection<scripted_inner>;

// Случайная последовательность записей, чтений и shutdown, и случайные ответы внутреннего соединения.
// Операция может начаться и в продолжении завершившейся (так читатель h2 пишет WINDOW_UPDATE и снова читает)
struct scenario {
  std::mt19937 rng;
  connection& c;
  size_t limit;
  size_t ops_left = 300;
  // каждый байт записей свой (по модулю простого числа), так видна потеря, повтор и перестановка
  size_t next_byte = 0;
  std::vector<byte_t> expected;
  size_t active = 0;
  bool reading = false;
  bool shutdown_started = false;
  bool shutdown_done = false;
  bool inner_failed = false;
  std::string failure;

  size_t random(size_t n) {
    return std::uniform_int_distribution<size_t>(0, n - 1)(rng);
  }
  size_t max_write() const {
    return 3 * limit + 1;
  }
  size_t write_size() {
    size_t room = c.outbuf.size() < limit ? limit - c.outbuf.size() : 1;
    const size_t sizes[] = {1, 2, room, limit - 1, limit, limit + 1, max_write()};
    return std::max<size_t>(1, sizes[random(std::size(sizes))]);
  }
  void maybe_continue() {
    if (ops_left == 0)
      return;
    switch (random(6)) {
      case 0:
      case 1:
        start_write();
        break;
      case 2:
        start_read();
        break;
    }
  }
  void start_write() {
    --ops_left;
    (void)write_op(*this, write_size());
  }
  void start_read() {
    if (reading)
      return;
    --ops_left;
    (void)read_op(*this);
  }

  static dd::job write_op(scenario& s, size_t size) {
    ++s.active;
    std::vector<byte_t> data(size);
    for (byte_t& b : data)
      b = byte_t(s.next_byte++ % 251);
    bool after_shutdown = s.shutdown_started;
    bool after_error = bool(s.c.write_ec);
    if (!after_shutdown)
      s.expected.insert(s.expected.end(), data.begin(), data.end());
    io_error_code ec;
    co_await write_awaiter(s.c, ec, data);
    if (after_shutdown && ec != error::operation_aborted && s.failure.empty())
      s.failure = "write after shutdown is not aborted";
    if (after_error && !ec && s.failure.empty())
      s.failure = "write after error succeeded";
    --s.active;
    s.maybe_continue();
  }

  static dd::job read_op(scenario& s) {
    ++s.active;
    s.reading = true;
    byte_t buf[16];
    std::span<byte_t> got = buf;
    io_error_code ec;
    if (!s.c.try_read(got))
      co_await dd::suspend_and_t([&](std::coroutine_handle<> h) { s.c.start_read(h, got, ec); });
    s.reading = false;
    --s.active;
    s.maybe_continue();
  }

  static dd::job shutdown_op(scenario& s) {
    s.shutdown_started = true;
    co_await s.c.shutdown();
    s.shutdown_done = true;
  }
};

TEST("buffered_connection: random reads, writes, shutdown and errors") {
  size_t seed = GENERATE_RANDOM(300);
  std::mt19937 params(seed);
  boost::asio::io_context io;
  any_io_context ioctx = make_asio_io_context(io);
  size_t limit = params() % 2 ? 1 : 16;
  auto c = std::make_unique<connection>(*&ioctx, limit);
  scenario s{std::mt19937(params()), *c, limit};
  scripted_inner& inner = c->inner;
  inner.tls_like = params() % 2;
  inner.max_write_size = limit + s.max_write();
  bool with_errors = params() % 4 == 0;
  // без shutdown соединение просто разрушается в конце
  bool with_shutdown = params() % 4 != 0;
  inner.accept = [&](size_t n) {
    if (n == 0)
      return size_t(0);
    switch (s.random(4)) {
      case 0:
        return size_t(0);
      case 1:
        return s.random(n);
      default:
        return n;
    }
  };
  inner.fail_now = [&] {
    bool f = with_errors && s.random(40) == 0;
    s.inner_failed |= f;
    return f;
  };

  auto fail = [&](std::string what) {
    (void)(void)c.release();  // писатель мог остаться посреди записи, разрушать нельзя
    FAIL(what + ", seed " + std::to_string(seed));
  };
  enum event { WRITE, READ, SHUTDOWN, COMPLETE_WRITE, COMPLETE_READ, POLL };
  for (size_t step = 0;; ++step) {
    if (step == 100000)
      fail("no progress");
    std::vector<event> events;
    if (s.ops_left) {
      events.push_back(WRITE);
      if (!s.reading)
        events.push_back(READ);
    }
    if (with_shutdown && !s.shutdown_started && (s.ops_left == 0 || s.random(50) == 0))
      events.push_back(SHUTDOWN);
    if (inner.pending_write)
      events.push_back(COMPLETE_WRITE);
    if (inner.pending_read)
      events.push_back(COMPLETE_READ);
    if (events.empty()) {
      // остался только запланированный в io_context писатель (или ничего)
      io.restart();
      if (io.poll() != 0)
        continue;
      break;
    }
    events.push_back(POLL);
    switch (events[s.random(events.size())]) {
      case WRITE:
        s.start_write();
        break;
      case READ:
        s.start_read();
        break;
      case SHUTDOWN:
        (void)scenario::shutdown_op(s);
        break;
      case COMPLETE_WRITE: {
        writer_node* n = std::exchange(inner.pending_write, nullptr);
        if (inner.fail_now()) {
          n->ec = error::broken_pipe;
        } else {
          std::span<const byte_t> rest = inner.tls_like ? std::span<const byte_t>(inner.unsent) : n->data;
          inner.sent.insert(inner.sent.end(), rest.begin(), rest.end());
          inner.unsent.clear();
          n->ec.clear();
        }
        n->callback.resume();
        break;
      }
      case COMPLETE_READ: {
        std::coroutine_handle<> h = std::exchange(inner.pending_read, nullptr);
        if (inner.shut || s.random(20) == 0)
          *inner.read_ec = error::eof;
        h.resume();
        break;
      }
      case POLL:
        io.restart();
        io.poll_one();
        break;
    }
  }
  // после ошибки внутреннего соединения дошло начало записанного, иначе всё
  bool sent_ok = s.inner_failed ? inner.sent.size() <= s.expected.size() &&
                                      std::equal(inner.sent.begin(), inner.sent.end(), s.expected.begin())
                                : inner.sent == s.expected;
  std::string what = inner.violation.empty() ? s.failure : inner.violation;
  if (what.empty() && with_shutdown && !s.shutdown_done)
    what = "shutdown not finished";
  if (what.empty() && s.active)
    what = "operation not finished";
  if (what.empty() && !sent_ok)
    what = "sent bytes differ from written";
  if (!what.empty())
    fail(what);
  // отмена таймера shutdown
  io.restart();
  io.poll();
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
