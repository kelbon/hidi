#include "test_connection.hpp"

#include <kelcoro/algorithm.hpp>
#include <moko3/moko3.hpp>

#include <atomic>
#include <format>
#include <mutex>
#include <set>
#include <thread>

using namespace hidi;

namespace {

// общее для всех серверов h2server_mt (у каждого потока свой сервер)
struct mt_stats {
  std::mutex mtx;
  // потоки, на которых обрабатывались запросы
  std::set<std::thread::id> threads;
  // запрос обработан не на потоке своего сервера
  std::atomic<size_t> wrong_thread = 0;
  // запросы "/wait" ждут, пока `release` не станет true
  std::atomic<size_t> waiting = 0;
  std::atomic<bool> release = false;
};

// отвечает телом запроса. "/wait" отвечает только после mt_stats::release
struct mt_test_server : h2server {
  mt_stats* stats;

  mt_test_server(mt_stats* s, server_ssl_context_ptr ssl, h2server_options opts)
      : h2server(std::move(ssl), std::move(opts)), stats(s) {
  }

  dd::task<http_response> handle_request(http_request req, request_context) override {
    if (!ioctx().running_in_this_thread())
      ++stats->wrong_thread;
    {
      std::lock_guard l(stats->mtx);
      stats->threads.insert(std::this_thread::get_id());
    }
    if (req.path == "/wait") {
      ++stats->waiting;
      while (!stats->release)
        co_await yield_on_ioctx(*&ioctx());
    }
    http_response rsp;
    rsp.status = 200;
    rsp.body = std::move(req.body.data);
    co_return rsp;
  }
};

// h2server_mt, run которого выполняется в отдельном потоке. Деструктор останавливает сервер и ждёт run
struct running_mt_server {
  mt_stats stats;
  h2server_mt server;
  internet_address addr;
  std::atomic<bool> run_ended = false;
  bool stop_requested = false;
  std::thread runner;

  running_mt_server(size_t threads, server_ssl_context_ptr ssl, tcp_connection_options tcp)
      : server(threads, std::in_place_type<mt_test_server>, &stats, std::move(ssl),
               h2server_options{.tcp = tcp}) {
    addr = server.listen({.addr = localhost(), .reuse_address = true});
    runner = std::thread([this] {
      server.run();
      run_ended = true;
    });
  }

  // мягкая остановка: run завершится, когда активные запросы будут обработаны
  // Note: только один раз, повторный request_stop после конца run никогда бы не выполнился
  void request_stop() {
    if (!std::exchange(stop_requested, true))
      server.request_stop();
  }

  ~running_mt_server() {
    // если тест упал, пока запросы ждали
    stats.release = true;
    request_stop();
    runner.join();
  }
};

using clients_t = std::vector<std::unique_ptr<h2client>>;

// `count` клиентов к `addr`, каждый открывает своё соединение. Работают на `rawio`
clients_t make_clients(size_t count, internet_address addr, bool tls, tcp_connection_options tcp,
                       asio::io_context& rawio) {
  clients_t clients;
  for (size_t i = 0; i < count; ++i) {
    clients.push_back(std::make_unique<h2client>(endpoint(addr),
                                                 tls ? make_ssl_context_for_client({}) : nullptr,
                                                 h2client_options{.tcp = tcp}, make_asio_io_context(rawio)));
  }
  return clients;
}

http_request make_request(std::string path, std::string_view body = {}) {
  http_request req{.path = std::move(path), .method = http_method_e::POST};
  req.body.data.assign(body.begin(), body.end());
  return req;
}

// выполняет `test` на цикле событий клиентов (сервер работает в своих потоках)
void run_on_clients(std::string_view name, asio::io_context& rawio, dd::task<void> test) {
  bool ended = false;
  std::exception_ptr ex;
  (void)run_test(name, std::move(test), ended, ex);
  fuzzing::fuzzer fuz(moko3::get_testbox().randg());
  fuz.run_until(deadline_after(moko3::get_testbox().test_timeout(name)), ended, rawio);
  if (ex)
    std::rethrow_exception(std::move(ex));
}

// вызывает f(tls, buffer_writes) для каждого варианта транспорта
template <typename F>
void for_each_transport(moko3::section_info* _section, F&& f) {
  SECTION("NO TLS") {
    SECTION("direct writes") {
      f(false, false);
    }
    SECTION("buffered writes") {
      f(false, true);
    }
  }
  SECTION("TLS") {
    SECTION("direct writes") {
      f(true, false);
    }
    SECTION("buffered writes") {
      f(true, true);
    }
  }
}

constexpr size_t REQUESTS_PER_CLIENT = 3;

dd::task<void> echo_from_all_clients(clients_t& clients) {
  std::vector<std::string> bodies;
  std::vector<dd::task<http_response>> requests;
  for (size_t c = 0; c < clients.size(); ++c) {
    for (size_t i = 0; i < REQUESTS_PER_CLIENT; ++i) {
      bodies.push_back(std::format("client {} request {}", c, i));
      requests.push_back(clients[c]->send_request(make_request("/echo", bodies.back()), deadline_after(5s)));
    }
  }
  auto responses = co_await dd::when_all(std::move(requests));
  for (size_t i = 0; i < responses.size(); ++i) {
    REQUIRE(responses[i].has_value());
    REQUIRE_EQ((*responses[i]).status, 200);
    REQUIRE_EQ((*responses[i]).body_strview(), bodies[i]);
  }
}

struct wait_result {
  bool done = false;
  int status = 0;
  std::exception_ptr ex;
};

dd::job send_wait_request(h2client& client, wait_result& r) {
  on_scope_exit {
    r.done = true;
  };
  try {
    http_response rsp = co_await client.send_request(make_request("/wait"), deadline_after(5s));
    r.status = rsp.status;
  } catch (...) {
    r.ex = std::current_exception();
  }
}

dd::task<void> stop_during_requests(running_mt_server& srv, clients_t& clients, asio::io_context& rawio) {
  any_io_context io = make_asio_io_context(rawio);
  std::vector<wait_result> results(clients.size());
  for (size_t i = 0; i < clients.size(); ++i)
    send_wait_request(*clients[i], results[i]);
  co_await wait_until([&] { return srv.stats.waiting == clients.size(); }, *&io);

  srv.request_stop();
  // остановка уже идёт, а запросы ещё обрабатываются
  deadline_t d = deadline_after(50ms);
  co_await wait_until([&] { return d.is_reached(); }, *&io);
  REQUIRE(!srv.run_ended);
  srv.stats.release = true;

  co_await wait_until([&] { return std::ranges::all_of(results, &wait_result::done); }, *&io);
  for (wait_result& r : results) {
    if (r.ex)
      std::rethrow_exception(r.ex);
    REQUIRE_EQ(r.status, 200);
  }
  co_await wait_until([&] { return srv.run_ended.load(); }, *&io);
}

}  // namespace

// соединения раздаются серверам по кругу, поэтому при 2 соединениях на поток запросы обрабатываются на всех
// потоках, каждый на потоке своего сервера (после rebind соединение работает в контексте этого сервера)
TEST("mt server serves connections on all threads") {
  const size_t threads = GENERATE(1, 2, 4);
  for_each_transport(_section, [&](bool tls, bool buffer_writes) {
    tcp_connection_options tcp{.write_buffer_limit = buffer_writes ? TEST_WRITE_BUFFER_LIMIT : 0};
    running_mt_server srv(threads, tls ? test_server_ssl_ctx() : nullptr, tcp);
    asio::io_context rawio;
    clients_t clients = make_clients(2 * threads, srv.addr, tls, tcp, rawio);

    run_on_clients("mt server serves connections on all threads", rawio, echo_from_all_clients(clients));

    REQUIRE_EQ(srv.stats.wrong_thread.load(), 0);
    std::lock_guard l(srv.stats.mtx);
    REQUIRE_EQ(srv.stats.threads.size(), threads);
  });
}

// request_stop не прерывает начатые запросы ни на одном потоке, run завершается после их ответов
TEST("mt server request_stop waits active requests") {
  const size_t threads = GENERATE(1, 2, 4);
  for_each_transport(_section, [&](bool tls, bool buffer_writes) {
    tcp_connection_options tcp{.write_buffer_limit = buffer_writes ? TEST_WRITE_BUFFER_LIMIT : 0};
    running_mt_server srv(threads, tls ? test_server_ssl_ctx() : nullptr, tcp);
    asio::io_context rawio;
    // по соединению на каждый поток
    clients_t clients = make_clients(threads, srv.addr, tls, tcp, rawio);

    run_on_clients("mt server request_stop waits active requests", rawio,
                   stop_during_requests(srv, clients, rawio));

    std::lock_guard l(srv.stats.mtx);
    REQUIRE_EQ(srv.stats.threads.size(), threads);
  });
}

TEST("mt server run without listen throws") {
  mt_stats stats;
  h2server_mt server(2, std::in_place_type<mt_test_server>, &stats, nullptr, h2server_options{});
  REQUIRE_THROWS(server.run());
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
