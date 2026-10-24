
#include "test_connection.hpp"
#include "fuzzing/fuzzer.hpp"

#include <moko3/moko3.hpp>

using namespace hidi;

// пишет пока не получит ошибку. Пир не читает, поэтому рано или поздно буферы ОС заполнятся и запись встанет
static dd::task<void> write_until_error(any_connection_t& con, io_error_code& ec, bool& done) {
  std::vector<byte_t> bytes(1024 * 1024);
  while (!ec)
    co_await write_awaiter(con, ec, bytes);
  done = true;
}

// пир не читает, поэтому начатая запись никогда не завершится. shutdown не должен её ждать
static dd::task<void> shutdown_with_blocked_write(any_io_context_ref ioctx) {
  any_acceptor a = ioctx.create_acceptor(localhost(), /*reuse_address=*/true);
  a.listen();
  any_connection_t peer = co_await ioctx.create_connection_client({a.get_local_endpoint()}, deadline_after(5s));
  io_error_code ec;
  any_connection_t con = co_await a.accept(ec);
  REQUIRE(!ec);

  io_error_code write_ec;
  bool write_done = false;
  write_until_error(con, write_ec, write_done).start_and_detach();
  co_await net.sleep(ioctx, std::chrono::milliseconds(100));

  co_await con->shutdown();
  // либо отменена зависшая запись, либо следующая запись после shutdown
  REQUIRE(write_done);
  REQUIRE(write_ec == boost::asio::error::operation_aborted);
  co_await peer->shutdown();
}

TEST("shutdown does not wait for blocked write") {
  any_io_context ioctx = make_asio_io_context();
  bool ended = false;
  std::exception_ptr ex;
  (void)run_test("shutdown does not wait for blocked write", shutdown_with_blocked_write(*&ioctx), ended, ex);
  fuzzing::fuzzer fuz;
  fuz.run_until(deadline_after(std::chrono::seconds(5)), ended, ioctx);
  REQUIRE(ended);
  if (ex)
    std::rethrow_exception(ex);
}

// сервер принял TCP соединение, но не отвечает на TLS handshake. Клиент должен уважать deadline
TEST("client TLS handshake respects deadline") {
  boost::asio::io_context rawio;
  boost::asio::ip::tcp::acceptor silent(rawio, internet_address(boost::asio::ip::address_v4::loopback(), 0));
  silent.listen();

  h2client client(silent.local_endpoint(), h2client_options{},
                  make_asio_tls_io_context(make_ssl_context_for_client({})));
  bool ended = false;
  std::exception_ptr ex;
  auto connect = [](h2client& c) -> dd::task<void> {
    (void)co_await c.try_connect(deadline_after(std::chrono::milliseconds(200)));
  };
  (void)run_test("client TLS handshake respects deadline", connect(client), ended, ex);
  fuzzing::fuzzer fuz;
  fuz.run_until(deadline_after(std::chrono::seconds(3)), ended, client.ioctx());
  REQUIRE(ended);
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
