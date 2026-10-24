
#include "test_connection.hpp"
#include "fuzzing/fuzzer.hpp"
#include "hidi/asio/io_impl.hpp"

#include <boost/asio/ssl.hpp>

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

static server_ssl_context_ptr test_ssl_ctx() {
  return make_ssl_context_for_server(HTTP2_TLS_DIR "/test_server.crt", HTTP2_TLS_DIR "/test_server.key");
}

// клиент открыл TCP соединение и молчит. Это не должно мешать серверу принимать других клиентов
SERVER_TEST("silent TCP connection does not block accept", test_ssl_ctx()) {
  boost::asio::io_context rawio;
  boost::asio::ip::tcp::socket silent(rawio);
  // соединение попадает в очередь listen, даже пока сервер не вызвал accept
  silent.connect(addr);

  auto client = co_await fake_client_connection(ioctx, addr, deadline_after(std::chrono::seconds(2)));
  co_await emulate_client_connection(client);
}

// молчащее соединение закрывается по connection_timeout, в том числе посреди TLS handshake
SERVER_TEST("silent TCP connection is dropped by connection timeout", test_ssl_ctx()) {
  server.get_options().connection_timeout = std::chrono::milliseconds(100);
  boost::asio::io_context rawio;
  boost::asio::ip::tcp::socket silent(rawio);
  silent.connect(addr);

  deadline_t deadline = deadline_after(std::chrono::seconds(2));
  while (server.sessions_count() == 0 && !deadline.is_reached())
    co_await net.sleep(ioctx, std::chrono::milliseconds(10));
  REQUIRE(server.sessions_count() == 1);
  while (server.sessions_count() != 0 && !deadline.is_reached())
    co_await net.sleep(ioctx, std::chrono::milliseconds(10));
  REQUIRE(server.sessions_count() == 0);
}

// подключается к серверу как TLS клиент, предлагающий в ALPN `offer`, и возвращает выбранный сервером протокол
static dd::task<std::string> alpn_selected_by_server(any_io_context& io, internet_address addr,
                                                     std::vector<unsigned char> offer) {
  namespace ssl = boost::asio::ssl;
  ssl::context sslctx(ssl::context::tls_client);
  sslctx.set_verify_mode(ssl::verify_none);
  if (!offer.empty())
    REQUIRE(0 == SSL_CTX_set_alpn_protos(sslctx.native_handle(), offer.data(), offer.size()));
  ssl::stream<boost::asio::ip::tcp::socket> sock(aa::any_cast<asio_tls_io&>(io).ioctx, sslctx);
  // соединение попадает в очередь listen, даже пока сервер не вызвал accept
  sock.lowest_layer().connect(addr);
  io_error_code ec;
  co_await net.handshake(sock, ssl::stream_base::client, ec);
  REQUIRE(!ec);
  const unsigned char* selected = nullptr;
  unsigned int len = 0;
  SSL_get0_alpn_selected(sock.native_handle(), &selected, &len);
  co_return std::string((const char*)selected, len);
}

// сервер выбирает h2, если клиент его предлагает, и не отклоняет клиентов без h2
SERVER_TEST("ALPN", test_ssl_ctx()) {
  if (!is_tls_server)
    co_return;
  SECTION("h2 offered") {
    std::vector<unsigned char> offer{8, 'h', 't', 't', 'p', '/', '1', '.', '1', 2, 'h', '2'};
    REQUIRE((co_await alpn_selected_by_server(server.ioctx(), addr, offer)) == "h2");
  }
  SECTION("h2 not offered") {
    std::vector<unsigned char> offer{8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    REQUIRE((co_await alpn_selected_by_server(server.ioctx(), addr, offer)).empty());
  }
  SECTION("no ALPN") {
    REQUIRE((co_await alpn_selected_by_server(server.ioctx(), addr, {})).empty());
  }
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
