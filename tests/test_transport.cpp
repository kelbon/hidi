
#include "test_connection.hpp"
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
TRANSPORT_TEST("shutdown does not wait for blocked write") {
  any_io_context ioctx = make_asio_io_context(rawio);
  any_acceptor a = ioctx.create_acceptor(localhost(), /*reuse_address=*/true);
  a.listen();
  any_connection_t peer = co_await ioctx.create_connection_client({a.get_local_endpoint()}, deadline_after(5s));
  io_error_code ec;
  any_connection_t con = co_await a.accept(ec);
  REQUIRE(!ec);

  io_error_code write_ec;
  bool write_done = false;
  write_until_error(con, write_ec, write_done).start_and_detach();
  co_await net.sleep(rawio, std::chrono::milliseconds(100));

  co_await con->shutdown();
  // либо отменена зависшая запись, либо следующая запись после shutdown
  REQUIRE(write_done);
  REQUIRE(write_ec == boost::asio::error::operation_aborted);
  co_await peer->shutdown();
}

// сервер принял TCP соединение, но не отвечает на TLS handshake. Клиент должен уважать deadline
TRANSPORT_TEST("client TLS handshake respects deadline") {
  any_io_context ioctx = make_asio_tls_io_context(rawio, make_ssl_context_for_client({}));
  boost::asio::ip::tcp::acceptor silent(rawio, localhost());
  silent.listen();
  bool timeout = false;
  try {
    (void)co_await ioctx.create_connection_client({silent.local_endpoint()},
                                                  deadline_after(std::chrono::milliseconds(200)));
  } catch (timeout_exception&) {
    timeout = true;
  }
  REQUIRE(timeout);
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

static constexpr size_t BACKPRESSURE_CHUNK = 64 * 1024;
static constexpr size_t BACKPRESSURE_CHUNKS = 16;
// Буферы сокетов задаются явно и меньше одной TLS записи (16 KB), поэтому запись упирается в заполненные
// буферы посреди записи независимо от настроек ОС по умолчанию (ОС может только округлить размер вверх до
// своего минимума, у Linux это ~4.6 KB на отправку и ~2.3 KB на приём)
static constexpr int SMALL_SOCKET_BUFFER = 2048;

static byte_t pattern_byte(size_t i) {
  return byte_t(i % 251);
}

static dd::task<void> write_pattern(any_connection_t& con, bool& done) {
  std::vector<byte_t> chunk(BACKPRESSURE_CHUNK);
  io_error_code ec;
  for (size_t c = 0; c < BACKPRESSURE_CHUNKS; ++c) {
    for (size_t i = 0; i < chunk.size(); ++i)
      chunk[i] = pattern_byte(c * BACKPRESSURE_CHUNK + i);
    co_await write_awaiter(con, ec, chunk);
    REQUIRE(!ec);
  }
  done = true;
}

// принимает соединение (сервер нужен параллельно с подключением клиента, так как TLS handshake двусторонний)
static dd::task<void> accept_raw(boost::asio::ip::tcp::acceptor& a, ssl_context_ptr sslctx,
                                 any_connection_t& out, bool& done) {
  boost::asio::ip::tcp::socket sock(a.get_executor());
  io_error_code ec;
  co_await net.accept(a, sock, ec);
  REQUIRE(!ec);
  if (sslctx)
    out.reset(new asio_tls_connection(std::move(sock), std::move(sslctx)));
  else
    out.reset(new asio_connection(std::move(sock)));
  co_await out->handshake(ec);
  REQUIRE(!ec);
  done = true;
}

// Пишущая сторона упирается в заполненные буферы сокетов. Ни один байт не должен потеряться
TRANSPORT_TEST("write under backpressure") {
  bool tls = false;
  SECTION("TCP") {
  }
  SECTION("TLS") {
    tls = true;
  }
  tcp_connection_options opts{.send_buffer_size = SMALL_SOCKET_BUFFER, .receive_buffer_size = SMALL_SOCKET_BUFFER};
  any_io_context ioctx = tls ? make_asio_tls_io_context(rawio, make_ssl_context_for_client({}), opts)
                             : make_asio_io_context(rawio, opts);
  boost::asio::ip::tcp::acceptor a(rawio, localhost());
  // принятые соединения наследуют размер буфера от слушающего сокета
  a.set_option(boost::asio::socket_base::receive_buffer_size(SMALL_SOCKET_BUFFER));
  a.listen();
  any_connection_t reader;
  bool accepted = false;
  accept_raw(a, tls ? test_ssl_ctx().p : nullptr, reader, accepted).start_and_detach();
  any_connection_t writer = co_await ioctx.create_connection_client({a.local_endpoint()}, deadline_after(5s));
  while (!accepted)
    co_await net.sleep(rawio, std::chrono::milliseconds(1));

  bool written = false;
  write_pattern(writer, written).start_and_detach();
  co_await net.sleep(rawio, std::chrono::milliseconds(50));

  std::vector<byte_t> chunk(BACKPRESSURE_CHUNK);
  io_error_code ec;
  for (size_t c = 0; c < BACKPRESSURE_CHUNKS; ++c) {
    co_await read_awaiter(reader, ec, chunk);
    REQUIRE(!ec);
    for (size_t i = 0; i < chunk.size(); ++i)
      REQUIRE(chunk[i] == pattern_byte(c * BACKPRESSURE_CHUNK + i));
  }
  REQUIRE(written);
  co_await writer->shutdown();
  co_await reader->shutdown();
}

static dd::task<void> accept_and_get_sni(boost::asio::ip::tcp::acceptor& a, boost::asio::ssl::context& sslctx,
                                         std::string& sni, bool& done) {
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> sock(a.get_executor(), sslctx);
  io_error_code ec;
  co_await net.accept(a, sock.lowest_layer(), ec);
  REQUIRE(!ec);
  co_await net.handshake(sock, boost::asio::ssl::stream_base::server, ec);
  REQUIRE(!ec);
  const char* name = SSL_get_servername(sock.native_handle(), TLSEXT_NAMETYPE_host_name);
  sni = name ? name : "";
  done = true;
}

// клиент передаёт SNI, если подключается по доменному имени
// https://www.rfc-editor.org/rfc/rfc9113.html#section-9.2
TRANSPORT_TEST("client sends SNI") {
  any_io_context ioctx = make_asio_tls_io_context(rawio, make_ssl_context_for_client({}));
  boost::asio::ip::tcp::acceptor a(rawio, localhost());
  a.listen();
  endpoint target;
  std::string expected;
  SECTION("domain name") {
    target = endpoint(std::string("localhost"), a.local_endpoint().port());
    expected = "localhost";
  }
  SECTION("ip address") {
    target = endpoint(a.local_endpoint());
    expected = "";
  }
  ssl_context_ptr server_sslctx = test_ssl_ctx().p;
  std::string sni = "not set";
  bool done = false;
  accept_and_get_sni(a, server_sslctx->ctx, sni, done).start_and_detach();
  any_connection_t con = co_await ioctx.create_connection_client({target}, deadline_after(5s));
  while (!done)
    co_await net.sleep(rawio, std::chrono::milliseconds(1));
  REQUIRE(sni == expected);
  co_await con->shutdown();
}

// перевзвод таймера отменяет старое ожидание, но его завершение не должно влиять на новый взвод
TEST("timer re-arm ignores canceled wait") {
  boost::asio::io_context io;
  asio_timer timer(io);
  int fired = 0;
  int canceled = 0;
  timer.set_callback([&](bool c) { ++(c ? canceled : fired); });

  SECTION("re-arm") {
    timer.arm(deadline_after(std::chrono::hours(1)));
    timer.arm(deadline_after(std::chrono::milliseconds(1)));
    io.poll();  // завершение отменённого ожидания
    REQUIRE(timer.is_armed());
    REQUIRE(canceled == 0);
    io.run();
    REQUIRE(fired == 1);
    REQUIRE(!timer.is_armed());
  }
  SECTION("cancel") {
    // на этом держится net.sleep: отменённое ожидание сообщает об отмене
    timer.arm(deadline_after(std::chrono::hours(1)));
    REQUIRE(timer.cancel());
    io.run();
    REQUIRE(canceled == 1);
    REQUIRE(fired == 0);
  }
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
