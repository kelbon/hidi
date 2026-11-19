
#include "test_connection.hpp"
#include "hidi/tls_session.hpp"

#include <moko3/moko3.hpp>

#include <algorithm>
#include <cstring>
#include <random>

using namespace hidi;

namespace {

SSL_CTX* client_ctx() {
  static client_ssl_context_ptr ctx = make_ssl_context_for_client({});
  return ctx.p->ctx.native_handle();
}

SSL_CTX* server_ctx() {
  static server_ssl_context_ptr ctx = test_server_ssl_ctx();
  return ctx.p->ctx.native_handle();
}

std::vector<byte_t> random_bytes(size_t n) {
  std::mt19937 gen(n);
  std::vector<byte_t> r(n);
  for (byte_t& b : r)
    b = byte_t(gen());
  return r;
}

// отправленные байты одного направления, из них первые `fed` поданы получателю
struct wire {
  std::vector<byte_t> bytes;
  size_t fed = 0;

  // подаёт получателю следующие байты, не больше `max`
  void feed(tls_session& s, size_t max = size_t(-1)) {
    std::span<byte_t> in = s.input();
    size_t n = std::min({max, in.size(), bytes.size() - fed});
    std::copy_n(bytes.begin() + fed, n, in.begin());
    s.commit_readen_encrypted(n);
    fed += n;
  }
};

// клиент и сервер в памяти после handshake
struct session_pair {
  tls_session client{client_ctx()};
  tls_session server{server_ctx()};
  wire to_server;
  wire to_client;

  session_pair() {
    bool client_done = false;
    bool server_done = false;
    for (int i = 0; i < 10 && !(client_done && server_done); ++i) {
      io_error_code ec;
      if (!client_done) {
        to_client.feed(client);
        client_done = client.handshake(to_server.bytes, /*is_client=*/true, ec);
        REQUIRE(!ec);
      }
      if (!server_done) {
        to_server.feed(server);
        server_done = server.handshake(to_client.bytes, /*is_client=*/false, ec);
        REQUIRE(!ec);
      }
    }
    REQUIRE(client_done);
    REQUIRE(server_done);
    REQUIRE_EQ(to_server.fed, to_server.bytes.size());
    REQUIRE_EQ(to_client.fed, to_client.bytes.size());
    to_server = {};
    to_client = {};
  }
};

// расшифровывает всё из `w`, подавая его кусками по `chunk` байт, в буфер на `plain_size` байт
std::vector<byte_t> decrypt_all(tls_session& s, wire& w, size_t chunk, size_t plain_size) {
  std::vector<byte_t> result;
  std::vector<byte_t> plain(plain_size);
  for (;;) {
    io_error_code ec;
    size_t n = s.decrypt(plain, ec);
    REQUIRE(!ec);
    result.insert(result.end(), plain.begin(), plain.begin() + n);
    if (n == plain.size())
      continue;
    // меньше, чем просили - нужны ещё байты, значит поданное съедено целиком
    if (w.fed == w.bytes.size())
      break;
    w.feed(s, chunk);
  }
  w = {};
  return result;
}

// разбирает заголовки TLS записей, возвращает их число
size_t count_records(std::span<const byte_t> bytes) {
  size_t count = 0;
  while (!bytes.empty()) {
    REQUIRE(bytes.size() >= 5);
    REQUIRE_EQ(bytes[0], 0x17);  // application_data (TLS 1.3 прячет настоящий тип внутрь)
    size_t len = (size_t(bytes[3]) << 8) | bytes[4];
    REQUIRE(bytes.size() >= 5 + len);
    bytes = bytes.subspan(5 + len);
    ++count;
  }
  return count;
}

}  // namespace

// принятые байты подаются любыми кусками: по одному байту, посреди и по границам записей, всё сразу
TEST("tls_session transfers data both ways with any input chunking") {
  const size_t chunk = GENERATE(size_t(1), size_t(7), size_t(1000), size_t(16384 + 22), size_t(-1));
  for (size_t plain_size : {size_t(1), size_t(100), size_t(64 * 1024)}) {
    session_pair p;
    for (size_t size : {size_t(1), size_t(16384), size_t(16385), size_t(300'000)}) {
      std::vector<byte_t> data = random_bytes(size);
      io_error_code ec;
      p.client.encrypt(data, p.to_server.bytes, ec);
      REQUIRE(!ec);
      REQUIRE((decrypt_all(p.server, p.to_server, chunk, plain_size) == data));
      p.server.encrypt(data, p.to_client.bytes, ec);
      REQUIRE(!ec);
      REQUIRE((decrypt_all(p.client, p.to_client, chunk, plain_size) == data));
    }
  }
}

// один encrypt дописывает все записи подряд в конец out
TEST("tls_session encrypt appends all records at once") {
  session_pair p;
  std::vector<byte_t> data = random_bytes(1024 * 1024);
  std::vector<byte_t> out = {1, 2, 3};
  io_error_code ec;
  // клиент: у сервера перед первой записью ещё NewSessionTicket
  p.client.encrypt(data, out, ec);
  REQUIRE(!ec);
  REQUIRE((out[0] == 1 && out[1] == 2 && out[2] == 3));
  REQUIRE_EQ(count_records(std::span(out).subspan(3)), size_t(1024 * 1024 / 16384));
}

// не поместившееся в `plain` отдают следующие вызовы, даже без нового принятого
TEST("tls_session keeps decrypted rest inside") {
  session_pair p;
  std::vector<byte_t> data = random_bytes(1000);
  io_error_code ec;
  p.client.encrypt(data, p.to_server.bytes, ec);
  REQUIRE(!ec);

  std::vector<byte_t> plain(100);
  std::vector<byte_t> result;
  p.to_server.feed(p.server);
  size_t n = p.server.decrypt(plain, ec);
  REQUIRE(!ec);
  REQUIRE_EQ(n, size_t(100));
  REQUIRE_EQ(p.to_server.fed, p.to_server.bytes.size());
  result.insert(result.end(), plain.begin(), plain.end());
  while ((n = p.server.decrypt(plain, ec)) != 0)
    result.insert(result.end(), plain.begin(), plain.begin() + n);
  REQUIRE(!ec);
  REQUIRE((result == data));
}

// decrypt ничего не отправляет: ответ на KeyUpdate уходит перед следующими данными (RFC 8446 4.6.3)
TEST("tls_session answers KeyUpdate with next encrypt") {
  session_pair p;
  std::vector<byte_t> data = random_bytes(10);
  io_error_code ec;
  REQUIRE(SSL_key_update(p.server.native_handle(), SSL_KEY_UPDATE_REQUESTED));
  p.server.encrypt(data, p.to_client.bytes, ec);
  REQUIRE(!ec);
  REQUIRE((decrypt_all(p.client, p.to_client, size_t(-1), 100) == data));

  p.client.encrypt(data, p.to_server.bytes, ec);
  REQUIRE(!ec);
  // KeyUpdate и данные
  REQUIRE_EQ(count_records(p.to_server.bytes), size_t(2));
  REQUIRE((decrypt_all(p.server, p.to_server, size_t(-1), 100) == data));
  // после обновления ключей обе стороны продолжают понимать друг друга
  p.server.encrypt(data, p.to_client.bytes, ec);
  REQUIRE(!ec);
  REQUIRE((decrypt_all(p.client, p.to_client, size_t(-1), 100) == data));
}

// запись с мусором вместо шифротекста - ошибка, и она остаётся
TEST("tls_session error is fatal") {
  session_pair p;
  std::vector<byte_t> garbage(100, 0x17);
  garbage[1] = 3;
  garbage[2] = 3;
  garbage[3] = 0;
  garbage[4] = 95;
  std::vector<byte_t> plain(1000);
  io_error_code ec;
  wire{garbage}.feed(p.server);
  REQUIRE_EQ(p.server.decrypt(plain, ec), size_t(0));
  REQUIRE(ec);

  std::vector<byte_t> data = random_bytes(10);
  ec.clear();
  p.client.encrypt(data, p.to_server.bytes, ec);
  REQUIRE(!ec);
  p.to_server.feed(p.server);
  REQUIRE_EQ(p.server.decrypt(plain, ec), size_t(0));
  REQUIRE(ec);
}

// то, что пир прислал сразу после handshake, достаётся decrypt
TEST("tls_session handshake leaves data after it") {
  tls_session client(client_ctx());
  tls_session server(server_ctx());
  wire to_server;
  wire to_client;
  io_error_code ec;
  REQUIRE(!client.handshake(to_server.bytes, /*is_client=*/true, ec));  // ClientHello
  // ServerHello ... Finished
  to_server.feed(server);
  REQUIRE(!server.handshake(to_client.bytes, /*is_client=*/false, ec));
  // client Finished
  to_client.feed(client);
  REQUIRE(client.handshake(to_server.bytes, /*is_client=*/true, ec));
  REQUIRE(!ec);
  // клиент сразу шифрует данные, сервер получает их вместе с Finished
  std::vector<byte_t> data = random_bytes(100);
  client.encrypt(data, to_server.bytes, ec);
  REQUIRE(!ec);
  to_server.feed(server);
  REQUIRE(server.handshake(to_client.bytes, /*is_client=*/false, ec));
  REQUIRE(!ec);
  std::vector<byte_t> plain(1000);
  plain.resize(server.decrypt(plain, ec));
  REQUIRE(!ec);
  REQUIRE((plain == data));
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
