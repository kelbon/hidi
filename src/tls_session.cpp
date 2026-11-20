#include "hidi/tls_session.hpp"

#include <boost/asio/error.hpp>
#include <boost/asio/ssl/error.hpp>

#include <cassert>
#include <climits>
#include <cstring>

namespace hidi {

struct tls_session::bio {
  static int read(BIO* b, char* buf, int len) {
    BIO_clear_retry_flags(b);
    tls_session& s = *static_cast<tls_session*>(BIO_get_data(b));
    if (s.raf.available_count() == 0) {
      BIO_set_retry_read(b);
      return -1;
    }
    size_t n = s.raf.read_some_r(std::span((byte_t*)buf, len));
    return int(n);
  }

  static int write(BIO* b, const char* buf, int len) {
    BIO_clear_retry_flags(b);
    auto* out = static_cast<std::vector<byte_t>*>(BIO_get_data(b));
    if (!out)
      return len;
    // исключение не должно пройти через TLS библиотеку, нехватка памяти становится ошибкой SSL_*
    try {
      out->insert(out->end(), (const byte_t*)buf, (const byte_t*)buf + len);
    } catch (...) {
      return -1;
    }
    return len;
  }

  static long ctrl(BIO*, int cmd, long, void*) {
    // запись завершается сразу, сбрасывать нечего
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
  }

  static BIO_METHOD* get() {
    // никто не вызывает BIO_meth_free - SSL сессии хер знает как держат `m`,
    // а "утечку" статического объекта даже асан игнорирует
    static BIO_METHOD* m = [] {
      BIO_METHOD* r = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "name");
      if (!r || !BIO_meth_set_read(r, &read) || !BIO_meth_set_write(r, &write) ||
          !BIO_meth_set_ctrl(r, &ctrl))
        throw std::bad_alloc{};
      return r;
    }();
    return m;
  }
};

namespace {

// на время вызова направляет запись TLS библиотеки в `out`
struct output_scope {
  BIO* wbio;

  output_scope(BIO* wbio, std::vector<byte_t>* out) noexcept : wbio(wbio) {
    BIO_set_data(wbio, out);
  }
  ~output_scope() {
    BIO_set_data(wbio, nullptr);
  }
};

// после неудачного SSL_* заполняет ec, если дело не в нехватке принятых байт
void set_error(SSL* ssl, int r, io_error_code& ec) {
  switch (SSL_get_error(ssl, r)) {
    case SSL_ERROR_WANT_READ:
      return;
    case SSL_ERROR_ZERO_RETURN:
      ec = boost::asio::error::eof;
      return;
    case SSL_ERROR_SSL:
      if (unsigned long e = ERR_get_error())
        ec = io_error_code(int(e), boost::asio::error::get_ssl_category());
      else
        ec = boost::asio::ssl::error::unspecified_system_error;
      return;
    default:
      // BIO не блокирует запись и не сообщает о конце потока, так что остаётся только отказ его записи
      ec = boost::asio::error::no_memory;
      return;
  }
}

}  // namespace

tls_session::tls_session(SSL_CTX* ctx) {
  ssl = SSL_new(ctx);
  BIO* rbio = BIO_new(bio::get());
  BIO* wbio = BIO_new(bio::get());
  if (!ssl || !rbio || !wbio) {
    SSL_free(ssl);
    BIO_free(rbio);
    BIO_free(wbio);
    throw std::bad_alloc{};
  }
  BIO_set_init(rbio, 1);
  BIO_set_init(wbio, 1);
  BIO_set_data(rbio, this);
  // забирает владение над rbio, wbio
  SSL_set_bio(ssl, rbio, wbio);
}

tls_session::~tls_session() {
  SSL_free(ssl);
}

std::span<byte_t> tls_session::input() noexcept {
  return raf.input();
}

void tls_session::commit_readen_encrypted(size_t n) noexcept {
  raf.commit_readen(n);
}

bool tls_session::handshake(std::vector<byte_t>& to_send, bool is_client, io_error_code& ec) {
  ERR_clear_error();
  output_scope out(SSL_get_wbio(ssl), &to_send);
  // сторону задаёт первый вызов SSL_connect / SSL_accept, дальше они просто продолжают handshake
  int r = is_client ? SSL_connect(ssl) : SSL_accept(ssl);
  if (r == 1)
    return true;
  set_error(ssl, r, ec);
  return false;
}

size_t tls_session::decrypt(std::span<byte_t> plain, io_error_code& ec) {
  ERR_clear_error();
  // во время SSL_read AWS-LC пишет только фатальный алерт, после которого сессия непригодна. Ответ на
  // KeyUpdate он откладывает до следующего SSL_write, то есть до encrypt
  output_scope out(SSL_get_wbio(ssl), nullptr);
  // SSL_read отдаёт не больше одной записи за вызов
  size_t n = 0;
  while (n < plain.size()) {
    int r = SSL_read(ssl, plain.data() + n, int(std::min<size_t>(plain.size() - n, INT_MAX)));
    if (r <= 0) {
      set_error(ssl, r, ec);
      break;
    }
    n += size_t(r);
  }
  return n;
}

void tls_session::encrypt(std::span<const byte_t> plain, std::vector<byte_t>& to_send, io_error_code& ec) {
  // одно выделение памяти вместо роста на каждой записи. Запас на заголовок, nonce и тег записи примерный
  constexpr size_t MAX_RECORD_PLAIN_SIZE = 1 << 14;
  constexpr size_t RECORD_OVERHEAD = 64;
  try {
    to_send.reserve(to_send.size() + plain.size() +
                    (plain.size() / MAX_RECORD_PLAIN_SIZE + 1) * RECORD_OVERHEAD);
  } catch (...) {
    ec = boost::asio::error::no_memory;
    return;
  }
  ERR_clear_error();
  output_scope out(SSL_get_wbio(ssl), &to_send);
  while (!plain.empty()) {
    // без SSL_MODE_ENABLE_PARTIAL_WRITE и с BIO, который не блокирует, SSL_write шифрует всё переданное сразу
    int r = SSL_write(ssl, plain.data(), int(std::min<size_t>(plain.size(), INT_MAX)));
    if (r <= 0) {
      set_error(ssl, r, ec);
      if (!ec)  // например handshake не завершён
        ec = boost::asio::ssl::error::unspecified_system_error;
      return;
    }
    plain = plain.subspan(size_t(r));
  }
}

}  // namespace hidi
