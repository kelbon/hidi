#pragma once

#include "hidi/errors.hpp"
#include "hidi/utils/memory.hpp"
#include "hidi/utils/readahead_buffer.hpp"

#include <openssl/ssl.h>

#include <span>
#include <vector>

namespace hidi {

struct tls_session {
 private:
  // BIO, через который TLS библиотека читает `unread` и пишет в `to_send`
  struct bio;

  // шифротекста в одной TLS записи не больше 2^14 + 256 байт и 5 байт заголовка (RFC 8446, 5.2)
  static constexpr size_t MAX_RECORD_SIZE = (1 << 14) + 256 + 5;

  SSL* ssl = nullptr;
  // шифрованные данные полученные, но ещё не обработанные
  readahead_buffer raf;

 public:
  // до handshake сессию можно настроить через native_handle (SNI, проверка сертификата)
  // `input_limit` - до какого размера растёт буфер принятого
  explicit tls_session(SSL_CTX* ctx, size_t input_limit = MAX_RECORD_SIZE);

  tls_session(tls_session&&) = delete;
  void operator=(tls_session&&) = delete;
  ~tls_session();

  // куда читать принятое от пира. Сколько прочитано, сообщает commit_readen_encrypted
  // не пуст, если последний handshake / decrypt сообщил, что принятого не хватает
  [[nodiscard]] std::span<byte_t> input() noexcept;
  // в начало input() прочитано `n` байт
  void commit_readen_encrypted(size_t n) noexcept;

  // продвигает handshake на принятом, сообщения пиру дописывает в `to_send`
  // возвращает true, когда handshake завершён: то, что пир прислал после него, достанется decrypt
  // false без ec - нужно ещё принятого (всё принятое съедено)
  // `is_client` одинаков во всех вызовах
  [[nodiscard]] bool handshake(std::vector<byte_t>& to_send, bool is_client, io_error_code& ec);

  // расшифровывает принятое в начало `plain`, возвращает сколько записано
  // вернул меньше plain.size() без ec - нужно ещё принятого (всё принятое съедено)
  // вернул plain.size() - в сессии могло остаться принятое, его вернут следующие вызовы
  // ec == asio::error::eof - пир закрыл соединение (close_notify). Расшифрованное до ошибки уже в `plain`
  // ничего не отправляет пиру (см. реализацию), поэтому расшифровывать можно, пока пишется результат encrypt
  // pre: handshake завершён
  [[nodiscard]] size_t decrypt(std::span<byte_t> plain, io_error_code& ec);

  // шифрует весь `plain` (записями по 2^14 байт), дописывает в конец `to_send`
  // при ошибке в `to_send` может быть дописана часть, отправлять её не нужно
  // pre: handshake завершён
  void encrypt(std::span<const byte_t> plain, std::vector<byte_t>& to_send, io_error_code& ec);

  SSL* native_handle() noexcept {
    return ssl;
  }
};

}  // namespace hidi
