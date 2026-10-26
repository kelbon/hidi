#pragma once

#include "hidi/asio/io_impl.hpp"

#include <chrono>
#include <vector>

namespace hidi {

namespace noexport {

// Запись с буферизацией (tcp_connection_options::buffer_writes)
// try_write копирует данные в `outbuf` и сразу сообщает, что всё записано. Накопленное отправляет писатель
// одной записью в конце такта, когда выполнятся все уже готовые задачи (например ответы на все запросы,
// прочитанные за одно чтение). Это сильно уменьшает число системных вызовов при множестве мелких записей
// Ошибка записи становится известна позже: её возвращают следующие try_write
// shutdown сначала дописывает принятое (не дольше DRAIN_TIMEOUT), затем закрывает сокет
struct buffered_writer {
  // если в outbuf OUTBUF_LIMIT байт и больше, try_write ничего не принимает и запись ждёт в `waiters`
  static constexpr size_t OUTBUF_LIMIT = 64 * 1024;
  // сколько shutdown ждёт отправки принятого, если пир не читает
  static constexpr std::chrono::seconds DRAIN_TIMEOUT{1};

  // копится до конца такта
  std::vector<byte_t> outbuf;
  // пишется в сокет сейчас, хранится для переиспользования памяти
  std::vector<byte_t> sendbuf;
  // ждут места в outbuf (противодавление), данные переносятся в outbuf в порядке очереди
  bi::slist<writer_node, bi::cache_last<true>> waiters;
  // первая ошибка записи в сокет, после неё запись невозможна
  io_error_code write_ec;
  // писатель ждёт работы. nullptr, если он работает или уже запланирован
  std::coroutine_handle<> writer;
  // shutdown ждёт, пока писатель допишет принятое
  std::coroutine_handle<> drain_waiter;
  bool allow_write = true;
  ZAL_PIN;

  buffered_writer() = default;
  // соединение может быть уничтожено без shutdown (например не удался TLS handshake), писатель в этот момент
  // ждёт работы и должен быть уничтожен
  // pre: писатель не запланирован (иначе нужен shutdown перед уничтожением)
  ~buffered_writer() {
    assert(writer || !allow_write);
    if (writer)
      writer.destroy();
  }

  [[nodiscard]] bool has_work() const noexcept {
    return !outbuf.empty() || !waiters.empty();
  }
  // писатель ждёт работы и работы нет
  [[nodiscard]] bool idle() const noexcept {
    return writer && !has_work();
  }
};

}  // namespace noexport

struct asio_buffered_connection : connection_i {
  asio::ip::tcp::socket sock;
  noexport::single_read_assumption readdata;
  noexport::buffered_writer writedata;

  explicit asio_buffered_connection(asio::ip::tcp::socket);

  bool try_read(std::span<byte_t> buf) noexcept override;
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec) override;
  size_t try_write(std::span<const byte_t>, io_error_code&) noexcept override;
  void start_write(writer_node*) override;
  dd::task<void> shutdown() noexcept override;
  bool is_https() override {
    return false;
  }
};

struct asio_tls_buffered_connection : connection_i {
  noexport::single_read_assumption readdata;
  asio::ssl::stream<asio::ip::tcp::socket> sock;
  ssl_context_ptr sslctx;
  noexport::buffered_writer writedata;

  // precondition: ctx != nullptr
  explicit asio_tls_buffered_connection(asio::ip::tcp::socket s, ssl_context_ptr ctx);

  bool try_read(std::span<byte_t>) noexcept override;
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec) override;
  size_t try_write(std::span<const byte_t>, io_error_code&) noexcept override;
  void start_write(writer_node*) override;
  dd::task<void> shutdown() noexcept override;
  // server side TLS handshake
  dd::task<void> handshake(io_error_code& ec) override;
  bool is_https() override {
    return true;
  }
};

}  // namespace hidi
