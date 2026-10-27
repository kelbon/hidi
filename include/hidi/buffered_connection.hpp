#pragma once

#include "hidi/any_connection.hpp"
#include "hidi/utils/any_io_context.hpp"

#include <boost/intrusive/slist.hpp>

#include <chrono>
#include <vector>

namespace hidi {

// Запись с буферизацией (tcp_connection_options::buffer_writes) поверх любого соединения
// try_write копирует данные в `outbuf` и сразу сообщает, что всё записано. Накопленное отправляет писатель
// одной записью в конце такта, когда выполнятся все уже готовые задачи (например ответы на все запросы,
// прочитанные за одно чтение). Это сильно уменьшает число системных вызовов при множестве мелких записей
// Ошибка записи становится известна позже: её возвращают следующие try_write
// shutdown сначала дописывает принятое (не дольше DRAIN_TIMEOUT), затем закрывает внутреннее соединение
// Чтение, handshake и is_https передаются внутреннему соединению
struct buffered_connection final : connection_i {
  // если в outbuf OUTBUF_LIMIT байт и больше, try_write ничего не принимает и запись ждёт в `waiters`
  static constexpr size_t OUTBUF_LIMIT = 64 * 1024;
  // сколько shutdown ждёт отправки принятого, если пир не читает
  static constexpr std::chrono::seconds DRAIN_TIMEOUT{1};

  any_connection_t inner;
  // планирует отправку в конце такта и создаёт таймер для shutdown. Меняется при rebind
  any_io_context_ref io;

  // копится до конца такта
  std::vector<byte_t> outbuf;
  // пишется сейчас, хранится для переиспользования памяти
  std::vector<byte_t> sendbuf;
  // ждут места в outbuf (противодавление), данные переносятся в outbuf в порядке очереди
  bi::slist<writer_node, bi::cache_last<true>> waiters;
  // первая ошибка записи, после неё запись невозможна
  io_error_code write_ec;
  // писатель ждёт работы. nullptr, если он работает или уже запланирован
  std::coroutine_handle<> writer;
  // shutdown ждёт, пока писатель допишет принятое
  std::coroutine_handle<> drain_waiter;
  // узлы для io.attach: в очереди одновременно не больше одного запланированного писателя и одного shutdown
  dd::task_node writer_task;
  dd::task_node drain_task;
  bool allow_write = true;
  ZAL_PIN;

  // pre: inner != nullptr
  buffered_connection(any_connection_t inner, any_io_context_ref io);
  // соединение может быть уничтожено без shutdown (например не удался TLS handshake), писатель в этот момент
  // ждёт работы и должен быть уничтожен
  // pre: писатель не запланирован (иначе нужен shutdown перед уничтожением)
  ~buffered_connection() override;

  bool try_read(std::span<byte_t> buf) noexcept override {
    return inner->try_read(buf);
  }
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec) override {
    inner->start_read(callback, buf, ec);
  }
  size_t try_write(std::span<const byte_t>, io_error_code&) noexcept override;
  void start_write(writer_node*) override;
  dd::task<void> shutdown() noexcept override;
  dd::task<void> handshake(io_error_code& ec, bool is_client) override {
    return inner->handshake(ec, is_client);
  }
  bool is_https() override {
    return inner->is_https();
  }

  [[nodiscard]] bool has_work() const noexcept {
    return !outbuf.empty() || !waiters.empty();
  }
  // писатель ждёт работы и работы нет
  [[nodiscard]] bool idle() const noexcept {
    return writer && !has_work();
  }
  // писатель отправит накопленное в конце такта: всё, что уже готово выполниться, успеет дописать в outbuf
  void schedule_writer();
};

// оборачивает соединение в buffered_connection, если включена tcp_connection_options::buffer_writes
inline any_connection_t maybe_buffered(any_connection_t con, bool buffer_writes, any_io_context_ref io) {
  if (!buffer_writes)
    return con;
  return any_connection_t(new buffered_connection(std::move(con), io));
}

// для rebind_context: перевязывает buffered_connection на `other` и возвращает соединение, которое нужно
// перевязать реализации (внутреннее для buffered_connection, иначе само `con`)
inline any_connection_t& rebind_buffered(any_connection_t& con, any_io_context_ref other) noexcept {
  if (auto* b = dynamic_cast<buffered_connection*>(con.get())) {
    b->io = std::move(other);
    return b->inner;
  }
  return con;
}

}  // namespace hidi
