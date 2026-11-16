
#pragma once

#include "hidi/errors.hpp"
#include "hidi/utils/memory.hpp"
#include "hidi/utils/boost_intrusive.hpp"

#include <span>

#include <anyany/anyany.hpp>
#include <anyany/anyany_macro.hpp>

#include <kelcoro/task.hpp>

#include <boost/intrusive/slist_hook.hpp>

namespace hidi {

struct writer_node : bi::slist_base_hook<> {
  std::coroutine_handle<> callback;
  std::span<const byte_t> data;
  io_error_code& ec;
  ZAL_PIN;

  writer_node(std::span<const byte_t> data1, io_error_code& ec1) noexcept : data(data1), ec(ec1) {
  }
};

// returns false if not enough bytes available
anyany_method2_n(try_read_m, try_read, (&self, std::span<byte_t> buf) requires(self.try_read(buf))->bool);
// pre: try_read returns false!
anyany_method2_n(start_read_m, start_read,
                 (&self, std::coroutine_handle<> callback, std::span<byte_t> buf,
                  io_error_code& ec) requires(self.start_read(callback, buf, ec))
                     ->void);
// tries to write buffer,
// returns number of written bytes (0 on error)
anyany_method2_n(
    try_write_m, try_write,
    (&self, std::span<const byte_t> buf, io_error_code& ec) requires(self.try_write(buf, ec))->size_t);
// pre: node != nullptr
// pre: try_write returns < sent_data.size()
anyany_method2_n(start_write_m, start_write,
                 (&self, writer_node* node) requires(self.start_write(node))->void);
anyany_method2_n(shutdown_m, shutdown, (&self) requires(self.shutdown())->dd::task<void>);
// Завершает установку соединения (например TLS handshake)
// Вызывается ровно один раз
//  сервером для соединений из acceptor,
//  клиентом для соединений из create_connection_client
// `is_client` - сторона handshake
anyany_method2_n(
    handshake_m, handshake,
    (&self, io_error_code& ec, bool is_client) requires(self.handshake(ec, is_client))->dd::task<void>);
// static constexpr bool is_https в типе соединения
anyany_pseudomethod(is_https_m, requires(Self::is_https)->bool);
// Должно быть true если не каждая запись делает системный вызов (так что несколько мелких записей дешёвы)
anyany_pseudomethod(is_buffered_m, requires(Self::is_buffered)->bool);

struct rebind_result;

// перевязывает соединение на другой контекст (нужно только для h2server_mt)
// `native` - native() контекста, на который перевязывается. Соединение знает его тип
// pre: handshake ещё не делался
anyany_method_n(rebind_m, rebind,
                (&self, void* native, rebind_result& r) requires(self.rebind(native, r))->void);

// movable (SooS == 0), pointers to connection are stable
// Note: poly_ref/poly_ptr на any_connection_t ссылаются на vtable внутри него и инвалидируются его move
using any_connection_t =
    aa::basic_any_with_tags<aa::tags<aa::inline_vtable>, aa::default_allocator, /*SooS=*/0, try_read_m,
                            start_read_m, try_write_m, start_write_m, shutdown_m, handshake_m, is_https_m,
                            is_buffered_m, rebind_m, aa::type_info>;

// awaiters for using with .start_write / .start_read

struct read_awaiter {
  any_connection_t& con;
  io_error_code& ec;
  std::span<byte_t> buf;

  bool await_ready() noexcept {
    // использование try_read экономит suspend корутины
    // и для boost asio экономит поход в очередь io_context
    // если данные уже готовы
    // также предотвращает сценарий когда 'start_read' делает .resume без похода в io_context
    // и это вызывает stack overflow на большом потоке данных
    // (каждое чтение == погружение по стеку в await_suspend + .resume)
    return con.try_read(buf);
  }

  void await_suspend(std::coroutine_handle<> h) const {
    con.start_read(h, buf, ec);
  }
  static void await_resume() noexcept {
  }
};

template <typename C>
struct write_awaiter : writer_node {
  C& con;

  write_awaiter(C& con2, io_error_code& ec, std::span<const byte_t> buf) : writer_node(buf, ec), con(con2) {
  }

  bool await_ready() noexcept {
    // использование try_read экономит suspend корутины
    size_t written = con.try_write(data, ec);
    if (written == data.size() || ec)
      return true;
    remove_prefix(data, written);
    return false;
  }

  void await_suspend(std::coroutine_handle<> h) {
    callback = h;
    con.start_write(this);
  }
  static void await_resume() noexcept {
  }
};

}  // namespace hidi
