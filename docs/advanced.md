# Свой цикл событий и транспорт

hidi не привязан к boost asio. Клиент и сервер работают через `hidi::any_io_context` - стёртый тип
([anyany](https://github.com/kelbon/AnyAny)), который даёт цикл событий, таймеры и создаёт соединения.
asio - только реализация по умолчанию (`make_asio_io_context()`), её можно заменить своей

Контекст передаётся в конструктор, любой тип с нужными методами подходит без наследования:

```cpp
hidi::h2server server(ssl, hidi::h2server_options{}, my_io_context{...});
hidi::h2client client(remote, ssl, hidi::h2client_options{}, my_io_context{...});
```

Интерфейсы описаны в заголовках: [any_io_context.hpp](../include/hidi/utils/any_io_context.hpp),
[any_connection.hpp](../include/hidi/any_connection.hpp), [any_timer.hpp](../include/hidi/utils/any_timer.hpp),
[any_acceptor.hpp](../include/hidi/utils/any_acceptor.hpp)

## any_io_context

```cpp
struct my_io_context {
  // цикл событий
  size_t run();
  size_t poll();
  bool poll_one();
  void stop();
  bool stopped();
  void restart();
  bool running_in_this_thread();

  // ставит задачу в конец очереди, никогда не выполняет её сразу
  void attach(dd::task_node*);

  // см. asio_timer
  any_timer create_timer(timer_precision);

  dd::task<any_connection_t> create_connection_client(remote_and_local_endpoints, deadline_t,
                                                      tcp_connection_options, client_ssl_context_ptr);
  any_acceptor create_acceptor(internet_address, bool reuse_address, tcp_connection_options,
                               server_ssl_context_ptr);

  // нужны только для h2server_mt
  void start_task();
  void end_task();
  void* native();
};
```

## any_connection

```cpp
struct my_connection {
  // TLS или нет
  static constexpr bool is_https = false;

  // true, если весь `buf` можно прочитать сразу. Может заменить `buf` своей памятью вместо копирования
  bool try_read(std::span<byte_t>& buf);
  // вызывается только после того как try_read вернул false. Заполняет `buf` целиком (или ставит ec) и
  // продолжает `callback`
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec);

  // пишет сколько может сразу, возвращает сколько записано
  size_t try_write(std::span<const byte_t> buf, io_error_code& ec);
  // дописывает то, что не принял try_write, ставит node->ec и продолжает node->callback
  void start_write(writer_node* node);

  // завершает установку соединения (например TLS handshake), вызывается ровно один раз: сервером для
  // принятых соединений, клиентом для созданных
  dd::task<void> handshake(io_error_code& ec, bool is_client);
  dd::task<void> shutdown();

  // переносит соединение на другой контекст, `native` - его native(). Нужно только для h2server_mt
  void rebind(void* native, rebind_result& r);
};
```

## any_acceptor

```cpp
struct my_acceptor {
  // начинает слушать, возвращает адрес (порт, если был 0)
  internet_address listen();
  internet_address get_local_endpoint() const;
  // следующее соединение. Handshake для него вызовет сервер
  dd::task<any_connection_t> accept(io_error_code& ec);
  void close();
};
```
