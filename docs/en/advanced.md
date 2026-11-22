# Custom event loop and transport

hidi is not tied to boost asio. The client and the server work through `hidi::any_io_context` - a type-erased type
([anyany](https://github.com/kelbon/AnyAny)) that provides the event loop and timers and creates connections.
asio is only the default implementation (`make_asio_io_context()`), it can be replaced with your own

The context is passed to the constructor, any type with the required methods fits without inheritance:

```cpp
hidi::h2server server(ssl, hidi::h2server_options{}, my_io_context{...});
hidi::h2client client(remote, ssl, hidi::h2client_options{}, my_io_context{...});
```

The interfaces are described in the headers: [any_io_context.hpp](../../include/hidi/utils/any_io_context.hpp),
[any_connection.hpp](../../include/hidi/any_connection.hpp), [any_timer.hpp](../../include/hidi/utils/any_timer.hpp),
[any_acceptor.hpp](../../include/hidi/utils/any_acceptor.hpp)

## any_io_context

```cpp
struct my_io_context {
  // event loop
  size_t run();
  size_t poll();
  bool poll_one();
  void stop();
  bool stopped();
  void restart();
  bool running_in_this_thread();

  // puts the task at the end of the queue, never executes it immediately
  void attach(dd::task_node*);

  // see asio_timer
  any_timer create_timer(timer_precision);

  dd::task<any_connection_t> create_connection_client(remote_and_local_endpoints, deadline_t,
                                                      tcp_connection_options, client_ssl_context_ptr);
  any_acceptor create_acceptor(internet_address, bool reuse_address, tcp_connection_options,
                               server_ssl_context_ptr);

  // needed only for h2server_mt
  void start_task();
  void end_task();
  void* native();
};
```

## any_connection

```cpp
struct my_connection {
  // TLS or not
  static constexpr bool is_https = false;

  // true if the whole `buf` can be read immediately. May replace `buf` with its own memory instead of copying
  bool try_read(std::span<byte_t>& buf);
  // called only after try_read returned false. Fills `buf` completely (or sets ec) and
  // resumes `callback`
  void start_read(std::coroutine_handle<> callback, std::span<byte_t> buf, io_error_code& ec);

  // writes as much as it can immediately, returns how much is written
  size_t try_write(std::span<const byte_t> buf, io_error_code& ec);
  // writes what try_write did not accept, sets node->ec and resumes node->callback
  void start_write(writer_node* node);

  // completes connection establishment (for example the TLS handshake), called exactly once: by the server for
  // accepted connections, by the client for created ones
  dd::task<void> handshake(io_error_code& ec, bool is_client);
  dd::task<void> shutdown();

  // moves the connection to another context, `native` is its native(). Needed only for h2server_mt
  void rebind(void* native, rebind_result& r);
};
```

## any_acceptor

```cpp
struct my_acceptor {
  // starts listening, returns the address (and the port if it was 0)
  internet_address listen();
  internet_address get_local_endpoint() const;
  // the next connection. The server will call the handshake for it
  dd::task<any_connection_t> accept(io_error_code& ec);
  void close();
};
```
