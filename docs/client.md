# Клиент

`hidi::h2client` держит одно соединение с сервером и сам его устанавливает при запросе, если не подключен

Подробно интерфейс описан в [h2client.hpp](../include/hidi/h2client.hpp)

### Примеры

```cpp
#include <print>

#include <hidi/h2client.hpp>

dd::task<void> get(hidi::h2client& client) {
  hidi::http_request req{.path = "/hello"};
  hidi::http_response rsp =
      co_await client.send_request(std::move(req), hidi::deadline_after(std::chrono::seconds(5)));
  std::println("{} {}", rsp.status, rsp.body_strview());
  client.ioctx().stop();
}

int main() {
  hidi::h2client client(hidi::endpoint(std::string("example.com"), 443),
                        hidi::make_ssl_context_for_client({}));
  get(client).start_and_detach();
  client.ioctx().run();
}
```

- `nullptr` вместо TLS контекста - клиент без TLS
- `send_request(req, deadline)` при ошибке бросает исключение. Версия с `on_header` / `on_data_part`
  получает ответ по кускам и возвращает статус, при ошибке еррор код

## Стриминг запроса

Тело запроса отдаётся по кускам из канала:

```cpp
hidi::streaming_body_t greeting() {
  co_yield std::string_view("hello, ");
  co_yield std::string_view("world");
}

dd::task<void> send(hidi::h2client& client) {
  hidi::http_request req{.path = "/greet", .method = hidi::http_method_e::POST};
  hidi::http_response rsp = co_await client.send_streaming_request(
      std::move(req), greeting(), hidi::deadline_after(std::chrono::seconds(5)));
}
```

## CONNECT

`send_connect_request` открывает туннель (CONNECT или extended CONNECT, например websocket)

```cpp
dd::task<void> tunnel(hidi::h2client& client) {
  hidi::http_request req{.path = "/chat", .method = hidi::http_method_e::CONNECT};
  req.headers = {{":protocol", "websocket"}};
  // вызовется после получения HEADERS от сервера. Будущие данные представлены очередью `q`
  // данные возвращённые через co_yield отправляются серверу
  auto makestream = [](hidi::http_response, hidi::memory_queue_ptr q,
                       hidi::request_context) -> hidi::streaming_body_t {
    co_yield std::string_view("ping");
    auto answer = co_await q->next_chunk();
  };
  int status = co_await client.send_connect_request(std::move(req), std::move(makestream));
}
```

## Опции

Опции клиента подробно описаны в [h2client_options.hpp](../include/hidi/h2client_options.hpp):
