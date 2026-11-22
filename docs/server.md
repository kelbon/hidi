# Сервер

Однопоточный сервер создаётся как наследник `hidi::h2server`, переопределяющий по крайней мере `handle_request`. Подробности интерфейса в
[h2server.hpp](../include/hidi/h2server.hpp)

Многопоточный сервер создаётся из однопоточного с помощью `hidi::h2server_mt`

```cpp
#include <hidi/h2server.hpp>

struct my_server : hidi::h2server {
  using hidi::h2server::h2server;

  dd::task<hidi::http_response> handle_request(hidi::http_request req, hidi::request_context) override {
    hidi::http_response rsp;
    rsp.status = 200;
    rsp.headers = {{"content-type", "text/plain"}};
    std::string body = "hello from " + req.path;
    rsp.body.assign(body.begin(), body.end());
    co_return rsp;
  }
};

int main() {
  // поток на каждое ядро, my_server создаётся на каждом потоке из переданных аргументов
  hidi::h2server_mt server(std::in_place_type<my_server>,
                           hidi::make_ssl_context_for_server("server.crt", "server.key"));
  server.listen(hidi::server_endpoint{.addr = {boost::asio::ip::address_v4::any(), 443}});
  server.run();
}
```

- `nullptr` вместо TLS контекста - сервер без TLS
- `my_server` можно использовать напрямую как однопоточный сервер - `listen`, затем `run`
- остановка: `request_stop` (новые сессии не принимаются, текущие запросы дорабатывают)

## Стриминг ответа

Тело отдаётся по кускам из канала (`dd::channel`). Канал может заполнить трейлеры

```cpp
hidi::streaming_body_t by_parts(std::span<const hidi::byte_t> data) {
  for (auto part : data | std::views::chunk(16 * 1024))
    co_yield part;
}

dd::task<hidi::http_response> handle_request(hidi::http_request, hidi::request_context ctx) override {
  // для отправки трейлеров можно использовать streaming_body_with_trailers(by_parts(big_data), <trailer headers>)
  // если трейлеры нужно вычислять от тела, используйте другую перегрузку stream_response вместо хелпера
  co_return ctx.stream_response(200, {}, by_parts(big_data));
}
```

## Стриминг запроса и CONNECT

Чтобы получить запрос сразу после хедеров (до данных), нужно переопределить `answer_before_data` и вернуть `true`.

Тогда вместо `handle_request` вызывается `handle_request_stream`: тело
запроса приходит по кускам через `memory_queue`, а ответ - тоже канал. Так же устроены CONNECT и websocket
(чтобы клиент увидел поддержку сервером websocket, используйте опцию `supports_websocket`)

```cpp
bool answer_before_data(const hidi::http_request& r) const noexcept override {
  return r.method == hidi::http_method_e::CONNECT;
}

// эхо: возвращает всё, что прислал клиент
static hidi::streaming_body_t echo(hidi::memory_queue_ptr q, hidi::request_context) {
  while (!q->last_chunk_received()) {
    auto data = co_await q->next_chunk();
    co_yield data;
  }
}

dd::task<std::pair<hidi::http_response, hidi::bistream_body_maker_t>> handle_request_stream(
    hidi::http_request, hidi::memory_queue_ptr q, hidi::request_context) override {
  hidi::http_response rsp;
  rsp.status = 200;
  co_return {std::move(rsp), std::bind_front(&echo, q)};
}
```

## Опции

Опции сервера подробно описаны в [h2server_options.hpp](../include/hidi/h2server_options.hpp)

Отдельно стоит упомянуть `h2server_options::hardened()` - готовый набор опций для защиты сервера, выходящего в открытый интернет

