# hidi

Реализация HTTP/2 на C++20: клиент и сервер. Полностью соответствуют спецификации
([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)), проходят [h2spec](tests/test_h2spec.cpp)

[English version](docs/en/README.md)

[![HTTP Arena H/2](https://img.shields.io/endpoint?url=https://http-arena.com/badge/hidi/h2.json)](https://http-arena.com/#scope=h2&type=engine&tuned=0)

## Подключение

Через [CPM](https://github.com/cpm-cmake/CPM.cmake):

```cmake
CPMAddPackage("gh:kelbon/hidi@1.0.0")

target_link_libraries(myapp PRIVATE hidilib)
```

Больше ничего скачивать и ставить не нужно, всё нужное приходит вместе с hidi: TLS, корутины
[kelcoro](https://github.com/kelbon/kelcoro), [anyany](https://github.com/kelbon/AnyAny),
[HPACK](https://github.com/kelbon/HPACK)

## Что поддержано

- TLS (h2) и без TLS (h2c)
- стриминг тела запроса и ответа в обе стороны, трейлеры
- CONNECT и extended CONNECT, в том числе websocket поверх HTTP/2 (но не сам websocket протокол, только возможность его подключить)
- промежуточные ответы 1xx
- graceful shutdown, таймауты, пинги
- защита сервера (`h2server_options::hardened()`)

## Документация

- [Сервер](docs/server.md)
- [Клиент](docs/client.md)
- [Свой цикл событий и транспорт](docs/advanced.md)

## Где используется

hidi это низкоуровневый инструмент, использующийся в:

- [svarg](https://github.com/kelbon/svarg) - генерирует из OpenAPI спеки сервер и клиент на hidi
- [BT-YE](https://github.com/kelbon/BT-YE) - фреймворк для создания HTTP сервисов
