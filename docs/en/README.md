# hidi

HTTP/2 implementation in C++20: client and server. Both fully conform to the specification
([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) and pass [h2spec](../../tests/test_h2spec.cpp)

[Русская версия](../../README.md)

[![HTTP Arena H/2](https://img.shields.io/endpoint?url=https://http-arena.com/badge/hidi/h2.json)](https://http-arena.com/#scope=h2&type=engine&tuned=0)

## Getting started

With [CPM](https://github.com/cpm-cmake/CPM.cmake):

```cmake
CPMAddPackage("gh:kelbon/hidi@1.0.0")

target_link_libraries(myapp PRIVATE hidilib)
```

Nothing else needs to be downloaded or installed, everything required comes with hidi: TLS, the
[kelcoro](https://github.com/kelbon/kelcoro) coroutines, [anyany](https://github.com/kelbon/AnyAny),
[HPACK](https://github.com/kelbon/HPACK)

## What is supported

- TLS (h2) and without TLS (h2c)
- streaming of request and response bodies in both directions, trailers
- CONNECT and extended CONNECT, including websocket over HTTP/2 (not the websocket protocol itself, only the ability to plug it in)
- 1xx interim responses
- graceful shutdown, timeouts, pings
- server protection (`h2server_options::hardened()`)

## Documentation

- [Server](server.md)
- [Client](client.md)
- [Custom event loop and transport](advanced.md)

## Where it is used

hidi is a low-level tool used in:

- [svarg](https://github.com/kelbon/svarg) - generates a hidi server and client from an OpenAPI spec
- [BT-YE](https://github.com/kelbon/BT-YE) - framework for building HTTP services
