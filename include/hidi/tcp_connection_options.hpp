#pragma once

#include <cstdint>
#include <vector>
#include <filesystem>
#include <optional>
#include <string>

namespace hidi {

struct tcp_connection_options {
  // SO_SNDBUF / SO_RCVBUF. Если не заданы, размер буферов подбирает ОС
  // (в Linux явно заданный размер отключает автоматическую подстройку буфера)
  std::optional<uint32_t> send_buffer_size = std::nullopt;
  std::optional<uint32_t> receive_buffer_size = std::nullopt;
  static constexpr size_t DEFAULT_WRITE_BUFFER_LIMIT = 64 * 1024;
  // максимальный размер буфера
  // запись в соединение всегда буферизуется (buffered_connection)
  // значение 0 поставит размер по умолчанию
  size_t write_buffer_limit = DEFAULT_WRITE_BUFFER_LIMIT;
  static constexpr size_t DEFAULT_READ_BUFFER_LIMIT = 128 * 1024;
  // больше буфер - меньше системных вызовов на больших входящих данных
  size_t read_buffer_limit = DEFAULT_READ_BUFFER_LIMIT;
  bool is_primal_connection = true;
  /*
    if unset, SSL host name verification disabled.
    On windows it (likely) will produce errors until you add certificates in
    make_ssl_context_for_client(additional_certs)

    if you are receiving error with ssl hanfshake,
    add verify path for your certificate, specially on windows, where default path may be unreachable
    you can download default cerifiers here: (https://curl.se/docs/caextract.html)
  */
  std::optional<std::string> host_for_name_verification = std::nullopt;
};

}  // namespace hidi
