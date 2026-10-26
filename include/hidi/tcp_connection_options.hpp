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
  std::vector<std::filesystem::path> additional_ssl_certificates;
  // adds delay (waiting for new requests to merge them)
  bool merge_small_requests = false;
  bool is_primal_connection = true;
  /*
    if unset, SSL host name verification disabled.
    On windows it (likely) will produce errors until you set
    'additional_ssl_certificates'

    if you are receiving error with ssl hanfshake,
    add verify path for your certificate, specially on windows, where default path may be unreachable
    you can download default cerifiers here: (https://curl.se/docs/caextract.html)
  */
  std::optional<std::string> host_for_name_verification = std::nullopt;
};

}  // namespace hidi
