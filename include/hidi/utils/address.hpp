// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include <boost/asio/ip/tcp.hpp>

#include <variant>

namespace hidi {

namespace asio = boost::asio;

// only address without port
using ip_addr = asio::ip::address;
// ip + port
using internet_address = asio::ip::tcp::endpoint;

// [ip or fqdn] and port
// fqdn - Fully Qualified Domain Name
struct endpoint {
  std::variant<std::string, ip_addr> addr;
  asio::ip::port_type port = 0;

  endpoint() = default;

  // if port setted to 0, binds correct port
  endpoint(ip_addr a, asio::ip::port_type port = 0) : addr(std::move(a)), port(port) {
  }
  // Note: ignores if `fqdn` contains port already
  explicit endpoint(std::string fqdn, asio::ip::port_type port = 0) : addr(std::move(fqdn)), port(port) {
  }
  endpoint(internet_address a) : endpoint(a.address(), a.port()) {
  }

  // sets both addr and port
  void set_endpoint(internet_address a) noexcept {
    set_addr(a.address());
    set_port(a.port());
  }
  // returns address only if resolved already
  std::optional<internet_address> get_endpoint() const noexcept {
    if (auto* addr = ipaddr())
      return internet_address(*addr, get_port());
    else
      return std::nullopt;
  }

  void set_addr(ip_addr a) noexcept {
    addr = std::move(a);
  }
  void set_fqdn(std::string s) noexcept {
    addr = std::move(s);
  }
  void set_port(asio::ip::port_type p) noexcept {
    port = p;
  }
  asio::ip::port_type get_port() const noexcept {
    return port;
  }

  std::string* fqdn() noexcept {
    return std::get_if<std::string>(&addr);
  }
  const std::string* fqdn() const noexcept {
    return std::get_if<std::string>(&addr);
  }

  ip_addr* ipaddr() noexcept {
    return std::get_if<ip_addr>(&addr);
  }
  const ip_addr* ipaddr() const noexcept {
    return std::get_if<ip_addr>(&addr);
  }

  std::string fqdn_str() const noexcept {
    if (auto* x = fqdn())
      return *x;
    else
      return ipaddr()->to_string();
  }

  std::string to_string() const {
    if (auto* x = fqdn()) {
      if (port == 0)
        return *x;
      else
        return std::format("{}:{}", *x, port);
    } else {
      if (port == 0)
        return ipaddr()->to_string();
      else
        return std::format("{}:{}", ipaddr()->to_string(), port);
    }
  }

  bool operator==(const endpoint&) const = default;
};

}  // namespace hidi
