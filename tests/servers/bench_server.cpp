
#include "benchmark_server.hpp"
#include "hidi/asio/awaiters.hpp"

#include <csignal>
#include <iostream>

using namespace hidi;

h2server_mt server(std::in_place_type<bench_server>, h2server_options{},
                   tcp_connection_options{.buffer_writes = true});

void on_ctrl_c(int) {
  server.request_stop();
  std::signal(SIGINT, &on_ctrl_c);
}

int main() try {
  std::signal(SIGINT, &on_ctrl_c);
  asio::ip::tcp::endpoint addr(asio::ip::address_v4::loopback(), 2999);

  server.listen({addr});
  server.run();
} catch (std::exception& e) {
  std::cout << e.what() << std::endl;
}
