#include "hidi/asio/io.hpp"

#include "hidi/asio/io_impl.hpp"

namespace hidi {

any_io_context make_asio_io_context() {
  return any_io_context(aa::inplaced{[&] { return asio_io(); }});
}

any_io_context make_asio_io_context(asio::io_context& ctx) {
  return any_io_context(aa::inplaced{[&] { return asio_ref_io(ctx); }});
}

}  // namespace hidi
