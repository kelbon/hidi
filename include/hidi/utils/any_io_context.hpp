#pragma once

#include "hidi/any_connection.hpp"
#include "hidi/utils/any_timer.hpp"
#include "hidi/utils/any_acceptor.hpp"
#include "hidi/utils/address.hpp"
#include "hidi/asio/ssl_context.hpp"
#include "hidi/tcp_connection_options.hpp"

#include <kelcoro/executor_interface.hpp>
#include <kelcoro/task.hpp>

namespace hidi {

// returns true if executes something
anyany_method2_n(poll_one_m, poll_one, (&self) requires(self.poll_one())->bool);
// returns count of executed tasks
anyany_method2_n(poll_m, poll, (&self) requires(self.poll())->size_t);
anyany_method2_n(run_m, run, (&self) requires(self.run())->size_t);
// stops run
anyany_method2_n(stop_m, stop, (&self) requires(self.stop())->void);
// stop was called
anyany_method2_n(stopped_m, stopped, (&self) requires(self.stopped())->bool);
// allows call .run / poll / poll_one again
anyany_method2_n(restart_m, restart, (&self) requires(self.restart())->void);

// нужно только в h2server_mt. Помечает для 'run', что прекращать run нельзя
anyany_method2_n(start_task_m, start_task, (&self) requires(self.start_task())->void);

// нужно только в h2server_mt. Помечает для 'run', что работа начатая в 'start_task' окончена
anyany_method2_n(end_task_m, end_task, (&self) requires(self.end_task())->void);

anyany_method2_n(running_in_this_thread_m, running_in_this_thread,
                 (&self) requires(self.running_in_this_thread())->bool);

anyany_method2_n(create_timer_m, create_timer, (&self) requires(self.create_timer())->any_timer);
// never invokes task immediately, pushes it into queue always
// may be invoked from another thread (ONLY IN h2server_mt)
// 'attach' for compatibility with dd::any_executor_ref
anyany_method2_n(attach_task_m, attach, (&self, dd::task_node* n) requires(self.attach(n))->void);

struct remote_and_local_endpoints {
  // required, may be resolved
  endpoint remote;
  // optional, already resolved
  std::optional<internet_address> local = std::nullopt;
};

// Контекст - цикл событий и фабрика соединений. Как соединение устроено (TLS или нет, параметры TCP) задаёт
// создающий его клиент или сервер, поэтому на одном контексте живут и TLS, и обычные соединения

// creates TCP-like connection (client-side). `ssl` == nullptr - без TLS
anyany_method2_n(create_connection_client_m, create_connection_client,
                 (&self, remote_and_local_endpoints e, deadline_t d, tcp_connection_options opts,
                  client_ssl_context_ptr ssl) requires(self.create_connection_client(e, d, opts, ssl))
                     ->dd::task<any_connection_t>);
// creates TCP-like acceptor, which creates server-side connections in 'accept'. `ssl` == nullptr - без TLS
anyany_method2_n(create_acceptor_m, create_acceptor,
                 (&self, internet_address addr, bool reuse_address, tcp_connection_options opts,
                  server_ssl_context_ptr ssl) requires(self.create_acceptor(addr, reuse_address, opts, ssl))
                     ->any_acceptor);

struct rebind_context_m;

// movable (SooS == 0)
using any_io_context =
    aa::basic_any_with<aa::default_allocator, /*SooS=*/0, create_timer_m, attach_task_m, poll_one_m, poll_m,
                       run_m, stop_m, stopped_m, restart_m, running_in_this_thread_m,
                       create_connection_client_m, create_acceptor_m, rebind_context_m, start_task_m,
                       end_task_m, aa::type_info>;

using any_io_context_ref = any_io_context::ref;
using any_io_context_ptr = any_io_context::ptr;

using rebind_context_method_t = void (*)(any_connection_t&, any_io_context_ref);
// нужно только для h2server_mt
// static метод
// 'con' было получено из accept/create_connection_client этого контекста
// `other` такого же типа как и self
// никак не трогает self, по сути "статическая" функция
// con != nullptr
anyany_pseudomethod(rebind_context_m, requires(&Self::rebind_context)->rebind_context_method_t);

}  // namespace hidi
