// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 kelbon (github.com/kelbon)

#pragma once

#include "hidi/asio/aio_context.hpp"
#include "hidi/utils/any_io_context.hpp"

#include <boost/asio/post.hpp>

#include <kelcoro/executor_interface.hpp>

#include "kelcoro/common.hpp"

namespace hidi {

// schedules coroutine to be executed on `ctx`
// if not yet on it
// Note: must not be used as `yield`, since it will never suspend when running in this thread!
struct jump_on_ioctx : dd::task_node {
  any_io_context_ref ctx;

  jump_on_ioctx(any_io_context_ref ref) noexcept : ctx(ref) {
  }

  bool await_ready() noexcept {
    return ctx.running_in_this_thread();
  }

  void await_suspend(std::coroutine_handle<> h) {
    this->task = h;
    ctx.attach(this);
  }

  static void await_resume() noexcept {
  }
};

// schedules coroutine to be executed on `ctx`
// работает для любого boost::asio executor / io_context
struct yield_on_ioctx : dd::task_node {
  any_io_context_ref ctx;

  yield_on_ioctx(any_io_context_ref ref) noexcept : ctx(ref) {
  }
  yield_on_ioctx(any_io_context& ctx) noexcept : ctx(*&ctx) {
  }

  bool await_ready() noexcept {
    return false;
  }

  void await_suspend(std::coroutine_handle<> h) {
    this->task = h;
    ctx.attach(this);
  }

  static void await_resume() noexcept {
  }
};

inline auto yield_on_asio_ioctx(auto& ctx) {
  return dd::suspend_and_t([&](std::coroutine_handle<> h) { boost::asio::post(ctx, h); });
}

#ifndef NDEBUG
  #define HTTP2_ASSUME_THREAD_UNCHANGED_START \
    ::std::thread::id _debug_thread_id = ::std::this_thread::get_id()
// if assertion failed, its likely user callback (handle_request / channel) goes on another thread.
// can be fixed by jump_on_ioctx(request_context.owner_ioctx()) in `handle_request` body
  #define HTTP2_ASSUME_THREAD_UNCHANGED_END assert(_debug_thread_id == ::std::this_thread::get_id())
#else
  #define HTTP2_ASSUME_THREAD_UNCHANGED_START (void)0
  #define HTTP2_ASSUME_THREAD_UNCHANGED_END (void)0
#endif

}  // namespace hidi
