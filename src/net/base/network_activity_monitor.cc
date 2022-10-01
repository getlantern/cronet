// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_activity_monitor.h"

#include <atomic>
#include <type_traits>

#include "third_party/abseil-cpp/absl/base/attributes.h"

namespace net::activity_monitor {

namespace {

ABSL_CONST_INIT std::atomic<uint64_t> g_bytes_received = 0;

}  // namespace

void IncrementBytesReceived(uint64_t bytes_received) {
  // std::memory_order_relaxed is used because no other operation on
  // |bytes_received_| depends on memory operations that happened before this
  // increment.
  g_bytes_received.fetch_add(bytes_received, std::memory_order_relaxed);
}

uint64_t GetBytesReceived() {
  return g_bytes_received.load(std::memory_order_relaxed);
}

void ResetBytesReceivedForTesting() {
  g_bytes_received = 0;
}

}  // namespace net::activity_monitor
