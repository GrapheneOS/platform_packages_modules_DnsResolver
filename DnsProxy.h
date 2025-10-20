// Copyright 2025 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include "rust/cxx.h"

namespace android {
namespace net {
namespace dns_proxy_ffi {
// The DnsMarkCallback implementation must be thread-safe as it is passed
// between threads, and may be concurrently accessed.
using DnsMarkCallback = std::function<uint32_t(uint32_t netId, uint32_t uid)>;
// The NameServersCallback implementation must be thread-safe as it is passed
// between threads, and may be concurrently accessed.
using NameServersCallback =
        std::function<std::unique_ptr<std::vector<std::string>>(uint32_t netId)>;

struct DnsProxyServer;

// Thread-safety: The Rust DnsProxyServer implementation is both Send and Sync and should thus be
// safe to be accessed from multiple threads.
class DnsProxy {
  public:
    // Default constructor depending on DnsResolver global variables.
    DnsProxy();
    DnsProxy(DnsMarkCallback&& dnsMarkCallback, NameServersCallback&& nameServersCallback);

    DnsProxy(DnsProxy const&) = delete;
    void operator=(DnsProxy const&) = delete;

    void configureDnsProxy(uint32_t upstreamNetId, uint32_t uid, uint32_t downstreamIfIndex,
                           uint16_t downstreamPort);
    void stopDnsProxy(uint32_t downstreamIfIndex, uint16_t downstreamPort);

  private:
    rust::Box<DnsProxyServer> mServer;
};
}  // namespace dns_proxy_ffi
}  // namespace net
}  // namespace android
