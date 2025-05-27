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

// DNS Proxy AIDL header.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "DnsResolver.h"

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
}  // namespace dns_proxy_ffi
}  // namespace net
}  // namespace android
