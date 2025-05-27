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

// C++-side signature of cpp2rust cxx bridge in dns_proxy/ffi.rs.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "DnsProxy.h"

namespace android {
namespace net {
namespace dns_proxy_ffi {
uint32_t get_dns_mark(const DnsMarkCallback& callback, uint32_t netId, uint32_t uid);
// Signature follows definition in dns_proxy/ffi.rs. The unique pointer wrapper
// is required since C++ vector cannot be passed to rust directly.
std::unique_ptr<std::vector<std::string>> get_name_servers(const NameServersCallback& callback,
                                                           uint32_t netId);
}  // namespace dns_proxy_ffi
}  // namespace net
}  // namespace android
