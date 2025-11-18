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

#include "DnsProxy.h"
#include <cstdint>
#include <memory>
#include "DnsResolver.h"
#include "dns_proxy_cxx_bridge.rs.h"
#include "include/netd_resolv/resolv.h"

namespace android {
namespace net {
namespace dns_proxy_ffi {

// getDnsMark must be thread-safe since it is used in DnsMarkCallback.
uint32_t getDnsMark(ResolverNetdCallbacks& resNetdCallbacks, uint32_t netId, uint32_t uid) {
    android_net_context netContext;
    // Safety: get_network_context is thread-safe since the implementation is
    // behind a mutex lock.
    resNetdCallbacks.get_network_context(netId, uid, &netContext);
    return netContext.dns_mark;
}

// Safety: thread-safe since it is a lambda wrapper of a thread-safe function.
DnsMarkCallback makeDnsMarkCallback(ResolverNetdCallbacks resNetdCallbacks) {
    return [resNetdCallbacks = std::move(resNetdCallbacks)](uint32_t netId, uint32_t uid) mutable {
        return getDnsMark(resNetdCallbacks, netId, uid);
    };
}

// getNameServers must be thread-safe since it is used in NameServersCallback.
std::unique_ptr<std::vector<std::string>> getNameServers(DnsResolver& dnsResolv, uint32_t netId) {
    std::vector<std::string> res_servers;
    std::vector<std::string> res_domains;
    std::vector<std::string> res_tls_servers;
    std::vector<std::string> res_interface_names;
    std::vector<int32_t> params32;
    std::vector<int32_t> stats32;
    int32_t wait_for_pending_req_timeout_count32 = 0;
    // Safety: getResolverInfo is thread-safe since in its implementation, mutex
    // lock is applied when shared information is accessed.
    dnsResolv.resolverCtrl.getResolverInfo(netId, &res_servers, &res_domains, &res_tls_servers,
                                           &res_interface_names, &params32, &stats32,
                                           &wait_for_pending_req_timeout_count32);
    return std::make_unique<std::vector<std::string>>(std::move(res_servers));
}

// Safety: thread-safe since it is a lambda wrapper of a thread-safe function.
NameServersCallback makeNameServersCallback(DnsResolver& dnsResolv) {
    return [&dnsResolv](uint32_t netId) { return getNameServers(dnsResolv, netId); };
}

DnsProxy::DnsProxy(DnsMarkCallback&& dnsMarkCallback, NameServersCallback&& nameServersCallback)
    : mServer(proxy2_server_new(std::make_unique<DnsMarkCallback>(dnsMarkCallback),
                                std::make_unique<NameServersCallback>(nameServersCallback))) {}

// Default constructor depending on DnsResolver global variables.
DnsProxy::DnsProxy()
    : DnsProxy(makeDnsMarkCallback(android::net::gResNetdCallbacks),
               makeNameServersCallback(*android::net::gDnsResolv)) {}

void DnsProxy::configureDnsProxy(uint32_t upstreamNetId, uint32_t uid, uint32_t downstreamIfIndex) {
    mServer->proxy2_server_configure_forwarding(downstreamIfIndex, uid, upstreamNetId);
}

void DnsProxy::stopDnsProxy(uint32_t downstreamIfIndex) {
    mServer->proxy2_server_stop_forwarding(downstreamIfIndex);
}

}  // namespace dns_proxy_ffi
}  // namespace net
}  // namespace android
