/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "dns_responder_client"

#include "dns_responder_client_ndk.h"

#include <android/binder_manager.h>
#include "NetdClient.h"

#define TEST_NETID 30

// TODO: move this somewhere shared.
static const char* ANDROID_DNS_MODE = "ANDROID_DNS_MODE";

using aidl::android::net::IDnsResolver;
using aidl::android::net::INetd;
using aidl::android::net::ResolverOptionsParcel;
using aidl::android::net::ResolverParamsParcel;
using aidl::android::net::resolv::aidl::DohParamsParcel;
using android::base::Error;
using android::base::Result;
using android::net::ResolverStats;

ResolverParams::Builder::Builder() {
    // Default resolver configuration for opportunistic mode.
    mParcel.netId = TEST_NETID;

    // Default Resolver params.
    mParcel.sampleValiditySeconds = 300;
    mParcel.successThreshold = 25;
    mParcel.minSamples = 8;
    mParcel.maxSamples = 8;
    mParcel.baseTimeoutMsec = 1000;
    mParcel.retryCount = 2;

    mParcel.servers = {kDefaultServer};
    mParcel.domains = {kDefaultSearchDomain};
    mParcel.tlsServers = {kDefaultServer};
    mParcel.caCertificate = kCaCert;
    mParcel.resolverOptions = ResolverOptionsParcel{};  // optional, must be explicitly set.
    mParcel.dohParams = std::nullopt;
}

void DnsResponderClient::SetupMappings(unsigned numHosts, const std::vector<std::string>& domains,
                                       std::vector<Mapping>* mappings) {
    mappings->resize(numHosts * domains.size());
    auto mappingsIt = mappings->begin();
    for (unsigned i = 0; i < numHosts; ++i) {
        for (const auto& domain : domains) {
            mappingsIt->host = fmt::format("host{}", i);
            mappingsIt->entry = fmt::format("{}.{}.", mappingsIt->host, domain);
            mappingsIt->ip4 = fmt::format("192.0.2.{}", i % 253 + 1);
            mappingsIt->ip6 = fmt::format("2001:db8::{:x}", i % 65534 + 1);
            ++mappingsIt;
        }
    }
}

Result<ResolverInfo> DnsResponderClient::getResolverInfo() {
    std::vector<std::string> dnsServers;
    std::vector<std::string> domains;
    std::vector<std::string> dotServers;
    std::vector<int32_t> params;
    std::vector<int32_t> stats;
    std::vector<int32_t> waitForPendingReqTimeoutCount{0};
    auto rv = mDnsResolvSrv->getResolverInfo(TEST_NETID, &dnsServers, &domains, &dotServers,
                                             &params, &stats, &waitForPendingReqTimeoutCount);
    if (!rv.isOk()) {
        return Error() << "getResolverInfo failed: " << rv.getMessage();
    }
    if (stats.size() % IDnsResolver::RESOLVER_STATS_COUNT != 0) {
        return Error() << "Unexpected stats size: " << stats.size();
    }
    if (params.size() != IDnsResolver::RESOLVER_PARAMS_COUNT) {
        return Error() << "Unexpected params size: " << params.size();
    }
    if (waitForPendingReqTimeoutCount.size() != 1) {
        return Error() << "Unexpected waitForPendingReqTimeoutCount size: "
                       << waitForPendingReqTimeoutCount.size();
    }

    ResolverInfo out = {
            .dnsServers = std::move(dnsServers),
            .domains = std::move(domains),
            .dotServers = std::move(dotServers),
            .params{
                    .sample_validity = static_cast<uint16_t>(
                            params[IDnsResolver::RESOLVER_PARAMS_SAMPLE_VALIDITY]),
                    .success_threshold = static_cast<uint8_t>(
                            params[IDnsResolver::RESOLVER_PARAMS_SUCCESS_THRESHOLD]),
                    .min_samples =
                            static_cast<uint8_t>(params[IDnsResolver::RESOLVER_PARAMS_MIN_SAMPLES]),
                    .max_samples =
                            static_cast<uint8_t>(params[IDnsResolver::RESOLVER_PARAMS_MAX_SAMPLES]),
                    .base_timeout_msec = params[IDnsResolver::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC],
                    .retry_count = params[IDnsResolver::RESOLVER_PARAMS_RETRY_COUNT],
            },
            .stats = {},
            .waitForPendingReqTimeoutCount = waitForPendingReqTimeoutCount[0],
    };
    ResolverStats::decodeAll(stats, &out.stats);

    return std::move(out);
}

bool DnsResponderClient::SetResolversForNetwork(const std::vector<std::string>& servers,
                                                const std::vector<std::string>& domains) {
    const auto resolverParams = ResolverParams::Builder()
                                        .setDomains(domains)
                                        .setDnsServers(servers)
                                        .setDotServers({})
                                        .build();
    const auto rv = mDnsResolvSrv->setResolverConfiguration(resolverParams);
    return rv.isOk();
}

bool DnsResponderClient::SetResolversFromParcel(const ResolverParamsParcel& resolverParams) {
    const auto rv = mDnsResolvSrv->setResolverConfiguration(resolverParams);
    if (!rv.isOk()) LOG(ERROR) << "SetResolversFromParcel() -> " << rv.getMessage();
    return rv.isOk();
}

ResolverParamsParcel DnsResponderClient::GetDefaultResolverParamsParcel() {
    return ResolverParams::Builder().build();
}

void DnsResponderClient::SetupDNSServers(unsigned numServers, const std::vector<Mapping>& mappings,
                                         std::vector<std::unique_ptr<test::DNSResponder>>* dns,
                                         std::vector<std::string>* servers) {
    const char* listenSrv = "53";
    dns->resize(numServers);
    servers->resize(numServers);
    for (unsigned i = 0; i < numServers; ++i) {
        auto& server = (*servers)[i];
        auto& d = (*dns)[i];
        server = fmt::format("127.0.0.{}", i + 100);
        d = std::make_unique<test::DNSResponder>(server, listenSrv, ns_rcode::ns_r_servfail);
        for (const auto& mapping : mappings) {
            d->addMapping(mapping.entry.c_str(), ns_type::ns_t_a, mapping.ip4.c_str());
            d->addMapping(mapping.entry.c_str(), ns_type::ns_t_aaaa, mapping.ip6.c_str());
        }
        d->startServer();
    }
}

int DnsResponderClient::SetupOemNetwork(int oemNetId) {
    mNetdSrv->networkDestroy(oemNetId);
    mDnsResolvSrv->destroyNetworkCache(oemNetId);

    ::ndk::ScopedAStatus ret;
    if (DnsResponderClient::isRemoteVersionSupported(mNetdSrv, 6)) {
        const auto& config = DnsResponderClient::makeNativeNetworkConfig(
                oemNetId, NativeNetworkType::PHYSICAL, INetd::PERMISSION_NONE, /*secure=*/false);
        ret = mNetdSrv->networkCreate(config);
    } else {
        // Only for presubmit tests that run mainline module (and its tests) on R or earlier images.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        ret = mNetdSrv->networkCreatePhysical(oemNetId, INetd::PERMISSION_NONE);
#pragma clang diagnostic pop
    }
    if (!ret.isOk()) {
        fprintf(stderr, "Creating physical network %d failed, %s\n", oemNetId, ret.getMessage());
        return -1;
    }
    ret = mDnsResolvSrv->createNetworkCache(oemNetId);
    if (!ret.isOk()) {
        fprintf(stderr, "Creating network cache %d failed, %s\n", oemNetId, ret.getMessage());
        return -1;
    }
    setNetworkForProcess(oemNetId);
    if ((unsigned)oemNetId != getNetworkForProcess()) {
        return -1;
    }
    return 0;
}

int DnsResponderClient::TearDownOemNetwork(int oemNetId) {
    if (auto status = mNetdSrv->networkDestroy(oemNetId); !status.isOk()) {
        fprintf(stderr, "Removing network %d failed, %s\n", oemNetId, status.getMessage());
        return -1;
    }
    if (auto status = mDnsResolvSrv->destroyNetworkCache(oemNetId); !status.isOk()) {
        fprintf(stderr, "Removing network cache %d failed, %s\n", oemNetId, status.getMessage());
        return -1;
    }
    return 0;
}

void DnsResponderClient::SetUp() {
    // binder setup
    ndk::SpAIBinder netdBinder = ndk::SpAIBinder(AServiceManager_getService("netd"));
    mNetdSrv = INetd::fromBinder(netdBinder);
    if (mNetdSrv.get() == nullptr) {
        LOG(FATAL) << "Can't connect to service 'netd'. Missing root privileges? uid=" << getuid();
    }

    ndk::SpAIBinder resolvBinder = ndk::SpAIBinder(AServiceManager_getService("dnsresolver"));
    mDnsResolvSrv = IDnsResolver::fromBinder(resolvBinder);
    if (mDnsResolvSrv.get() == nullptr) {
        LOG(FATAL) << "Can't connect to service 'dnsresolver'. Missing root privileges? uid="
                   << getuid();
    }

    // Ensure resolutions go via proxy.
    setenv(ANDROID_DNS_MODE, "", 1);
    SetupOemNetwork(TEST_NETID);
}

void DnsResponderClient::TearDown() {
    TearDownOemNetwork(TEST_NETID);
}

NativeNetworkConfig DnsResponderClient::makeNativeNetworkConfig(int netId,
                                                                NativeNetworkType networkType,
                                                                int permission, bool secure) {
    NativeNetworkConfig config = {};
    config.netId = netId;
    config.networkType = networkType;
    config.permission = permission;
    config.secure = secure;
    // The vpnType doesn't matter in AOSP. Just pick a well defined one from INetd.
    config.vpnType = NativeVpnType::PLATFORM;
    return config;
}
