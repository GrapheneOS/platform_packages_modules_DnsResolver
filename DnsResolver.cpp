/**
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "resolv"

#include "DnsResolver.h"

#include <android-base/logging.h>

#include "DnsProxyListener.h"
#include "DnsResolverService.h"
#include "DnsTlsDispatcher.h"
#include "PrivateDnsConfiguration.h"
#include "netd_resolv/resolv.h"
#include "res_debug.h"
#include "util.h"

bool resolv_init(const ResolverNetdCallbacks* callbacks) {
    android::base::InitLogging(/*argv=*/nullptr);
    LOG(INFO) << __func__ << ": Initializing resolver";
    const bool isDebug = isDebuggable();
    resolv_set_log_severity(isDebug ? android::base::INFO : android::base::WARNING);
    doh_init_logger(isDebug ? DOH_LOG_LEVEL_INFO : DOH_LOG_LEVEL_WARN);
    using android::net::gApiLevel;
    gApiLevel = getApiLevel();
    using android::net::gResNetdCallbacks;
    gResNetdCallbacks.check_calling_permission = callbacks->check_calling_permission;
    gResNetdCallbacks.get_network_context = callbacks->get_network_context;
    gResNetdCallbacks.log = callbacks->log;
    if (gApiLevel >= 30) {
        gResNetdCallbacks.tagSocket = callbacks->tagSocket;
        gResNetdCallbacks.evaluate_domain_name = callbacks->evaluate_domain_name;
    }
    android::net::gDnsResolv = android::net::DnsResolver::getInstance();
    return android::net::gDnsResolv->start();
}

namespace android {
namespace net {

namespace {

bool verifyCallbacks() {
    if (!(gResNetdCallbacks.check_calling_permission && gResNetdCallbacks.get_network_context &&
          gResNetdCallbacks.log)) {
        return false;
    }
    if (gApiLevel >= 30) {
        return gResNetdCallbacks.tagSocket != nullptr;
    }
    return true;
}

}  // namespace

DnsResolver* gDnsResolv = nullptr;
ResolverNetdCallbacks gResNetdCallbacks;
uint64_t gApiLevel = 0;

DnsResolver* DnsResolver::getInstance() {
    // Instantiated on first use.
    static DnsResolver instance;
    return &instance;
}

DnsResolver::DnsResolver() {
    // TODO: make them member variables after fixing the circular dependency:
    //   DnsTlsDispatcher.h -> resolv_private.h -> DnsResolver.h -> DnsTlsDispatcher.h
    auto& dnsTlsDispatcher = DnsTlsDispatcher::getInstance();
    auto& privateDnsConfiguration = PrivateDnsConfiguration::getInstance();
    privateDnsConfiguration.setObserver(&dnsTlsDispatcher);
    privateDnsConfiguration.initDoh();
}

bool DnsResolver::start() {
    if (!verifyCallbacks()) {
        LOG(ERROR) << __func__ << ": Callback verification failed";
        return false;
    }
    if (mDnsProxyListener.startListener()) {
        PLOG(ERROR) << __func__ << ": Unable to start DnsProxyListener";
        return false;
    }
    binder_status_t ret;
    if ((ret = DnsResolverService::start()) != STATUS_OK) {
        LOG(ERROR) << __func__ << ": Unable to start DnsResolverService: " << ret;
        return false;
    }
    return true;
}

int DnsResolver::setLogSeverity(int32_t logSeverity) {
    return resolv_set_log_severity(logSeverity);
}

}  // namespace net
}  // namespace android
