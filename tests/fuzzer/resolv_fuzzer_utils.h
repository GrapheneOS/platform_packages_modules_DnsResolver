#ifndef RESOLV_FUZZER_UTILS_H_
#define RESOLV_FUZZER_UTILS_H_

#include <arpa/inet.h>  // for inet_pton
#include <fuzzer/FuzzedDataProvider.h>

#include "DnsResolver.h"
#include "Experiments.h"  // for update property
#include "ResolverController.h"
#include "dns_responder/dns_responder_client_ndk.h"
#include "dns_responder/dns_tls_frontend.h"
#include "doh.h"  // for DOH_LOG_LEVEL_DEBUG
#include "doh_frontend.h"
#include "getaddrinfo.h"
#include "gethnamaddr.h"
#include "res_debug.h"  // for resolv_set_log_severity
#include "resolv_cache.h"
#include "resolv_test_utils.h"

namespace android::net {

// TODO: Consider moving to packages/modules/DnsResolver/tests/resolv_test_utils.h.
constexpr int MAXPACKET = 8 * 1024;

// Tests A/AAAA/CNAME type and CNAME chain.
const std::vector<DnsRecord> records = {
        {kHelloExampleCom, ns_type::ns_t_a, kHelloExampleComAddrV4},
        {kHelloExampleCom, ns_type::ns_t_aaaa, kHelloExampleComAddrV6},
        {kCnameA, ns_type::ns_t_cname, kCnameB},
        {kCnameB, ns_type::ns_t_a, kHelloExampleComAddrV4},
        {kCnameC, ns_type::ns_t_cname, kCnameD},
};

const android_net_context mNetContext = {
        .app_netid = TEST_NETID,
        .app_mark = MARK_UNSET,
        .dns_netid = TEST_NETID,
        .dns_mark = MARK_UNSET,
        .uid = TEST_UID,
};

// Initializes servers to simulate the DNS over UDP/TLS/HTTPS.
test::DNSResponder dns{kDefaultServer, kDnsPortString};
test::DohFrontend doh{kDefaultServer, kDohPortString, "127.0.1.3", kDnsPortString};
test::DNSResponder doh_backend{"127.0.1.3", kDnsPortString};
test::DnsTlsFrontend dot{kDefaultServer, kDotPortString, "127.0.2.3", kDnsPortString};
test::DNSResponder dot_backend{"127.0.2.3", kDnsPortString};
ResolverController resolverCtrl;

// TODO: Consider moving to packages/modules/DnsResolver/tests/resolv_test_utils.h.
void StartDns(test::DNSResponder& dns, const std::vector<DnsRecord>& records) {
    for (const auto& r : records) {
        dns.addMapping(r.host_name, r.type, r.addr);
    }

    ASSERT_TRUE(dns.startServer());
    dns.clearQueries();
}

int RandomSocketType(FuzzedDataProvider& fdp) {
    int socktype = fdp.PickValueInArray(
            {SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_DCCP, SOCK_PACKET});
    if (fdp.ConsumeBool()) socktype |= SOCK_CLOEXEC;
    if (fdp.ConsumeBool()) socktype |= SOCK_NONBLOCK;
    return socktype;
}

// Initializes the callback functions to createNetworkCache.
void InitDnsResolverCallbacks() {
    gResNetdCallbacks.check_calling_permission = [](const char*) -> bool { return true; };
    gResNetdCallbacks.get_network_context = [](uint32_t, uint32_t, android_net_context*) {};
    gResNetdCallbacks.log = [](const char*) {};
}

void InitServers() {
    StartDns(dns, records);
    doh.startServer();
    StartDns(doh_backend, records);
    dot.startServer();
    StartDns(dot_backend, records);
}

void CleanServers() {
    dns.clearQueries();
    doh.clearQueries();
    doh_backend.clearQueries();
    dot.clearQueries();
    dot_backend.clearQueries();
}

// Initializes servers only one time.
bool DoInit() {
    // Sets log level to WARNING to lower I/O time cost.
    resolv_set_log_severity(android::base::WARNING);
    doh_init_logger(DOH_LOG_LEVEL_WARN);

    // Needs to init callback and create netework cache.
    InitDnsResolverCallbacks();
    resolverCtrl.createNetworkCache(TEST_NETID);
    InitServers();

    return true;
}

void CleanUp() {
    CleanServers();
    resolverCtrl.flushNetworkCache(TEST_NETID);
}

}  // namespace android::net

#endif  // RESOLV_FUZZER_UTILS_H_
