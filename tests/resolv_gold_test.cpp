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
 *
 */

#define LOG_TAG "resolv_gold_test"

#include <Fwmark.h>
#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <gmock/gmock-matchers.h>
#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>

#include "PrivateDnsConfiguration.h"
#include "dns_responder/dns_responder.h"
#include "dns_responder_client.h"
#include "getaddrinfo.h"
#include "golddata.pb.h"
#include "resolv_cache.h"
#include "resolv_test_utils.h"
#include "tests/dns_responder/dns_tls_certificate.h"
#include "tests/dns_responder/dns_tls_frontend.h"

namespace android {
namespace net {
using android::netdutils::ScopedAddrinfo;
using std::chrono::milliseconds;

const std::string kTestDataPath = android::base::GetExecutableDirectory() + "/testdata/";
const std::vector<std::string> kGoldFilesGetAddrInfo = {
        "getaddrinfo.topsite.google.pbtxt",    "getaddrinfo.topsite.youtube.pbtxt",
        "getaddrinfo.topsite.amazon.pbtxt",    "getaddrinfo.topsite.yahoo.pbtxt",
        "getaddrinfo.topsite.facebook.pbtxt",  "getaddrinfo.topsite.reddit.pbtxt",
        "getaddrinfo.topsite.wikipedia.pbtxt", "getaddrinfo.topsite.ebay.pbtxt",
        "getaddrinfo.topsite.netflix.pbtxt",   "getaddrinfo.topsite.bing.pbtxt"};

// Fixture test class definition.
class TestBase : public ::testing::Test {
  protected:
    void SetUp() override {
        // Create cache for test
        resolv_create_cache_for_net(TEST_NETID);
    }

    void TearDown() override {
        // Clear TLS configuration for test
        gPrivateDnsConfiguration.clear(TEST_NETID);
        // Delete cache for test
        resolv_delete_cache_for_net(TEST_NETID);
    }

    void SetResolverConfiguration(const std::vector<std::string>& servers = {},
                                  const std::vector<std::string>& domains = {},
                                  const std::vector<std::string>& tlsServers = {},
                                  const std::string& tlsHostname = "",
                                  const std::string& caCert = "") {
        // Determine the DNS configuration steps from setResolverConfiguration() in
        // packages/modules/DnsResolver/ResolverController.cpp. The gold test just needs to setup
        // simply DNS and DNS-over-TLS server configuration. Some implementation in
        // setResolverConfiguration() are not required. For example, limiting TLS server amount is
        // not necessary for gold test because gold test has only one TLS server for testing
        // so far.
        Fwmark fwmark;
        fwmark.netId = TEST_NETID;
        fwmark.explicitlySelected = true;
        fwmark.protectedFromVpn = true;
        fwmark.permission = PERMISSION_SYSTEM;
        ASSERT_EQ(gPrivateDnsConfiguration.set(TEST_NETID, fwmark.intValue, tlsServers, tlsHostname,
                                               caCert),
                  0);
        ASSERT_EQ(resolv_set_nameservers(TEST_NETID, servers, domains, kParams), 0);
    }

    void SetResolvers() { SetResolverConfiguration(kDefaultServers, kDefaultSearchDomains); }

    void SetResolversWithTls() {
        // Pass servers as both network-assigned and TLS servers. Tests can
        // determine on which server and by which protocol queries arrived.
        // See also DnsClient::SetResolversWithTls() in
        // packages/modules/DnsResolver/tests/dns_responder/dns_responder_client.h.
        SetResolverConfiguration(kDefaultServers, kDefaultSearchDomains, kDefaultServers,
                                 kDefaultPrivateDnsHostName, kCaCert);
    }

    bool WaitForPrivateDnsValidation(const std::string& serverAddr) {
        constexpr milliseconds retryIntervalMs{20};
        constexpr milliseconds timeoutMs{3000};
        android::base::Timer t;
        while (t.duration() < timeoutMs) {
            const auto& validatedServers =
                    gPrivateDnsConfiguration.getStatus(TEST_NETID).validatedServers();
            for (const auto& server : validatedServers) {
                if (serverAddr == ToString(&server.ss)) return true;
            }
            std::this_thread::sleep_for(retryIntervalMs);
        }
        return false;
    }

    static constexpr res_params kParams = {
            .sample_validity = 300,
            .success_threshold = 25,
            .min_samples = 8,
            .max_samples = 8,
            .base_timeout_msec = 1000,
            .retry_count = 2,
    };
    static constexpr android_net_context kNetcontext = {
            .app_netid = TEST_NETID,
            .app_mark = MARK_UNSET,
            .dns_netid = TEST_NETID,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
    };
    static constexpr android_net_context kNetcontextTls = {
            .app_netid = TEST_NETID,
            .app_mark = MARK_UNSET,
            .dns_netid = TEST_NETID,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
            // Set TLS flags. See also maybeFixupNetContext() in
            // packages/modules/DnsResolver/DnsProxyListener.cpp.
            .flags = NET_CONTEXT_FLAG_USE_DNS_OVER_TLS | NET_CONTEXT_FLAG_USE_EDNS,
    };
};
class ResolvGetAddrInfo : public TestBase {};

// Parameterized test class definition.
class ResolvGoldTest : public TestBase, public ::testing::WithParamInterface<std::string> {};

// GetAddrInfo tests.
INSTANTIATE_TEST_SUITE_P(GetAddrInfo, ResolvGoldTest, ::testing::ValuesIn(kGoldFilesGetAddrInfo),
                         [](const ::testing::TestParamInfo<std::string>& info) {
                             std::string name = info.param;
                             std::replace_if(
                                     std::begin(name), std::end(name),
                                     [](char ch) { return !std::isalnum(ch); }, '_');
                             return name;
                         });

// Fixture tests.
TEST_F(ResolvGetAddrInfo, RemovePacketMapping) {
    test::DNSResponder dns(test::DNSResponder::MappingType::BINARY_PACKET);
    ASSERT_TRUE(dns.startServer());
    ASSERT_NO_FATAL_FAILURE(SetResolvers());

    dns.addMappingBinaryPacket(kHelloExampleComQueryV4, kHelloExampleComResponseV4);

    addrinfo* res = nullptr;
    const addrinfo hints = {.ai_family = AF_INET};
    NetworkDnsEventReported event;
    int rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
    ScopedAddrinfo result(res);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(rv, 0);
    EXPECT_EQ(ToString(result), "1.2.3.4");

    // Remove existing DNS record.
    dns.removeMappingBinaryPacket(kHelloExampleComQueryV4);

    // Expect to have no answer in DNS query result.
    rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
    result.reset(res);
    ASSERT_EQ(result, nullptr);
    ASSERT_EQ(rv, EAI_NODATA);
}

TEST_F(ResolvGetAddrInfo, ReplacePacketMapping) {
    test::DNSResponder dns(test::DNSResponder::MappingType::BINARY_PACKET);
    ASSERT_TRUE(dns.startServer());
    ASSERT_NO_FATAL_FAILURE(SetResolvers());

    // Register the record which uses IPv4 address 1.2.3.4.
    dns.addMappingBinaryPacket(kHelloExampleComQueryV4, kHelloExampleComResponseV4);

    // Expect that the DNS query returns IPv4 address 1.2.3.4.
    addrinfo* res = nullptr;
    const addrinfo hints = {.ai_family = AF_INET};
    NetworkDnsEventReported event;
    int rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
    ScopedAddrinfo result(res);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(rv, 0);
    EXPECT_EQ(ToString(result), "1.2.3.4");

    // Replace the registered record with a record which uses new IPv4 address 5.6.7.8.
    std::vector<uint8_t> newHelloExampleComResponseV4 = {
            /* Header */
            0x00, 0x00, /* Transaction ID: 0x0000 */
            0x81, 0x80, /* Flags: qr rd ra */
            0x00, 0x01, /* Questions: 1 */
            0x00, 0x01, /* Answer RRs: 1 */
            0x00, 0x00, /* Authority RRs: 0 */
            0x00, 0x00, /* Additional RRs: 0 */
            /* Queries */
            0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d, 0x00, /* Name: hello.example.com */
            0x00, 0x01,                   /* Type: A */
            0x00, 0x01,                   /* Class: IN */
            /* Answers */
            0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d, 0x00, /* Name: hello.example.com */
            0x00, 0x01,                   /* Type: A */
            0x00, 0x01,                   /* Class: IN */
            0x00, 0x00, 0x00, 0x00,       /* Time to live: 0 */
            0x00, 0x04,                   /* Data length: 4 */
            0x05, 0x06, 0x07, 0x08        /* Address: 5.6.7.8 */
    };
    dns.addMappingBinaryPacket(kHelloExampleComQueryV4, newHelloExampleComResponseV4);

    // Expect that DNS query returns new IPv4 address 5.6.7.8.
    rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
    result.reset(res);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(rv, 0);
    EXPECT_EQ(ToString(result), "5.6.7.8");
}

TEST_F(ResolvGetAddrInfo, BasicTlsQuery) {
    test::DNSResponder dns;
    dns.addMapping(kHelloExampleCom, ns_type::ns_t_a, "1.2.3.4");
    dns.addMapping(kHelloExampleCom, ns_type::ns_t_aaaa, "::1.2.3.4");
    ASSERT_TRUE(dns.startServer());

    test::DnsTlsFrontend tls;
    ASSERT_TRUE(tls.startServer());
    ASSERT_NO_FATAL_FAILURE(SetResolversWithTls());
    EXPECT_TRUE(WaitForPrivateDnsValidation(tls.listen_address()));

    dns.clearQueries();
    addrinfo* res = nullptr;
    // If the socket type is not specified, every address will appear twice, once for
    // SOCK_STREAM and one for SOCK_DGRAM. Just pick one because the addresses for
    // the second query of different socket type are responded by the cache.
    const addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    NetworkDnsEventReported event;
    const int rv =
            resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontextTls, &res, &event);
    ScopedAddrinfo result(res);
    ASSERT_EQ(rv, 0);
    EXPECT_EQ(GetNumQueries(dns, kHelloExampleCom), 2U);
    const std::vector<std::string> result_strs = ToStrings(result);
    EXPECT_THAT(result_strs, testing::UnorderedElementsAreArray({"1.2.3.4", "::1.2.3.4"}));
    EXPECT_EQ(tls.queries(), 3);
}

// Parameterized tests.
TEST_P(ResolvGoldTest, GoldData) {
    const auto& testFile = GetParam();

    // Convert the testing configuration from .pbtxt file to proto.
    std::string file_content;
    ASSERT_TRUE(android::base::ReadFileToString(kTestDataPath + testFile, &file_content))
            << strerror(errno);
    android::net::GoldTest goldtest;
    ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(file_content, &goldtest));
    ASSERT_EQ(android::net::CallType::CALL_GETADDRINFO, goldtest.config().call());
    ASSERT_TRUE(goldtest.config().has_addrinfo());

    test::DNSResponder dns(test::DNSResponder::MappingType::BINARY_PACKET);
    ASSERT_TRUE(dns.startServer());
    ASSERT_NO_FATAL_FAILURE(SetResolvers());

    // Register packet mapping (query, response) from proto.
    for (const auto& m : goldtest.packet_mapping()) {
        // Convert string to bytes because .proto type "bytes" is "string" type in C++.
        // See also the section "Scalar Value Types" in "Language Guide (proto3)".
        dns.addMappingBinaryPacket(std::vector<uint8_t>(m.query().begin(), m.query().end()),
                                   std::vector<uint8_t>(m.response().begin(), m.response().end()));
    }

    addrinfo* res = nullptr;
    const auto& args = goldtest.config().addrinfo();
    const addrinfo hints = {
            // Clear the flag AI_ADDRCONFIG to avoid flaky test because AI_ADDRCONFIG looks at
            // whether connectivity is available. It makes that the resolver may send only A
            // or AAAA DNS query per connectivity even AF_UNSPEC has been assigned. See also
            // have_ipv6() and have_ipv4() in packages/modules/DnsResolver/getaddrinfo.cpp.
            // TODO: Consider keeping the configuration flag AI_ADDRCONFIG once the unit
            // test can treat the IPv4 and IPv6 connectivity.
            .ai_flags = args.ai_flags() & ~AI_ADDRCONFIG,
            .ai_family = args.family(),
            .ai_socktype = args.socktype(),
            .ai_protocol = args.protocol(),
    };
    NetworkDnsEventReported event;
    const int rv =
            resolv_getaddrinfo(args.host().c_str(), nullptr, &hints, &kNetcontext, &res, &event);
    ScopedAddrinfo result(res);
    ASSERT_EQ(goldtest.result().return_code(), rv);

    if (goldtest.result().return_code() != GT_EAI_NO_ERROR) {
        ASSERT_EQ(result, nullptr);
    } else {
        ASSERT_NE(result, nullptr);
        const auto& addresses = goldtest.result().addresses();
        EXPECT_THAT(ToStrings(result),
                    ::testing::UnorderedElementsAreArray(
                            std::vector<std::string>(addresses.begin(), addresses.end())));
    }
    EXPECT_EQ(GetNumQueries(dns, args.host().c_str()), (hints.ai_family == AF_UNSPEC) ? 2U : 1U);
}

}  // end of namespace net
}  // end of namespace android
