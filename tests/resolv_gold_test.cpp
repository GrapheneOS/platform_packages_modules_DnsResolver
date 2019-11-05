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

#include <android-base/file.h>
#include <gmock/gmock-matchers.h>
#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>

#include "dns_responder/dns_responder.h"
#include "getaddrinfo.h"
#include "golddata.pb.h"
#include "resolv_cache.h"
#include "resolv_test_utils.h"

namespace android {
namespace net {
using android::net::NetworkDnsEventReported;
using android::netdutils::ScopedAddrinfo;

// Fixture test class definition.
class TestBase : public ::testing::Test {
  protected:
    void SetUp() override {
        // Create cache for test
        resolv_create_cache_for_net(TEST_NETID);
    }

    void TearDown() override {
        // Delete cache for test
        resolv_delete_cache_for_net(TEST_NETID);
    }

    int SetResolvers() {
        const std::vector<std::string> servers = {test::kDefaultListenAddr};
        const std::vector<std::string> domains = {"example.com"};
        return resolv_set_nameservers(TEST_NETID, servers, domains, kParams);
    }

    const std::string kTestPath = android::base::GetExecutableDirectory();
    const std::string kTestDataPath = kTestPath + "/testdata/";
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
};
class ResolvGetAddrInfo : public TestBase {};

// Parameterized test class definition.
class ResolvGoldTest : public TestBase, public ::testing::WithParamInterface<std::string> {};

// GetAddrInfo tests.
INSTANTIATE_TEST_SUITE_P(GetAddrInfo, ResolvGoldTest,
                         ::testing::Values(std::string("getaddrinfo.topsite.google.pbtxt")),
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
    ASSERT_EQ(0, SetResolvers());

    dns.addMappingBinaryPacket(kHelloExampleComQueryV4, kHelloExampleComResponseV4);

    addrinfo* res = nullptr;
    const addrinfo hints = {.ai_family = AF_INET};
    NetworkDnsEventReported event;
    int rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
    ScopedAddrinfo result(res);
    ASSERT_NE(nullptr, result);
    ASSERT_EQ(0, rv);
    EXPECT_EQ("1.2.3.4", ToString(result));

    // Remove existing DNS record.
    dns.removeMappingBinaryPacket(kHelloExampleComQueryV4);

    // Expect to have no answer in DNS query result.
    rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
    result.reset(res);
    ASSERT_EQ(nullptr, result);
    ASSERT_EQ(EAI_NODATA, rv);
}

TEST_F(ResolvGetAddrInfo, ReplacePacketMapping) {
    test::DNSResponder dns(test::DNSResponder::MappingType::BINARY_PACKET);
    ASSERT_TRUE(dns.startServer());
    ASSERT_EQ(0, SetResolvers());

    // Register the record which uses IPv4 address 1.2.3.4.
    dns.addMappingBinaryPacket(kHelloExampleComQueryV4, kHelloExampleComResponseV4);

    // Expect that the DNS query returns IPv4 address 1.2.3.4.
    addrinfo* res = nullptr;
    const addrinfo hints = {.ai_family = AF_INET};
    NetworkDnsEventReported event;
    int rv = resolv_getaddrinfo(kHelloExampleCom, nullptr, &hints, &kNetcontext, &res, &event);
    ScopedAddrinfo result(res);
    ASSERT_NE(nullptr, result);
    ASSERT_EQ(0, rv);
    EXPECT_EQ("1.2.3.4", ToString(result));

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
    ASSERT_NE(nullptr, result);
    ASSERT_EQ(0, rv);
    EXPECT_EQ("5.6.7.8", ToString(result));
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
    ASSERT_EQ(0, SetResolvers());

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
            .ai_family = args.family(),
            .ai_socktype = args.socktype(),
            .ai_protocol = args.protocol(),
            // Clear the flag AI_ADDRCONFIG to avoid flaky test because AI_ADDRCONFIG looks at
            // whether connectivity is available. It makes that the resolver may send only A
            // or AAAA DNS query per connectivity even AF_UNSPEC has been assigned. See also
            // have_ipv6() and have_ipv4() in packages/modules/DnsResolver/getaddrinfo.cpp.
            // TODO: Consider keeping the configuration flag AI_ADDRCONFIG once the unit
            // test can treat the IPv4 and IPv6 connectivity.
            .ai_flags = args.ai_flags() & ~AI_ADDRCONFIG,
    };
    NetworkDnsEventReported event;
    int rv = resolv_getaddrinfo(args.host().c_str(), nullptr, &hints, &kNetcontext, &res, &event);
    ScopedAddrinfo result(res);
    ASSERT_EQ(goldtest.result().return_code(), rv);

    if (goldtest.result().return_code() != GT_EAI_NO_ERROR) {
        ASSERT_EQ(nullptr, result);
    } else {
        ASSERT_NE(nullptr, result);
        const auto& addresses = goldtest.result().addresses();
        EXPECT_THAT(ToStrings(result),
                    ::testing::UnorderedElementsAreArray(
                            std::vector<std::string>(addresses.begin(), addresses.end())));
    }
    EXPECT_EQ((hints.ai_family == AF_UNSPEC) ? 2U : 1U, GetNumQueries(dns, args.host().c_str()));
}

}  // end of namespace net
}  // end of namespace android
