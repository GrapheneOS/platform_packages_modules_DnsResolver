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

#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include "dns_responder/dns_responder.h"
#include "getaddrinfo.h"
#include "resolv_cache.h"
#include "resolv_test_utils.h"

namespace android {
namespace net {
using android::net::NetworkDnsEventReported;
using android::netdutils::ScopedAddrinfo;

static const std::vector<uint8_t> kHelloExampleComQueryV4 = {
        /* Header */
        0x00, 0x00, /* Transaction ID: 0x0000 */
        0x01, 0x00, /* Flags: rd */
        0x00, 0x01, /* Questions: 1 */
        0x00, 0x00, /* Answer RRs: 0 */
        0x00, 0x00, /* Authority RRs: 0 */
        0x00, 0x00, /* Additional RRs: 0 */
        /* Queries */
        0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, /* Name: hello.example.com */
        0x00, 0x01,             /* Type: A */
        0x00, 0x01              /* Class: IN */
};

static const std::vector<uint8_t> kHelloExampleComResponseV4 = {
        /* Header */
        0x00, 0x00, /* Transaction ID: 0x0000 */
        0x81, 0x80, /* Flags: qr rd ra */
        0x00, 0x01, /* Questions: 1 */
        0x00, 0x01, /* Answer RRs: 1 */
        0x00, 0x00, /* Authority RRs: 0 */
        0x00, 0x00, /* Additional RRs: 0 */
        /* Queries */
        0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, /* Name: hello.example.com */
        0x00, 0x01,             /* Type: A */
        0x00, 0x01,             /* Class: IN */
        /* Answers */
        0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, /* Name: hello.example.com */
        0x00, 0x01,             /* Type: A */
        0x00, 0x01,             /* Class: IN */
        0x00, 0x00, 0x00, 0x00, /* Time to live: 0 */
        0x00, 0x04,             /* Data length: 4 */
        0x01, 0x02, 0x03, 0x04  /* Address: 1.2.3.4 */
};

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

}  // end of namespace net
}  // end of namespace android
