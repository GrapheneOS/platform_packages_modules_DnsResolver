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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "DnsStats.h"

namespace android::net {

using namespace std::chrono_literals;
using android::netdutils::IPSockAddr;
using std::chrono::milliseconds;
using ::testing::IsEmpty;
using ::testing::UnorderedElementsAreArray;

namespace {

DnsQueryEvent makeDnsQueryEvent(const Protocol protocol, const NsRcode rcode,
                                const milliseconds& latency) {
    DnsQueryEvent event;
    event.set_protocol(protocol);
    event.set_rcode(rcode);
    event.set_latency_micros(latency.count() * 1000);
    return event;
}

StatsData makeStatsData(const IPSockAddr& server, const int total, const milliseconds& latencyMs,
                        const std::map<int, int>& rcodeCounts) {
    StatsData ret(server);
    ret.total = total;
    ret.latencyUs = latencyMs;
    ret.rcodeCounts = rcodeCounts;
    return ret;
}

}  // namespace

class StatsRecordsTest : public ::testing::Test {};

TEST_F(StatsRecordsTest, PushRecord) {
    const IPSockAddr server = IPSockAddr::toIPSockAddr("127.0.0.2", 53);
    constexpr size_t size = 3;
    const StatsRecords::Record recordNoError = {NS_R_NO_ERROR, 10ms};
    const StatsRecords::Record recordTimeout = {NS_R_TIMEOUT, 250ms};

    StatsRecords sr(server, size);
    EXPECT_EQ(sr.getStatsData(), makeStatsData(server, 0, 0ms, {}));

    sr.push(recordNoError);
    EXPECT_EQ(sr.getStatsData(), makeStatsData(server, 1, 10ms, {{NS_R_NO_ERROR, 1}}));

    sr.push(recordNoError);
    EXPECT_EQ(sr.getStatsData(), makeStatsData(server, 2, 20ms, {{NS_R_NO_ERROR, 2}}));

    sr.push(recordTimeout);
    EXPECT_EQ(sr.getStatsData(),
              makeStatsData(server, 3, 270ms, {{NS_R_NO_ERROR, 2}, {NS_R_TIMEOUT, 1}}));

    sr.push(recordTimeout);
    EXPECT_EQ(sr.getStatsData(),
              makeStatsData(server, 3, 510ms, {{NS_R_NO_ERROR, 1}, {NS_R_TIMEOUT, 2}}));

    sr.push(recordTimeout);
    EXPECT_EQ(sr.getStatsData(),
              makeStatsData(server, 3, 750ms, {{NS_R_NO_ERROR, 0}, {NS_R_TIMEOUT, 3}}));
}

class DnsStatsTest : public ::testing::Test {
  protected:
    DnsStats mDnsStats;
};

TEST_F(DnsStatsTest, SetServers) {
    static const struct {
        std::vector<std::string> servers;
        std::vector<std::string> expectation;
        bool isSuccess;
    } tests[] = {
            // Normal case.
            {
                    {"127.0.0.1", "127.0.0.2", "fe80::1%22", "2001:db8::2", "::1"},
                    {"127.0.0.1", "127.0.0.2", "fe80::1%22", "2001:db8::2", "::1"},
                    true,
            },
            // Duplicate servers.
            {
                    {"127.0.0.1", "2001:db8::2", "127.0.0.1", "2001:db8::2"},
                    {"127.0.0.1", "2001:db8::2"},
                    true,
            },
            // Invalid server addresses. The state remains in previous state.
            {
                    {"not_an_ip", "127.0.0.3", "127.a.b.2"},
                    {"127.0.0.1", "2001:db8::2"},
                    false,
            },
            // Clean up the old servers 127.0.0.1 and 127.0.0.2.
            {
                    {"127.0.0.4", "2001:db8::5"},
                    {"127.0.0.4", "2001:db8::5"},
                    true,
            },
            // Empty list.
            {{}, {}, true},
    };

    for (const auto& [servers, expectation, isSuccess] : tests) {
        std::vector<IPSockAddr> ipSockAddrs;
        ipSockAddrs.reserve(servers.size());
        for (const auto& server : servers) {
            ipSockAddrs.push_back(IPSockAddr::toIPSockAddr(server, 53));
        }

        EXPECT_TRUE(mDnsStats.setServers(ipSockAddrs, PROTO_TCP) == isSuccess);
        EXPECT_TRUE(mDnsStats.setServers(ipSockAddrs, PROTO_UDP) == isSuccess);
        EXPECT_TRUE(mDnsStats.setServers(ipSockAddrs, PROTO_DOT) == isSuccess);

        std::vector<StatsData> expectedStats;
        expectedStats.reserve(expectation.size());
        for (const auto& exp : expectation) {
            expectedStats.push_back(makeStatsData(IPSockAddr::toIPSockAddr(exp, 53), 0, 0ms, {}));
        }

        EXPECT_THAT(mDnsStats.getStats(PROTO_TCP), UnorderedElementsAreArray(expectedStats));
        EXPECT_THAT(mDnsStats.getStats(PROTO_UDP), UnorderedElementsAreArray(expectedStats));
        EXPECT_THAT(mDnsStats.getStats(PROTO_DOT), UnorderedElementsAreArray(expectedStats));
    }
}

TEST_F(DnsStatsTest, SetServersDifferentPorts) {
    const std::vector<IPSockAddr> servers = {
            IPSockAddr::toIPSockAddr("127.0.0.1", 0),   IPSockAddr::toIPSockAddr("fe80::1", 0),
            IPSockAddr::toIPSockAddr("127.0.0.1", 53),  IPSockAddr::toIPSockAddr("127.0.0.1", 5353),
            IPSockAddr::toIPSockAddr("127.0.0.1", 853), IPSockAddr::toIPSockAddr("fe80::1", 53),
            IPSockAddr::toIPSockAddr("fe80::1", 5353),  IPSockAddr::toIPSockAddr("fe80::1", 853),
    };

    // Servers setup fails due to port unset.
    EXPECT_FALSE(mDnsStats.setServers(servers, PROTO_TCP));
    EXPECT_FALSE(mDnsStats.setServers(servers, PROTO_UDP));
    EXPECT_FALSE(mDnsStats.setServers(servers, PROTO_DOT));

    EXPECT_THAT(mDnsStats.getStats(PROTO_TCP), IsEmpty());
    EXPECT_THAT(mDnsStats.getStats(PROTO_UDP), IsEmpty());
    EXPECT_THAT(mDnsStats.getStats(PROTO_DOT), IsEmpty());

    EXPECT_TRUE(mDnsStats.setServers(std::vector(servers.begin() + 2, servers.end()), PROTO_TCP));
    EXPECT_TRUE(mDnsStats.setServers(std::vector(servers.begin() + 2, servers.end()), PROTO_UDP));
    EXPECT_TRUE(mDnsStats.setServers(std::vector(servers.begin() + 2, servers.end()), PROTO_DOT));

    const std::vector<StatsData> expectedStats = {
            makeStatsData(servers[2], 0, 0ms, {}), makeStatsData(servers[3], 0, 0ms, {}),
            makeStatsData(servers[4], 0, 0ms, {}), makeStatsData(servers[5], 0, 0ms, {}),
            makeStatsData(servers[6], 0, 0ms, {}), makeStatsData(servers[7], 0, 0ms, {}),
    };

    EXPECT_THAT(mDnsStats.getStats(PROTO_TCP), UnorderedElementsAreArray(expectedStats));
    EXPECT_THAT(mDnsStats.getStats(PROTO_UDP), UnorderedElementsAreArray(expectedStats));
    EXPECT_THAT(mDnsStats.getStats(PROTO_DOT), UnorderedElementsAreArray(expectedStats));
}

TEST_F(DnsStatsTest, AddStatsAndClear) {
    const std::vector<IPSockAddr> servers = {
            IPSockAddr::toIPSockAddr("127.0.0.1", 53),
            IPSockAddr::toIPSockAddr("127.0.0.2", 53),
    };
    const DnsQueryEvent record = makeDnsQueryEvent(PROTO_UDP, NS_R_NO_ERROR, 10ms);

    EXPECT_TRUE(mDnsStats.setServers(servers, PROTO_TCP));
    EXPECT_TRUE(mDnsStats.setServers(servers, PROTO_UDP));

    // Fail to add stats because of incorrect arguments.
    EXPECT_FALSE(mDnsStats.addStats(IPSockAddr::toIPSockAddr("127.0.0.4", 53), record));
    EXPECT_FALSE(mDnsStats.addStats(IPSockAddr::toIPSockAddr("127.a.b.4", 53), record));

    EXPECT_TRUE(mDnsStats.addStats(servers[0], record));
    EXPECT_TRUE(mDnsStats.addStats(servers[0], record));
    EXPECT_TRUE(mDnsStats.addStats(servers[1], record));

    const std::vector<StatsData> expectedStatsForTcp = {
            makeStatsData(servers[0], 0, 0ms, {}),
            makeStatsData(servers[1], 0, 0ms, {}),
    };
    const std::vector<StatsData> expectedStatsForUdp = {
            makeStatsData(servers[0], 2, 20ms, {{NS_R_NO_ERROR, 2}}),
            makeStatsData(servers[1], 1, 10ms, {{NS_R_NO_ERROR, 1}}),
    };

    EXPECT_THAT(mDnsStats.getStats(PROTO_TCP), UnorderedElementsAreArray(expectedStatsForTcp));
    EXPECT_THAT(mDnsStats.getStats(PROTO_UDP), UnorderedElementsAreArray(expectedStatsForUdp));
    EXPECT_THAT(mDnsStats.getStats(PROTO_DOT), IsEmpty());

    // Clear stats.
    EXPECT_TRUE(mDnsStats.setServers({}, PROTO_TCP));
    EXPECT_TRUE(mDnsStats.setServers({}, PROTO_UDP));
    EXPECT_TRUE(mDnsStats.setServers({}, PROTO_DOT));
    EXPECT_THAT(mDnsStats.getStats(PROTO_TCP), IsEmpty());
    EXPECT_THAT(mDnsStats.getStats(PROTO_UDP), IsEmpty());
    EXPECT_THAT(mDnsStats.getStats(PROTO_DOT), IsEmpty());
}

TEST_F(DnsStatsTest, StatsRemainsInExistentServer) {
    std::vector<IPSockAddr> servers = {
            IPSockAddr::toIPSockAddr("127.0.0.1", 53),
            IPSockAddr::toIPSockAddr("127.0.0.2", 53),
    };
    const DnsQueryEvent recordNoError = makeDnsQueryEvent(PROTO_UDP, NS_R_NO_ERROR, 10ms);
    const DnsQueryEvent recordTimeout = makeDnsQueryEvent(PROTO_UDP, NS_R_TIMEOUT, 250ms);

    EXPECT_TRUE(mDnsStats.setServers(servers, PROTO_UDP));

    // Add a record to 127.0.0.1.
    EXPECT_TRUE(mDnsStats.addStats(servers[0], recordNoError));

    // Add four records to 127.0.0.2.
    EXPECT_TRUE(mDnsStats.addStats(servers[1], recordNoError));
    EXPECT_TRUE(mDnsStats.addStats(servers[1], recordNoError));
    EXPECT_TRUE(mDnsStats.addStats(servers[1], recordTimeout));
    EXPECT_TRUE(mDnsStats.addStats(servers[1], recordTimeout));

    std::vector<StatsData> expectedStats = {
            makeStatsData(servers[0], 1, 10ms, {{NS_R_NO_ERROR, 1}}),
            makeStatsData(servers[1], 4, 520ms, {{NS_R_NO_ERROR, 2}, {NS_R_TIMEOUT, 2}}),
    };
    EXPECT_THAT(mDnsStats.getStats(PROTO_UDP), UnorderedElementsAreArray(expectedStats));

    // Update the server list, the stats of 127.0.0.2 will remain.
    servers = {
            IPSockAddr::toIPSockAddr("127.0.0.2", 53),
            IPSockAddr::toIPSockAddr("127.0.0.3", 53),
            IPSockAddr::toIPSockAddr("127.0.0.4", 53),
    };
    EXPECT_TRUE(mDnsStats.setServers(servers, PROTO_UDP));
    expectedStats = {
            makeStatsData(servers[0], 4, 520ms, {{NS_R_NO_ERROR, 2}, {NS_R_TIMEOUT, 2}}),
            makeStatsData(servers[1], 0, 0ms, {}),
            makeStatsData(servers[2], 0, 0ms, {}),
    };
    EXPECT_THAT(mDnsStats.getStats(PROTO_UDP), UnorderedElementsAreArray(expectedStats));

    // Let's add a record to 127.0.0.2 again.
    EXPECT_TRUE(mDnsStats.addStats(servers[0], recordNoError));
    expectedStats = {
            makeStatsData(servers[0], 5, 530ms, {{NS_R_NO_ERROR, 3}, {NS_R_TIMEOUT, 2}}),
            makeStatsData(servers[1], 0, 0ms, {}),
            makeStatsData(servers[2], 0, 0ms, {}),
    };
    EXPECT_THAT(mDnsStats.getStats(PROTO_UDP), UnorderedElementsAreArray(expectedStats));
}

TEST_F(DnsStatsTest, AddStatsRecords_100000) {
    constexpr int num = 100000;
    const std::vector<IPSockAddr> servers = {
            IPSockAddr::toIPSockAddr("127.0.0.1", 53),
            IPSockAddr::toIPSockAddr("127.0.0.2", 53),
            IPSockAddr::toIPSockAddr("127.0.0.3", 53),
            IPSockAddr::toIPSockAddr("127.0.0.4", 53),
    };

    EXPECT_TRUE(mDnsStats.setServers(servers, PROTO_TCP));
    EXPECT_TRUE(mDnsStats.setServers(servers, PROTO_UDP));
    EXPECT_TRUE(mDnsStats.setServers(servers, PROTO_DOT));

    for (int i = 0; i < num; i++) {
        const auto eventTcp = makeDnsQueryEvent(PROTO_TCP, static_cast<NsRcode>(i % 10), 10ms);
        const auto eventUdp = makeDnsQueryEvent(PROTO_UDP, static_cast<NsRcode>(i % 10), 10ms);
        const auto eventDot = makeDnsQueryEvent(PROTO_DOT, static_cast<NsRcode>(i % 10), 10ms);
        for (const auto& server : servers) {
            const std::string trace = server.toString() + "-" + std::to_string(i);
            SCOPED_TRACE(trace);
            EXPECT_TRUE(mDnsStats.addStats(server, eventTcp));
            EXPECT_TRUE(mDnsStats.addStats(server, eventUdp));
            EXPECT_TRUE(mDnsStats.addStats(server, eventDot));
        }
    }
}

}  // namespace android::net
