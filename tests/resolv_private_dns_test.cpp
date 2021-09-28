/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "resolv_private_dns_test"

#include <aidl/android/net/IDnsResolver.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <netdutils/InternetAddresses.h>
#include <netdutils/Stopwatch.h>

#include "doh_frontend.h"
#include "tests/dns_responder/dns_responder.h"
#include "tests/dns_responder/dns_responder_client_ndk.h"
#include "tests/dns_responder/dns_tls_frontend.h"
#include "tests/resolv_test_utils.h"
#include "tests/unsolicited_listener/unsolicited_event_listener.h"

using aidl::android::net::resolv::aidl::IDnsResolverUnsolicitedEventListener;
using android::base::unique_fd;
using android::net::resolv::aidl::UnsolicitedEventListener;
using android::netdutils::ScopedAddrinfo;
using android::netdutils::Stopwatch;
using std::chrono::milliseconds;

const std::string kDohFlag("persist.device_config.netd_native.doh");
const std::string kDohQueryTimeoutFlag("persist.device_config.netd_native.doh_query_timeout_ms");
const std::string kDohProbeTimeoutFlag("persist.device_config.netd_native.doh_probe_timeout_ms");

namespace {

// A helper which can propagate the failure to outside of the stmt to know which line
// of stmt fails. The expectation fails only for the first failed stmt.
#define EXPECT_NO_FAILURE(stmt)                                         \
    do {                                                                \
        bool alreadyFailed = HasFailure();                              \
        stmt;                                                           \
        if (!alreadyFailed && HasFailure()) EXPECT_FALSE(HasFailure()); \
    } while (0)

}  // namespace

// Base class to deal with netd binder service and resolver binder service.
// TODO: derive ResolverTest from this base class.
class BaseTest : public ::testing::Test {
  public:
    static void SetUpTestSuite() {
        // Get binder service.
        // Note that |mDnsClient| is not used for getting binder service in this static function.
        // The reason is that wants to keep |mDnsClient| as a non-static data member. |mDnsClient|
        // which sets up device network configuration could be independent from every test.
        // TODO: Perhaps add a static function in resolv_test_binder_utils.{cpp,h} to get binder
        // service.
        AIBinder* binder = AServiceManager_getService("dnsresolver");
        sResolvBinder = ndk::SpAIBinder(binder);
        auto resolvService = aidl::android::net::IDnsResolver::fromBinder(sResolvBinder);
        ASSERT_NE(nullptr, resolvService.get());

        // Subscribe the death recipient to the service IDnsResolver for detecting Netd death.
        // GTEST assertion macros are not invoked for generating a test failure in the death
        // recipient because the macros can't indicate failed test if Netd died between tests.
        // Moreover, continuing testing may have no meaningful after Netd death. Therefore, the
        // death recipient aborts process by GTEST_LOG_(FATAL) once Netd died.
        sResolvDeathRecipient = AIBinder_DeathRecipient_new([](void*) {
            constexpr char errorMessage[] = "Netd died";
            LOG(ERROR) << errorMessage;
            GTEST_LOG_(FATAL) << errorMessage;
        });
        ASSERT_EQ(STATUS_OK, AIBinder_linkToDeath(binder, sResolvDeathRecipient, nullptr));

        // Subscribe the unsolicited event listener for verifying unsolicited event contents.
        sUnsolicitedEventListener = ndk::SharedRefBase::make<UnsolicitedEventListener>(TEST_NETID);
        ASSERT_TRUE(
                resolvService->registerUnsolicitedEventListener(sUnsolicitedEventListener).isOk());

        // Start the binder thread pool for listening DNS metrics events and receiving death
        // recipient.
        ABinderProcess_startThreadPool();
    }
    static void TearDownTestSuite() { AIBinder_DeathRecipient_delete(sResolvDeathRecipient); }

  protected:
    void SetUp() {
        mDnsClient.SetUp();
        sUnsolicitedEventListener->reset();
    }

    void TearDown() {
        // Ensure the dump works at the end of each test.
        mDnsClient.TearDown();
    }

    void resetNetwork() {
        mDnsClient.TearDown();
        mDnsClient.SetupOemNetwork();
    }

    void flushCache() { mDnsClient.resolvService()->flushNetworkCache(TEST_NETID); }

    bool WaitForDotValidation(std::string serverAddr, bool validated) {
        return WaitForPrivateDnsValidation(serverAddr, validated,
                                           IDnsResolverUnsolicitedEventListener::PROTOCOL_DOT);
    }

    bool WaitForDohValidation(std::string serverAddr, bool validated) {
        return WaitForPrivateDnsValidation(serverAddr, validated,
                                           IDnsResolverUnsolicitedEventListener::PROTOCOL_DOH);
    }

    bool WaitForPrivateDnsValidation(std::string serverAddr, bool validated, int protocol) {
        return sUnsolicitedEventListener->waitForPrivateDnsValidation(
                serverAddr,
                validated ? IDnsResolverUnsolicitedEventListener::VALIDATION_RESULT_SUCCESS
                          : IDnsResolverUnsolicitedEventListener::VALIDATION_RESULT_FAILURE,
                protocol);
    }

    bool hasUncaughtPrivateDnsValidation(const std::string& serverAddr) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        return sUnsolicitedEventListener->findValidationRecord(
                       serverAddr, IDnsResolverUnsolicitedEventListener::PROTOCOL_DOT) ||
               sUnsolicitedEventListener->findValidationRecord(
                       serverAddr, IDnsResolverUnsolicitedEventListener::PROTOCOL_DOH);
    }

    DnsResponderClient mDnsClient;

    // Use a shared static DNS listener for all tests to avoid registering lots of listeners
    // which may be released late until process terminated. Currently, registered DNS listener
    // is removed by binder death notification which is fired when the process hosting an
    // IBinder has gone away. If every test registers its DNS listener, Netd
    // may temporarily hold lots of dead listeners until the unit test process terminates.
    // TODO: Perhaps add an unregistering listener binder call or fork a listener process which
    // could be terminated earlier.
    inline static std::shared_ptr<UnsolicitedEventListener> sUnsolicitedEventListener;

    // Use a shared static death recipient to monitor the service death. The static death
    // recipient could monitor the death not only during the test but also between tests.
    inline static AIBinder_DeathRecipient* sResolvDeathRecipient;

    // The linked AIBinder_DeathRecipient will be automatically unlinked if the binder is deleted.
    // The binder needs to be retained throughout tests.
    inline static ndk::SpAIBinder sResolvBinder;
};

class BasePrivateDnsTest : public BaseTest {
  public:
    static void SetUpTestSuite() {
        BaseTest::SetUpTestSuite();
        test::DohFrontend::initRustAndroidLogger();
    }

  protected:
    void SetUp() override {
        mDohScopedProp = make_unique<ScopedSystemProperties>(kDohFlag, "1");
        mDohQueryTimeoutScopedProp =
                make_unique<ScopedSystemProperties>(kDohQueryTimeoutFlag, "1000");
        unsigned int expectedProbeTimeout = kExpectedDohValidationTimeWhenTimeout.count();
        mDohProbeTimeoutScopedProp = make_unique<ScopedSystemProperties>(
                kDohProbeTimeoutFlag, std::to_string(expectedProbeTimeout));
        BaseTest::SetUp();

        static const std::vector<DnsRecord> records = {
                {kQueryHostname, ns_type::ns_t_a, kQueryAnswerA},
                {kQueryHostname, ns_type::ns_t_aaaa, kQueryAnswerAAAA},
        };

        for (const auto& r : records) {
            dns.addMapping(r.host_name, r.type, r.addr);
            dot_backend.addMapping(r.host_name, r.type, r.addr);
            doh_backend.addMapping(r.host_name, r.type, r.addr);
        }
    }

    void TearDown() override {
        DumpResolverService();
        mDohScopedProp.reset();
        BaseTest::TearDown();
    }

    void sendQueryAndCheckResult() {
        const addrinfo hints = {.ai_socktype = SOCK_DGRAM};
        ScopedAddrinfo result = safe_getaddrinfo(kQueryHostname, nullptr, &hints);
        EXPECT_THAT(ToStrings(result),
                    testing::ElementsAreArray({kQueryAnswerAAAA, kQueryAnswerA}));
    };

    void expectQueries(int dnsQueries, int dotQueries, int dohQueries) {
        EXPECT_EQ(dns.queries().size(), static_cast<size_t>(dnsQueries));
        EXPECT_EQ(dot.queries(), dotQueries);
        EXPECT_EQ(doh.queries(), dohQueries);
    }

    // Used when a DoH probe is sent while the DoH server doesn't respond.
    void waitForDohValidationTimeout() {
        std::this_thread::sleep_for(kExpectedDohValidationTimeWhenTimeout);
    }

    // Used when a DoH probe is sent while the DoH server is not listening on the port.
    void waitForDohValidationFailed() {
        std::this_thread::sleep_for(kExpectedDohValidationTimeWhenServerUnreachable);
    }

    void DumpResolverService() {
        unique_fd fd(open("/dev/null", O_WRONLY));
        EXPECT_EQ(mDnsClient.resolvService()->dump(fd, nullptr, 0), 0);

        const char* querylogCmd[] = {"querylog"};  // Keep it sync with DnsQueryLog::DUMP_KEYWORD.
        EXPECT_EQ(mDnsClient.resolvService()->dump(fd, querylogCmd, std::size(querylogCmd)), 0);
    }

    static constexpr milliseconds kExpectedDohValidationTimeWhenTimeout{1000};
    static constexpr milliseconds kExpectedDohValidationTimeWhenServerUnreachable{1000};
    static constexpr char kQueryHostname[] = "TransportParameterizedTest.example.com.";
    static constexpr char kQueryAnswerA[] = "1.2.3.4";
    static constexpr char kQueryAnswerAAAA[] = "2001:db8::100";

    test::DNSResponder dns{test::kDefaultListenAddr, "53"};
    test::DohFrontend doh{test::kDefaultListenAddr, "443", "127.0.1.3", "53"};
    test::DnsTlsFrontend dot{test::kDefaultListenAddr, "853", "127.0.2.3", "53"};
    test::DNSResponder doh_backend{"127.0.1.3", "53"};
    test::DNSResponder dot_backend{"127.0.2.3", "53"};

    // Used to enable DoH during the tests and set up a shorter timeout.
    std::unique_ptr<ScopedSystemProperties> mDohScopedProp;
    std::unique_ptr<ScopedSystemProperties> mDohQueryTimeoutScopedProp;
    std::unique_ptr<ScopedSystemProperties> mDohProbeTimeoutScopedProp;
};

// Parameterized test for the combination of DoH and DoT.
//  - DoT: the assigned private DNS servers support DoT only.
//  - DoH: the assigned private DNS servers support DoH only.
//  - DOT + DoH: the assigned private DNS servers support both DoT and DoH.
class TransportParameterizedTest : public BasePrivateDnsTest,
                                   public testing::WithParamInterface<uint8_t> {
  public:
    static constexpr uint8_t kDotBit = 0x01;
    static constexpr uint8_t kDohBit = 0x02;
    static constexpr std::array<uint8_t, 3> sParams = {kDotBit, kDohBit, kDotBit | kDohBit};

  protected:
    void SetUp() override {
        BasePrivateDnsTest::SetUp();

        ASSERT_TRUE(dns.startServer());
        if (testParamHasDot()) {
            ASSERT_TRUE(dot_backend.startServer());
            ASSERT_TRUE(dot.startServer());
        }
        if (testParamHasDoh()) {
            ASSERT_TRUE(doh_backend.startServer());
            ASSERT_TRUE(doh.startServer());
        }
    }

    bool testParamHasDot() { return GetParam() & kDotBit; }
    bool testParamHasDoh() { return GetParam() & kDohBit; }
};

INSTANTIATE_TEST_SUITE_P(PrivateDns, TransportParameterizedTest,
                         testing::ValuesIn(TransportParameterizedTest::sParams),
                         [](const testing::TestParamInfo<uint8_t>& info) {
                             std::string name;
                             if (info.param & TransportParameterizedTest::kDotBit) name += "DoT";
                             if (info.param & TransportParameterizedTest::kDohBit) name += "DoH";
                             return name;
                         });

TEST_P(TransportParameterizedTest, GetAddrInfo) {
    const auto parcel = DnsResponderClient::GetDefaultResolverParamsParcel();
    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));

    if (testParamHasDoh()) EXPECT_TRUE(WaitForDohValidation(test::kDefaultListenAddr, true));
    if (testParamHasDot()) EXPECT_TRUE(WaitForDotValidation(test::kDefaultListenAddr, true));

    // This waiting time is expected to avoid that the DoH validation event interferes other tests.
    if (!testParamHasDoh()) waitForDohValidationFailed();

    // Have the test independent of the number of sent queries in private DNS validation, because
    // the DnsResolver can send either 1 or 2 queries in DoT validation.
    if (testParamHasDoh()) {
        doh.clearQueries();
    }
    if (testParamHasDot()) {
        EXPECT_TRUE(dot.waitForQueries(1));
        dot.clearQueries();
    }
    dns.clearQueries();

    EXPECT_NO_FAILURE(sendQueryAndCheckResult());
    if (testParamHasDoh()) {
        EXPECT_NO_FAILURE(expectQueries(0 /* dns */, 0 /* dot */, 2 /* doh */));
    } else {
        EXPECT_NO_FAILURE(expectQueries(0 /* dns */, 2 /* dot */, 0 /* doh */));
    }

    // Stop the private DNS servers. Since we are in opportunistic mode, queries will
    // fall back to the cleartext nameserver.
    flushCache();
    dot.stopServer();
    doh.stopServer();

    EXPECT_NO_FAILURE(sendQueryAndCheckResult());
    if (testParamHasDoh()) {
        EXPECT_NO_FAILURE(expectQueries(2 /* dns */, 0 /* dot */, 2 /* doh */));
    } else {
        EXPECT_NO_FAILURE(expectQueries(2 /* dns */, 2 /* dot */, 0 /* doh */));
    }
}

class PrivateDnsDohTest : public BasePrivateDnsTest {
  protected:
    void SetUp() override {
        BasePrivateDnsTest::SetUp();

        ASSERT_TRUE(dns.startServer());
        ASSERT_TRUE(dot_backend.startServer());
        ASSERT_TRUE(dot.startServer());
        ASSERT_TRUE(doh_backend.startServer());
        ASSERT_TRUE(doh.startServer());
    }
};

// Tests that DoH validation doesn't take much time in the following scenario:
//   - DoH server is unreachable.
//   - DoH server does not respond.
TEST_F(PrivateDnsDohTest, ValidationFail) {
    using std::chrono::microseconds;

    constexpr milliseconds TIMING_TOLERANCE{1000};

    // Make the DoT server broken so that the test can receive the validation event of both
    // DoT and DoH, so we can calculate the time taken on DoH validation.
    dot.stopServer();

    // Set the DoH server unreachable.
    doh.stopServer();

    Stopwatch s;
    const auto parcel = DnsResponderClient::GetDefaultResolverParamsParcel();
    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));
    EXPECT_TRUE(WaitForDohValidation(test::kDefaultListenAddr, false));
    EXPECT_TRUE(WaitForDotValidation(test::kDefaultListenAddr, false));
    EXPECT_LT(s.getTimeAndResetUs(),
              microseconds(kExpectedDohValidationTimeWhenServerUnreachable + TIMING_TOLERANCE)
                      .count());

    // Set the DoH server unresponsive.
    ASSERT_TRUE(doh.startServer());
    doh_backend.setResponseProbability(0.0);
    doh_backend.setErrorRcode(static_cast<ns_rcode>(-1));

    s.getTimeAndResetUs();
    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));
    EXPECT_TRUE(WaitForDohValidation(test::kDefaultListenAddr, false));
    EXPECT_TRUE(WaitForDotValidation(test::kDefaultListenAddr, false));
    EXPECT_LT(s.getTimeAndResetUs(),
              microseconds(kExpectedDohValidationTimeWhenTimeout + TIMING_TOLERANCE).count());

    EXPECT_NO_FAILURE(sendQueryAndCheckResult());
    EXPECT_FALSE(hasUncaughtPrivateDnsValidation(test::kDefaultListenAddr));
}

// Tests that DoH query fails and fallback happens.
//   - Fallback to UDP if DoH query times out
//   - Fallback to DoT if DoH validation is in progress or has failed.
TEST_F(PrivateDnsDohTest, QueryFailover) {
    const auto parcel = DnsResponderClient::GetDefaultResolverParamsParcel();
    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));
    EXPECT_TRUE(WaitForDohValidation(test::kDefaultListenAddr, true));
    EXPECT_TRUE(WaitForDotValidation(test::kDefaultListenAddr, true));
    EXPECT_TRUE(dot.waitForQueries(1));
    dot.clearQueries();
    dns.clearQueries();

    doh_backend.setResponseProbability(0.0);
    doh_backend.setErrorRcode(static_cast<ns_rcode>(-1));

    // Expect that the query fall back to UDP.
    EXPECT_NO_FAILURE(sendQueryAndCheckResult());
    EXPECT_EQ(dot.queries(), 0);
    EXPECT_EQ(dns.queries().size(), 2U);
    flushCache();

    resetNetwork();
    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));

    EXPECT_TRUE(WaitForDotValidation(test::kDefaultListenAddr, true));
    EXPECT_TRUE(dot.waitForQueries(1));
    dot.clearQueries();
    dns.clearQueries();

    // Expect that the query fall back to DoT as DoH validation is in progress.
    EXPECT_NO_FAILURE(sendQueryAndCheckResult());

    EXPECT_EQ(dot.queries(), 2);
    EXPECT_EQ(dns.queries().size(), 0U);
    waitForDohValidationTimeout();
    flushCache();

    // Expect that this query fall back to DoT as DoH validation has failed.
    EXPECT_NO_FAILURE(sendQueryAndCheckResult());
    EXPECT_EQ(dot.queries(), 4);
    EXPECT_EQ(dns.queries().size(), 0U);
}

// Tests that the DnsResolver prioritizes IPv6 DoH servers over IPv4 DoH servers.
TEST_F(PrivateDnsDohTest, PreferIpv6) {
    constexpr char listen_ipv6_addr[] = "::1";
    const std::vector<std::vector<std::string>> testConfig = {
            {test::kDefaultListenAddr, listen_ipv6_addr},
            {listen_ipv6_addr, test::kDefaultListenAddr},
    };

    // To simplify the test, set the DoT server broken.
    dot.stopServer();

    test::DNSResponder dns_ipv6{listen_ipv6_addr, "53"};
    test::DohFrontend doh_ipv6{listen_ipv6_addr, "443", listen_ipv6_addr, "53"};
    dns_ipv6.addMapping(kQueryHostname, ns_type::ns_t_a, kQueryAnswerA);
    dns_ipv6.addMapping(kQueryHostname, ns_type::ns_t_aaaa, kQueryAnswerAAAA);
    ASSERT_TRUE(dns_ipv6.startServer());
    ASSERT_TRUE(doh_ipv6.startServer());

    for (const auto& serverList : testConfig) {
        SCOPED_TRACE(fmt::format("serverList: [{}]", fmt::join(serverList, ", ")));

        auto parcel = DnsResponderClient::GetDefaultResolverParamsParcel();
        parcel.servers = serverList;
        parcel.tlsServers = serverList;
        ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));

        // Currently, DnsResolver sorts the server list and did DoH validation only
        // for the first server.
        EXPECT_TRUE(WaitForDohValidation(listen_ipv6_addr, true));

        doh.clearQueries();
        doh_ipv6.clearQueries();

        EXPECT_NO_FAILURE(sendQueryAndCheckResult());
        EXPECT_EQ(doh_ipv6.queries(), 2);
        EXPECT_NO_FAILURE(expectQueries(0 /* dns */, 0 /* dot */, 0 /* doh */));

        resetNetwork();
    }
}

// Tests that DoH server setting can be replaced/removed correctly.
TEST_F(PrivateDnsDohTest, ChangeAndClearPrivateDnsServer) {
    constexpr char listen_ipv6_addr[] = "::1";

    // To simplify the test, set the DoT server broken.
    dot.stopServer();

    test::DNSResponder dns_ipv6{listen_ipv6_addr, "53"};
    test::DohFrontend doh_ipv6{listen_ipv6_addr, "443", listen_ipv6_addr, "53"};
    dns_ipv6.addMapping(kQueryHostname, ns_type::ns_t_a, kQueryAnswerA);
    dns_ipv6.addMapping(kQueryHostname, ns_type::ns_t_aaaa, kQueryAnswerAAAA);
    ASSERT_TRUE(dns_ipv6.startServer());
    ASSERT_TRUE(doh_ipv6.startServer());

    auto parcel = DnsResponderClient::GetDefaultResolverParamsParcel();
    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));

    // Use v4 DoH server first.
    EXPECT_TRUE(WaitForDohValidation(test::kDefaultListenAddr, true));
    doh.clearQueries();
    EXPECT_NO_FAILURE(sendQueryAndCheckResult());
    EXPECT_NO_FAILURE(expectQueries(0 /* dns */, 0 /* dot */, 2 /* doh */));

    // Change to the v6 DoH server.
    parcel.servers = {listen_ipv6_addr};
    parcel.tlsServers = {listen_ipv6_addr};
    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));
    EXPECT_TRUE(WaitForDohValidation(listen_ipv6_addr, true));
    doh.clearQueries();
    doh_ipv6.clearQueries();
    flushCache();
    EXPECT_NO_FAILURE(sendQueryAndCheckResult());
    EXPECT_EQ(doh_ipv6.queries(), 2);
    EXPECT_NO_FAILURE(expectQueries(0 /* dns */, 0 /* dot */, 0 /* doh */));

    // Change to an invalid DoH server.
    parcel.tlsServers = {kHelloExampleComAddrV4};
    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));
    doh_ipv6.clearQueries();
    dns_ipv6.clearQueries();
    flushCache();
    EXPECT_NO_FAILURE(sendQueryAndCheckResult());
    EXPECT_EQ(doh_ipv6.queries(), 0);
    EXPECT_EQ(dns_ipv6.queries().size(), 2U);

    // Remove private DNS servers.
    parcel.tlsServers = {};
    ASSERT_TRUE(mDnsClient.SetResolversFromParcel(parcel));
    doh_ipv6.clearQueries();
    dns_ipv6.clearQueries();
    flushCache();
    EXPECT_NO_FAILURE(sendQueryAndCheckResult());
    EXPECT_EQ(doh_ipv6.queries(), 0);
    EXPECT_EQ(dns_ipv6.queries().size(), 2U);
}
