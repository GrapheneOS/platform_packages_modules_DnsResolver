/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <list>
#include <map>
#include <mutex>
#include <vector>

#include <android-base/thread_annotations.h>
#include <netdutils/InternetAddresses.h>

#include "DnsTlsServer.h"

namespace android {
namespace net {

// The DNS over TLS mode on a specific netId.
enum class PrivateDnsMode : uint8_t { OFF, OPPORTUNISTIC, STRICT };

struct PrivateDnsStatus {
    PrivateDnsMode mode;

    // TODO: change the type to std::vector<DnsTlsServer>.
    std::map<DnsTlsServer, Validation, AddressComparator> serversMap;

    std::list<DnsTlsServer> validatedServers() const {
        std::list<DnsTlsServer> servers;

        for (const auto& pair : serversMap) {
            if (pair.second == Validation::success) {
                servers.push_back(pair.first);
            }
        }
        return servers;
    }
};

class PrivateDnsConfiguration {
  public:
    // The only instance of PrivateDnsConfiguration.
    static PrivateDnsConfiguration& getInstance() {
        static PrivateDnsConfiguration instance;
        return instance;
    }

    int set(int32_t netId, uint32_t mark, const std::vector<std::string>& servers,
            const std::string& name, const std::string& caCert) EXCLUDES(mPrivateDnsLock);

    PrivateDnsStatus getStatus(unsigned netId) EXCLUDES(mPrivateDnsLock);

    void clear(unsigned netId) EXCLUDES(mPrivateDnsLock);

    struct ServerIdentity {
        const netdutils::IPAddress ip;
        const std::string name;
        const int protocol;

        explicit ServerIdentity(const DnsTlsServer& server)
            : ip(netdutils::IPSockAddr::toIPSockAddr(server.ss).ip()),
              name(server.name),
              protocol(server.protocol) {}

        bool operator<(const ServerIdentity& other) const {
            return std::tie(ip, name, protocol) < std::tie(other.ip, other.name, other.protocol);
        }
        bool operator==(const ServerIdentity& other) const {
            return std::tie(ip, name, protocol) == std::tie(other.ip, other.name, other.protocol);
        }
    };

  private:
    typedef std::map<ServerIdentity, DnsTlsServer> PrivateDnsTracker;
    typedef std::set<DnsTlsServer, AddressComparator> ThreadTracker;

    PrivateDnsConfiguration() = default;

    void startValidation(const DnsTlsServer& server, unsigned netId, uint32_t mark)
            REQUIRES(mPrivateDnsLock);

    bool recordPrivateDnsValidation(const DnsTlsServer& server, unsigned netId, bool success)
            EXCLUDES(mPrivateDnsLock);

    // Decide if a validation for |server| is needed. Note that servers that have failed
    // multiple validation attempts but for which there is still a validating
    // thread running are marked as being Validation::in_process.
    bool needsValidation(const DnsTlsServer& server) REQUIRES(mPrivateDnsLock);

    void updateServerState(const ServerIdentity& identity, Validation state, uint32_t netId)
            REQUIRES(mPrivateDnsLock);

    std::mutex mPrivateDnsLock;
    std::map<unsigned, PrivateDnsMode> mPrivateDnsModes GUARDED_BY(mPrivateDnsLock);

    // Contains all servers for a network, along with their current validation status.
    // In case a server is removed due to a configuration change, it remains in this map,
    // but is marked inactive.
    // Any pending validation threads will continue running because we have no way to cancel them.
    std::map<unsigned, PrivateDnsTracker> mPrivateDnsTransports GUARDED_BY(mPrivateDnsLock);

    // For testing. The observer is notified of onValidationStateUpdate 1) when a validation is
    // about to begin or 2) when a validation finishes. If a validation finishes when in OFF mode
    // or when the network has been destroyed, |validation| will be Validation::fail.
    // WARNING: The Observer is notified while the lock is being held. Be careful not to call
    // any method of PrivateDnsConfiguration from the observer.
    // TODO: fix the reentrancy problem.
    class Observer {
      public:
        virtual ~Observer(){};
        virtual void onValidationStateUpdate(const std::string& serverIp, Validation validation,
                                             uint32_t netId) = 0;
    };

    void setObserver(Observer* observer);
    void maybeNotifyObserver(const std::string& serverIp, Validation validation,
                             uint32_t netId) const REQUIRES(mPrivateDnsLock);

    Observer* mObserver GUARDED_BY(mPrivateDnsLock);

    friend class PrivateDnsConfigurationTest;
};

}  // namespace net
}  // namespace android
