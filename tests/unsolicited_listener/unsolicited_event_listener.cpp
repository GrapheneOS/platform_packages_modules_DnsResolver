/**
 * Copyright (c) 2021, The Android Open Source Project
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

#include "unsolicited_event_listener.h"

#include <thread>

#include <android-base/chrono_utils.h>
#include <android-base/format.h>

namespace android::net::resolv::aidl {

using ::aidl::android::net::resolv::aidl::PrivateDnsValidationEventParcel;
using android::base::ScopedLockAssertion;
using std::chrono::milliseconds;

constexpr milliseconds kEventTimeoutMs{5000};

::ndk::ScopedAStatus UnsolicitedEventListener::onDnsHealthEvent(
        const ::aidl::android::net::resolv::aidl::DnsHealthEventParcel&) {
    // default no-op
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus UnsolicitedEventListener::onNat64PrefixEvent(
        const ::aidl::android::net::resolv::aidl::Nat64PrefixEventParcel&) {
    // default no-op
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus UnsolicitedEventListener::onPrivateDnsValidationEvent(
        const PrivateDnsValidationEventParcel& event) {
    {
        std::lock_guard lock(mMutex);
        // keep updating the server to have latest validation status.
        mValidationRecords.insert_or_assign({event.netId, event.ipAddress}, event.validation);
    }
    mCv.notify_one();
    return ::ndk::ScopedAStatus::ok();
}

bool UnsolicitedEventListener::waitForPrivateDnsValidation(const std::string& serverAddr,
                                                           int validation) {
    const auto now = std::chrono::steady_clock::now();

    std::unique_lock lock(mMutex);
    ScopedLockAssertion assume_lock(mMutex);

    // onPrivateDnsValidationEvent() might already be invoked. Search for the record first.
    do {
        if (findAndRemoveValidationRecord({mNetId, serverAddr}, validation)) return true;
    } while (mCv.wait_until(lock, now + kEventTimeoutMs) != std::cv_status::timeout);

    // Timeout.
    return false;
}

bool UnsolicitedEventListener::findAndRemoveValidationRecord(const ServerKey& key, int value) {
    auto it = mValidationRecords.find(key);
    if (it != mValidationRecords.end() && it->second == value) {
        mValidationRecords.erase(it);
        return true;
    }
    return false;
}

}  // namespace android::net::resolv::aidl
