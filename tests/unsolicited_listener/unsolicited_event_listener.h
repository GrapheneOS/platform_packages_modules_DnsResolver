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

#pragma once

#include <string>

#include <aidl/android/net/resolv/aidl/BnDnsResolverUnsolicitedEventListener.h>

namespace android::net::resolv::aidl {

class UnsolicitedEventListener
    : public ::aidl::android::net::resolv::aidl::BnDnsResolverUnsolicitedEventListener {
  public:
    UnsolicitedEventListener() = default;
    ~UnsolicitedEventListener() = default;

    virtual ::ndk::ScopedAStatus onDnsHealthEvent(
            const ::aidl::android::net::resolv::aidl::DnsHealthEventParcel&) override;
    virtual ::ndk::ScopedAStatus onNat64PrefixEvent(
            const ::aidl::android::net::resolv::aidl::Nat64PrefixEventParcel&) override;
    virtual ::ndk::ScopedAStatus onPrivateDnsValidationEvent(
            const ::aidl::android::net::resolv::aidl::PrivateDnsValidationEventParcel&) override;
};

}  // namespace android::net::resolv::aidl
