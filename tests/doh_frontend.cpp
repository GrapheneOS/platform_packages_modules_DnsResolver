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
 */

#include "doh_frontend.h"

#define LOG_TAG "DohFrontend"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <gtest/gtest.h>

#include "dns_tls_certificate.h"

namespace test {

DohFrontend::~DohFrontend() {
    if (mRustDoh) {
        stopServer();
        rust::frontend_delete(mRustDoh);
    }
}

bool DohFrontend::startServer() {
    std::lock_guard guard(mMutex);
    if (mRustDoh == nullptr) {
        mRustDoh = rust::frontend_new(mAddress.c_str(), mService.c_str(), mBackendAddress.c_str(),
                                      mBackendService.c_str());
        if (mRustDoh == nullptr) {
            LOG(ERROR) << "Failed to create rust DoH frontend";
            return false;
        }
    }

    rust::frontend_set_certificate(mRustDoh, kCertificate);
    rust::frontend_set_private_key(mRustDoh, kPrivatekey);

    return rust::frontend_start(mRustDoh);
}

bool DohFrontend::stopServer() {
    std::lock_guard guard(mMutex);
    if (!mRustDoh) return false;

    rust::frontend_stop(mRustDoh);
    return true;
}

int DohFrontend::queries() const {
    std::lock_guard guard(mMutex);
    if (!mRustDoh) return 0;

    rust::Stats stats;
    rust::frontend_stats(mRustDoh, &stats);
    return stats.queries_received;
}

void DohFrontend::clearQueries() {
    std::lock_guard guard(mMutex);
    if (mRustDoh) {
        frontend_stats_clear_queries(mRustDoh);
    }
}

}  // namespace test
