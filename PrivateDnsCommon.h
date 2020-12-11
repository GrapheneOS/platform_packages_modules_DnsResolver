/*
 * Copyright (C) 2020 The Android Open Source Project
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

namespace android::net {

// Validation status of a private DNS server on a specific netId.
enum class Validation : uint8_t {
    in_process,
    success,
    success_but_expired,
    fail,
    unknown_server,
    unknown_netid,
};

// The private DNS mode on a specific netId.
enum class PrivateDnsMode : uint8_t {
    OFF,
    OPPORTUNISTIC,
    STRICT,
};

}  // namespace android::net
