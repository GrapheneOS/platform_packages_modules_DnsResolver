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

#include "dns_tls_certificate.h"

#include <android-base/file.h>
#include <android-base/logging.h>

using android::base::ReadFileToString;

std::string ToAbsolutePath(const std::string& relativePath) {
    return std::string(android::base::GetExecutableDirectory() + '/' + relativePath);
}

std::string ReadRelativeFile(const std::string& relativePath) {
    const auto path = ToAbsolutePath(relativePath);
    std::string out;
    if (!ReadFileToString(path, &out)) {
        PLOG(FATAL) << "Read " << path << " failed";
    }
    return out;
}
