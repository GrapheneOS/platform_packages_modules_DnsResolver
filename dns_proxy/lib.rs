// Copyright 2025 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! DNS proxy for the Android DnsResolver module.

// Some code may not be used during the development.
// TODO (b/379992903): Remove this after library is completed.
#![allow(dead_code)]

#[cfg(feature = "android-ffi")]
mod ffi;
mod packet;
mod server;
// In-progress drop-in replacement for server.
mod server2;
