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

#pragma once

#include <string>

// Currently the hostname of TLS server must match the CN filed on the server's certificate.
// Inject a test CA whose hostname is "example.com" for DNS-OVER-TLS tests.
inline constexpr char kDefaultPrivateDnsHostName[] = "example.com";
inline constexpr char kDefaultIncorrectPrivateDnsHostName[] = "www.example.com";

/*
 * test cert, key, and rootca files can be generated using openssl with
 * the following steps:
 *
 * 1. Create CA certificate:
 * $ openssl genrsa 2048 > ca_key.pem
 * $ openssl req -new -sha256 -x509 -nodes -days 3650 -key ca_key.pem -out ca_certificate.pem -subj
 * '/C=/ST=/L=/CN=/emailAddress='
 *
 * 2. Create private key:
 * $ openssl req -sha256 -newkey rsa:2048 -days 3650 -nodes -keyout server_key.pem -out
 * server_req.pem -subj '/C=/ST=/L=/CN=example.com/emailAddress='
 * $ openssl rsa -in server_key.pem -out server_key.pem
 *
 * 3. Create server certificate:
 * $ openssl x509 -sha256 -req -in server_req.pem -days 3650 -CA
 * ca_certificate.pem -CAkey ca_key.pem -set_serial 01 -out server_certificate.pem
 *
 * 4. Verify the certificate:
 * $ openssl verify -CAfile ca_certificate.pem server_certificate.pem
 */

// Relative paths to the executable.
inline constexpr char kCaCertPath[] = "test_keys/ca_certificate.pem";
inline constexpr char kServerPrivateKeyPath[] = "test_keys/server_key.pem";
inline constexpr char kServerCertPath[] = "test_keys/server_certificate.pem";

std::string ToAbsolutePath(const std::string& relativePath);
std::string ReadRelativeFile(const std::string& relativePath);
