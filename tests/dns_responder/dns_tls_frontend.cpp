/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "dns_tls_frontend.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG_TAG "DnsTlsFrontend"
#include <android-base/logging.h>
#include <netdutils/InternetAddresses.h>
#include <netdutils/SocketOption.h>

using android::netdutils::enableSockopt;
using android::netdutils::ScopedAddrinfo;

namespace {
/*
 * test cert, key, and rootca files can be generated using openssl with
 * the following commands:
 *
 * Create CA certificate:
 * $ openssl genrsa 2048 > ca-key.pem
 * $ openssl req -new -sha256 -x509 -nodes -days 3650 -key ca_key.pem -out ca_certificate.pem -subj
 * '/C=/ST=/L=/CN=/emailAddress='
 *
 * Create server certificate:
 * $ openssl req -sha256 -newkey rsa:2048 -days 3650 -nodes -keyout serve_key.pem -out
 * server_req.pem -subj '/C=/ST=/L=/CN=example.com/emailAddress='
 * $ openssl rsa -in server_key.pem
 * -out server_key.pem $ openssl x509 -sha256 -req -in server_req.pem -days 3650 -CA
 * ca_certificate.pem -CAkey ca_key.pem -set_serial 01 -out server_certificate.pem
 *
 * Verify the certificate:
 * $ openssl verify -CAfile ca_certificate.pem server_certificate.pem
 */
// server_certificate.pem
static const char kCertificate[] = R"(
const std::string kCertificate =
-----BEGIN CERTIFICATE-----
MIICijCCAXICAQEwDQYJKoZIhvcNAQELBQAwADAeFw0xOTA2MTAwODM3MzlaFw0y
OTA2MDcwODM3MzlaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuo/v4VuY0Ees5HRx+NwTGm/bgToUFjq9R4z4
FX+j8yyohxS8OxQZzpKu8JJytyPPi+SnXqZB25usGBPJHapD1Q5YYCIZF9EBztIq
nEDbxvcWBrv7NDDhPMQ6v5YFhAIUN3a1yBESBWQOWsNkwJw04Wc4agZrhhnG/vS7
gu1gn+CnaDYupAmHrGS9cSV/B9ZCpLhis2JxmULgdz6ZBee/x8dHHFd1Qeb/+G8j
hBqhYbQK7ZFLmIO3DXrlP/ONXJ8IE2+PPDloiotkY5ar/1ZbRQS9fSKM9J6pipOE
bAI1QF+tEn1bnaLfJfoMHIcb0p5xr04OALUZOGw4iVfxulMRIQIDAQABMA0GCSqG
SIb3DQEBCwUAA4IBAQAuI2NjdWiD2lwmRraW6C7VBF+Sf+9QlzTVzSjuDbPkkYIo
YWpeYsEeFO5NlxxXl77iu4MqznSAOK8GCiNDCCulDNWRhd5lcO1dVHLcIFYKZ+xv
6IuH3vh60qJ2hoZbalwflnMQklqh3745ZyOH79dzKTFvlWyNJ2hQgP9bZ2g8F4od
dS7aOwvx3DCv46b7vBJMKd53ZCdHubfFebDcGxc60DUR0fLSI/o1MJgriODZ1SX7
sxwzrxvbJW0T+gJOL0C0lE6D84F9oL2u3ef17fC5u1bRd/77pzjTM+dQe7sZspCz
iboTujdUqo+NSdWgwPUTGTYQg/1i9Qe0vjc0YplY
-----END CERTIFICATE-----
)";

// server_key.pem
static const char kPrivatekey[] = R"(
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuo/v4VuY0Ees5HRx+NwTGm/bgToUFjq9R4z4FX+j8yyohxS8
OxQZzpKu8JJytyPPi+SnXqZB25usGBPJHapD1Q5YYCIZF9EBztIqnEDbxvcWBrv7
NDDhPMQ6v5YFhAIUN3a1yBESBWQOWsNkwJw04Wc4agZrhhnG/vS7gu1gn+CnaDYu
pAmHrGS9cSV/B9ZCpLhis2JxmULgdz6ZBee/x8dHHFd1Qeb/+G8jhBqhYbQK7ZFL
mIO3DXrlP/ONXJ8IE2+PPDloiotkY5ar/1ZbRQS9fSKM9J6pipOEbAI1QF+tEn1b
naLfJfoMHIcb0p5xr04OALUZOGw4iVfxulMRIQIDAQABAoIBACDLLF9wumviLYH6
9g3IoZMEFpGgo+dEbAEnxnQA+9DDCNy1yGCaJ+8n2ZhwJboLkXAFwWXh07HGq3mQ
AMo2I7ZPzzkWxVJqaubwCo1s2TUgOb71TDLgZLdJxwnmVRHfS650L3/7gC9yZxON
RSiWTLVSb5gziLMJ1PD8E/nvwAxaJDlT6vzqwRbnHBkQoumTmds2ecLJd2/6pfl4
bMhtIKA3ULqnJlqlRt6ds/pWU9ttmXEX52uaGhzaF7PRomOW5pKR6CyBzNCn/RNF
ZPIINW1TVWss9NMZsJLdIzs7Oon5gQYil9rU2uiA5ZUanYDIL9DOMrfAM3hfUuFq
ZOhfBAECgYEA36CT81EkdDE7pum/kIuCG3wDEls+xNbWmF76IJAxnolJzKvJsdJA
0za/l1Qe3/bRYHZWKc7by45LFYefOsS29jqBnBBMLurI7OLtcXqkTSSm11AfsDDI
gw4bKs81TYdHhnbIDGeApfSWOGXgDM/j4N3stuvY1lOIocXqKMomZVMCgYEA1ZHD
jtxeAmCqzJHIJ4DOY0Y2RR3Bq3ue/mc8gmV9wDyJMMvBpvOoRkUjwbKZToi4Px30
5fn6SCRtOKfEL0b9LV7JFsMr84Zoj8kjtnE0BdNfQqdE/uWltpATl6YUPlzqZTGs
HBGVpsNCzYkjFu9m/zIiryCHY8Uut3VEZmNJjTsCgYEAgADBTzAuBpg7xeHcdhd0
xNiqRXKXLkKvGQ6ca9E9pbp91LqsO63Wz09yQWO0PIxh8q4pycqPQyfS0KMNwKzi
8XQxxiwJ/30Cv51xPlht/X4yReKmEMsLqwCDCnEK2LLLfSs2fOst11B2QBgINC03
CfrdySKcvqmX9sl7rBdx/OMCgYB9t2o4RDwKhkDEXuRFbKsRARmdIeEJQqHa+4ZA
8+FMMdZIJQj/b9qUUsqzkKBx/EUI0meAoN/Va6vnd8oiUlViSbNxdL4AghQ2353o
HUcUTtJ6d+BDc4dSqgj+ccLk2ukXXGAFvcwr+DDwsFM5gv9MJYUJNcq8ziurzpnO
848uVQKBgEmyAa2jt1qNpAvxU0MakJIuKhQl2b6/54EKi9WKqIMs1+rKk6O/Ck3n
+tEWqHhZ4uCRmvTgpOM821l4fTHsoJ8IGWV0mwfk95pEL+g/eBLExR4etMqaW9uz
x8vnVTKNzZsAVgRcemcLqzuyuMg+/ZnH+YNMzMl0Nbkt+kE3FhfM
-----END RSA PRIVATE KEY-----
)";

static bssl::UniquePtr<X509> stringToX509Certs(const char* certs) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(certs, strlen(certs)));
    return bssl::UniquePtr<X509>(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

// Convert a string buffer containing an RSA Private Key into an OpenSSL RSA struct.
static bssl::UniquePtr<RSA> stringToRSAPrivateKey(const char* key) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(key, strlen(key)));
    return bssl::UniquePtr<RSA>(PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

std::string addr2str(const sockaddr* sa, socklen_t sa_len) {
    char host_str[NI_MAXHOST] = {0};
    int rv = getnameinfo(sa, sa_len, host_str, sizeof(host_str), nullptr, 0, NI_NUMERICHOST);
    if (rv == 0) return std::string(host_str);
    return std::string();
}

}  // namespace

namespace test {

bool DnsTlsFrontend::startServer() {
    OpenSSL_add_ssl_algorithms();

    // reset queries_ to 0 every time startServer called
    // which would help us easy to check queries_ via calling waitForQueries
    queries_ = 0;

    ctx_.reset(SSL_CTX_new(TLS_server_method()));
    if (!ctx_) {
        LOG(ERROR) << "SSL context creation failed";
        return false;
    }

    SSL_CTX_set_ecdh_auto(ctx_.get(), 1);

    bssl::UniquePtr<X509> ca_certs(stringToX509Certs(kCertificate));
    if (!ca_certs) {
        LOG(ERROR) << "StringToX509Certs failed";
        return false;
    }

    if (SSL_CTX_use_certificate(ctx_.get(), ca_certs.get()) <= 0) {
        LOG(ERROR) << "SSL_CTX_use_certificate failed";
        return false;
    }

    bssl::UniquePtr<RSA> private_key(stringToRSAPrivateKey(kPrivatekey));
    if (SSL_CTX_use_RSAPrivateKey(ctx_.get(), private_key.get()) <= 0) {
        LOG(ERROR) << "Error loading client RSA Private Key data.";
        return false;
    }

    // Set up TCP server socket for clients.
    addrinfo frontend_ai_hints{
            .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE};
    addrinfo* frontend_ai_res = nullptr;
    int rv = getaddrinfo(listen_address_.c_str(), listen_service_.c_str(), &frontend_ai_hints,
                         &frontend_ai_res);
    ScopedAddrinfo frontend_ai_res_cleanup(frontend_ai_res);
    if (rv) {
        LOG(ERROR) << "frontend getaddrinfo(" << listen_address_.c_str() << ", "
                   << listen_service_.c_str() << ") failed: " << gai_strerror(rv);
        return false;
    }

    for (const addrinfo* ai = frontend_ai_res; ai; ai = ai->ai_next) {
        android::base::unique_fd s(socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (s.get() < 0) {
            PLOG(INFO) << "ignore creating socket failed " << s.get();
            continue;
        }
        enableSockopt(s.get(), SOL_SOCKET, SO_REUSEPORT).ignoreError();
        enableSockopt(s.get(), SOL_SOCKET, SO_REUSEADDR).ignoreError();
        std::string host_str = addr2str(ai->ai_addr, ai->ai_addrlen);
        if (bind(s.get(), ai->ai_addr, ai->ai_addrlen)) {
            PLOG(INFO) << "failed to bind TCP " << host_str.c_str() << ":"
                       << listen_service_.c_str();
            continue;
        }
        LOG(INFO) << "bound to TCP " << host_str.c_str() << ":" << listen_service_.c_str();
        socket_ = std::move(s);
        break;
    }

    if (listen(socket_.get(), 1) < 0) {
        PLOG(INFO) << "failed to listen socket " << socket_.get();
        return false;
    }

    // Set up UDP client socket to backend.
    addrinfo backend_ai_hints{.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM};
    addrinfo* backend_ai_res = nullptr;
    rv = getaddrinfo(backend_address_.c_str(), backend_service_.c_str(), &backend_ai_hints,
                     &backend_ai_res);
    ScopedAddrinfo backend_ai_res_cleanup(backend_ai_res);
    if (rv) {
        LOG(ERROR) << "backend getaddrinfo(" << listen_address_.c_str() << ", "
                   << listen_service_.c_str() << ") failed: " << gai_strerror(rv);
        return false;
    }
    backend_socket_.reset(socket(backend_ai_res->ai_family, backend_ai_res->ai_socktype,
                                 backend_ai_res->ai_protocol));
    if (backend_socket_.get() < 0) {
        PLOG(INFO) << "backend socket " << backend_socket_.get() << " creation failed";
        return false;
    }

    // connect() always fails in the test DnsTlsSocketTest.SlowDestructor because of
    // no backend server. Don't check it.
    connect(backend_socket_.get(), backend_ai_res->ai_addr, backend_ai_res->ai_addrlen);

    // Set up eventfd socket.
    event_fd_.reset(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
    if (event_fd_.get() == -1) {
        PLOG(INFO) << "failed to create eventfd " << event_fd_.get();
        return false;
    }

    {
        std::lock_guard lock(update_mutex_);
        handler_thread_ = std::thread(&DnsTlsFrontend::requestHandler, this);
    }
    LOG(INFO) << "server started successfully";
    return true;
}

void DnsTlsFrontend::requestHandler() {
    LOG(DEBUG) << "Request handler started";
    enum { EVENT_FD = 0, LISTEN_FD = 1 };
    pollfd fds[2] = {{.fd = event_fd_.get(), .events = POLLIN},
                     {.fd = socket_.get(), .events = POLLIN}};

    while (true) {
        int poll_code = poll(fds, std::size(fds), -1);
        if (poll_code <= 0) {
            PLOG(WARNING) << "Poll failed with error " << poll_code;
            break;
        }

        if (fds[EVENT_FD].revents & (POLLIN | POLLERR)) {
            handleEventFd();
            break;
        }
        if (fds[LISTEN_FD].revents & (POLLIN | POLLERR)) {
            sockaddr_storage addr;
            socklen_t len = sizeof(addr);

            LOG(DEBUG) << "Trying to accept a client";
            android::base::unique_fd client(
                    accept4(socket_.get(), reinterpret_cast<sockaddr*>(&addr), &len, SOCK_CLOEXEC));
            if (client.get() < 0) {
                // Stop
                PLOG(INFO) << "failed to accept client socket " << client.get();
                break;
            }

            bssl::UniquePtr<SSL> ssl(SSL_new(ctx_.get()));
            SSL_set_fd(ssl.get(), client.get());

            LOG(DEBUG) << "Doing SSL handshake";
            bool success = false;
            if (SSL_accept(ssl.get()) <= 0) {
                LOG(INFO) << "SSL negotiation failure";
            } else {
                LOG(DEBUG) << "SSL handshake complete";
                success = handleOneRequest(ssl.get());
            }

            if (success) {
                // Increment queries_ as late as possible, because it represents
                // a query that is fully processed, and the response returned to the
                // client, including cleanup actions.
                ++queries_;
            }
        }
    }
    LOG(DEBUG) << "Ending loop";
}

bool DnsTlsFrontend::handleOneRequest(SSL* ssl) {
    uint8_t queryHeader[2];
    if (SSL_read(ssl, &queryHeader, 2) != 2) {
        LOG(INFO) << "Not enough header bytes";
        return false;
    }
    const uint16_t qlen = (queryHeader[0] << 8) | queryHeader[1];
    uint8_t query[qlen];
    size_t qbytes = 0;
    while (qbytes < qlen) {
        int ret = SSL_read(ssl, query + qbytes, qlen - qbytes);
        if (ret <= 0) {
            LOG(INFO) << "Error while reading query";
            return false;
        }
        qbytes += ret;
    }
    int sent = send(backend_socket_.get(), query, qlen, 0);
    if (sent != qlen) {
        LOG(INFO) << "Failed to send query";
        return false;
    }
    const int max_size = 4096;
    uint8_t recv_buffer[max_size];
    int rlen = recv(backend_socket_.get(), recv_buffer, max_size, 0);
    if (rlen <= 0) {
        LOG(INFO) << "Failed to receive response";
        return false;
    }
    uint8_t responseHeader[2];
    responseHeader[0] = rlen >> 8;
    responseHeader[1] = rlen;
    if (SSL_write(ssl, responseHeader, 2) != 2) {
        LOG(INFO) << "Failed to write response header";
        return false;
    }
    if (SSL_write(ssl, recv_buffer, rlen) != rlen) {
        LOG(INFO) << "Failed to write response body";
        return false;
    }
    return true;
}

bool DnsTlsFrontend::stopServer() {
    std::lock_guard lock(update_mutex_);
    if (!running()) {
        LOG(INFO) << "server not running";
        return false;
    }

    LOG(INFO) << "stopping frontend";
    if (!sendToEventFd()) {
        return false;
    }
    handler_thread_.join();
    socket_.reset();
    backend_socket_.reset();
    event_fd_.reset();
    ctx_.reset();
    LOG(INFO) << "frontend stopped successfully";
    return true;
}

bool DnsTlsFrontend::waitForQueries(int number, int timeoutMs) const {
    constexpr int intervalMs = 20;
    int limit = timeoutMs / intervalMs;
    for (int count = 0; count <= limit; ++count) {
        bool done = queries_ >= number;
        // Always sleep at least one more interval after we are done, to wait for
        // any immediate post-query actions that the client may take (such as
        // marking this server as reachable during validation).
        usleep(intervalMs * 1000);
        if (done) {
            // For ensuring that calls have sufficient headroom for slow machines
            LOG(DEBUG) << "Query arrived in " << count << "/" << limit << " of allotted time";
            return true;
        }
    }
    return false;
}

bool DnsTlsFrontend::sendToEventFd() {
    const uint64_t data = 1;
    if (const ssize_t rt = write(event_fd_.get(), &data, sizeof(data)); rt != sizeof(data)) {
        PLOG(INFO) << "failed to write eventfd, rt=" << rt;
        return false;
    }
    return true;
}

void DnsTlsFrontend::handleEventFd() {
    int64_t data;
    if (const ssize_t rt = read(event_fd_.get(), &data, sizeof(data)); rt != sizeof(data)) {
        PLOG(INFO) << "ignore reading eventfd failed, rt=" << rt;
    }
}

}  // namespace test
