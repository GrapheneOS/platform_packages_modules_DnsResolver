/*
 * Copyright (C) 2025 The Android Open Source Project
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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static bool send_fd(const int unix_sock, const int fd) {
    char zero[1] = { 0 };

    // If fd is invalid, early return with 'simple' write of a NULL byte.
    if (fd < 0) return 1 == write(unix_sock, zero, sizeof(zero));

    struct iovec iov = {
        .iov_base = zero,
        .iov_len = sizeof(zero),
    };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u = {};
    const struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = u.buf,
        .msg_controllen = sizeof(u.buf),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) abort();  // impossible
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int*)CMSG_DATA(cmsg) = fd;

    return 1 == sendmsg(unix_sock, &msg, MSG_NOSIGNAL);
}

static bool bind_to_ifindex(const int sock, const uint32_t ifindex) {
    if (!ifindex) return true;
    if (!setsockopt(sock, SOL_SOCKET, SO_BINDTOIFINDEX, &ifindex, sizeof(ifindex))) return true;
    char ifname[IF_NAMESIZE];
    if (!if_indextoname(ifindex, ifname)) return false;
    return !setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
}

static int create_socket(const int sock_type, const uint32_t ifindex) {
    const int sock = socket(AF_INET6, sock_type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;

    static const int zero = 0;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero))) {
        close(sock);
        return -1;
    }

    static const int one = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
        close(sock);
        return -1;
    }

    if (!bind_to_ifindex(sock, ifindex)) {
        close(sock);
        return -1;
    }

    static const struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(53),  // DNS port
    };

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
        close(sock);
        return -1;
    }

    return sock;
}

// expect to be called with arguments --cmdfd {unix_seq_packet_sock_fd_nr}
int main(const int argc, const char * const argv[]) {
    if (argc != 3) return 1;
    if (strcmp(argv[1], "--cmdfd")) return 2;

    const int cmdfd = atoi(argv[2]);
    if (cmdfd < 3) return 3;  // 0..2 reserved for stdin/out/err

    {
        // we want recv() below to block, so make cmdfd blocking
        const int flags = fcntl(cmdfd, F_GETFL);
        if (flags == -1) return 4;

        if (fcntl(cmdfd, F_SETFL, flags & ~O_NONBLOCK) == -1) return 5;
    }

    {
        const int udp_sock = create_socket(SOCK_DGRAM, 0);
        if (udp_sock < 0) return 6;
        if (!send_fd(cmdfd, udp_sock)) return 7; // exit() closes udp_sock
        close(udp_sock);
    }

    while (1) {
        unsigned char buf[5];
        const ssize_t len = recv(cmdfd, buf, sizeof(buf), 0);

        if (!len) break;  // EOF
        if (len < 0) {
            if (errno == EINTR) continue;
            if (errno == ECONNRESET) break;
            fprintf(stderr, "recv() failed: %s\n", strerror(errno));
            continue;
        }
        if (len != 4) {
            fprintf(stderr, "Received an illformed TCP socket request\n");
            return 8;
        }

        const uint32_t ifindex = *(uint32_t*)&buf;
        const int tcp_sock = create_socket(SOCK_STREAM, ifindex);
        send_fd(cmdfd, tcp_sock);
        if (tcp_sock < 0) {
            fprintf(stderr, "Failed to create tcp socket: %s\n", strerror(errno));
        } else {
            close(tcp_sock);
        }
    }

    return 0;
}
