/*
 * Copyright (C) 2024 The Android Open Source Project
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

#define LOG_TAG "resolv"

#include <linux/if_addrlabel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include "addrlabel.h"

uint32_t resolv_getaddrlabel_simple(const sockaddr* addr) {
    if (addr->sa_family == AF_INET) {
        return 4;
    } else if (addr->sa_family == AF_INET6) {
        const sockaddr_in6* addr6 = (const sockaddr_in6*)addr;
        if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr)) {
            return 0;
        } else if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
            return 4;
        } else if (IN6_IS_ADDR_6TO4(&addr6->sin6_addr)) {
            return 2;
        } else if (IN6_IS_ADDR_TEREDO(&addr6->sin6_addr)) {
            return 5;
        } else if (IN6_IS_ADDR_ULA(&addr6->sin6_addr)) {
            return ADDRLABEL_ULA;
        } else if (IN6_IS_ADDR_V4COMPAT(&addr6->sin6_addr)) {
            return 3;
        } else if (IN6_IS_ADDR_SITELOCAL(&addr6->sin6_addr)) {
            return 11;
        } else if (IN6_IS_ADDR_6BONE(&addr6->sin6_addr)) {
            return 12;
        } else {
            /* All other IPv6 addresses, including global unicast addresses. */
            return 1;
        }
    } else {
        /*
         * This should never happen.
         * Return a semi-random label as a last resort.
         */
        return 1;
    }
}

uint32_t resolv_getaddrlabel_netlink(const sockaddr* addr, int ifindex) {
    struct getaddrlabel_req {
        nlmsghdr nlh;
        ifaddrlblmsg msg;
        nlattr nla;
        in6_addr addr;
    } req = {
            .nlh =
                    {
                            .nlmsg_len = sizeof(getaddrlabel_req),
                            .nlmsg_type = RTM_GETADDRLABEL,
                            .nlmsg_flags = NLM_F_REQUEST,
                    },
            .msg =
                    {
                            .ifal_family = AF_INET6,
                            .ifal_prefixlen = 128,
                            .ifal_index = static_cast<__u32>(ifindex),
                    },
            .nla =
                    {
                            .nla_len = RTA_SPACE(sizeof(*addr)),
                            .nla_type = IFAL_ADDRESS,
                    },
            .addr = {},
    };

    if (addr->sa_family == AF_INET) {
        in6_addr v4mapped = {
                .in6_u.u6_addr32 = {0, 0, htonl(0xffff),
                                    reinterpret_cast<const sockaddr_in*>(addr)->sin_addr.s_addr}};
        req.addr = v4mapped;
    } else {
        req.addr = reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr;
    }

    // On error, return a semi-random label as a last resort.
    constexpr uint32_t LABEL_UNKNOWN = 0;
    uint32_t label = LABEL_UNKNOWN;

    const sockaddr_nl kernel = {
            .nl_family = AF_NETLINK,
    };
    android::base::unique_fd s(socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE));
    if (s == -1 || bind(s, reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel)) == -1 ||
        connect(s, reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel)) == -1 ||
        send(s, &req, sizeof(req), 0) < (ssize_t)sizeof(req)) {
        LOG(ERROR) << __func__ << ": Error sending netlink request: " << strerror(errno);
        return LABEL_UNKNOWN;
    }

    uint8_t response[256];
    ssize_t bytesread = recv(s, response, sizeof(response), MSG_DONTWAIT | MSG_TRUNC);
    if (bytesread < (ssize_t)(sizeof(nlmsghdr) + sizeof(nlmsgerr))) {
        LOG(ERROR) << __func__ << ": short read: " << bytesread;
        return LABEL_UNKNOWN;
    }

    nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(response);
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        nlmsgerr* err = reinterpret_cast<nlmsgerr*>(nlh + 1);
        LOG(ERROR) << __func__ << ": RTM_GETADDRLABEL: " << strerror(-err->error);
        return LABEL_UNKNOWN;
    }

    if (nlh->nlmsg_len < (ssize_t)(sizeof(nlmsghdr) + sizeof(ifaddrlblmsg))) {
        LOG(ERROR) << __func__ << ": short read: " << bytesread;
        return LABEL_UNKNOWN;
    }

    ifaddrlblmsg* msg = reinterpret_cast<ifaddrlblmsg*>(nlh + 1);
    rtattr* rta = reinterpret_cast<rtattr*>(msg + 1);
    size_t rta_len = NLMSG_PAYLOAD(nlh, sizeof(*msg));
    while (RTA_OK(rta, rta_len)) {
        if (rta->rta_type == IFAL_LABEL) {
            label = *static_cast<uint32_t*>(RTA_DATA(rta));
        }
        rta = RTA_NEXT(rta, rta_len);
    }

    return label;
}

uint32_t resolv_getaddrlabel(const struct sockaddr* addr) {
    return resolv_getaddrlabel_simple(addr);
}
