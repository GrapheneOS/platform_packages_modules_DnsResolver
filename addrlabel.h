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

/* These macros are modelled after the ones in <netinet/in6.h>. */

/* RFC 4380, section 2.6 */
#define IN6_IS_ADDR_TEREDO(a) \
    ((*(const uint32_t*)(const void*)(&(a)->s6_addr[0]) == ntohl(0x20010000)))

/* RFC 3056, section 2. */
#define IN6_IS_ADDR_6TO4(a) (((a)->s6_addr[0] == 0x20) && ((a)->s6_addr[1] == 0x02))

/* 6bone testing address area (3ffe::/16), deprecated in RFC 3701. */
#define IN6_IS_ADDR_6BONE(a) (((a)->s6_addr[0] == 0x3f) && ((a)->s6_addr[1] == 0xfe))

constexpr uint32_t ADDRLABEL_ULA = 13;        // RFC 6724
constexpr uint32_t ADDRLABEL_ULA_LOCAL = 14;  // draft-ietf-6man-rfc6724-update

// Calculates an RFC6724-style address label from the address itself.
uint32_t resolv_getaddrlabel_simple(const struct sockaddr* addr);

// Fetches an RFC6724-style address label from the kernel.
uint32_t resolv_getaddrlabel_netlink(const struct sockaddr* addr, int ifindex);

// Get the label for a given IPv4/IPv6 address. RFC 6724, section 2.1.
uint32_t resolv_getaddrlabel(const struct sockaddr* addr);
