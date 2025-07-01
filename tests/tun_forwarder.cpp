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
 *
 */

#define LOG_TAG "TunForwarder"

#include "tun_forwarder.h"

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ioctl.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/eventfd.h>
#include <sys/poll.h>

#include <android-base/logging.h>

extern "C" {
#include <checksum.h>
}

using android::base::Error;
using android::base::Result;
using android::base::unique_fd;
using android::netdutils::Slice;

namespace android::net {

static constexpr int MAXMTU = 1500;
static constexpr ssize_t TUN_HDRLEN = sizeof(struct tun_pi);
static constexpr ssize_t IP4_HDRLEN = sizeof(struct iphdr);
static constexpr ssize_t IP6_HDRLEN = sizeof(struct ip6_hdr);
static constexpr ssize_t TCP_HDRLEN = sizeof(struct tcphdr);
static constexpr ssize_t UDP_HDRLEN = sizeof(struct udphdr);

namespace {

bool operator==(const in6_addr& x, const in6_addr& y) {
    return std::memcmp(x.s6_addr, y.s6_addr, 16) == 0;
}

bool operator!=(const in6_addr& x, const in6_addr& y) {
    return !(x == y);
}

bool operator<(const in6_addr& x, const in6_addr& y) {
    return std::memcmp(x.s6_addr, y.s6_addr, 16) < 0;
}

}  // namespace

Result<TunForwarder::v4pair> TunForwarder::v4pair::makePair(
        const std::array<std::string, 2>& addrs) {
    v4pair pair;
    if (inet_pton(AF_INET, addrs[0].c_str(), &pair.src) != 1 ||
        inet_pton(AF_INET, addrs[1].c_str(), &pair.dst) != 1) {
        return Error() << "Failed to make v4pair";
    }
    return pair;
}

bool TunForwarder::v4pair::operator==(const v4pair& o) const {
    return std::tie(src.s_addr, dst.s_addr) == std::tie(o.src.s_addr, o.dst.s_addr);
}

bool TunForwarder::v4pair::operator<(const v4pair& o) const {
    return std::tie(src.s_addr, dst.s_addr) < std::tie(o.src.s_addr, o.dst.s_addr);
}

Result<TunForwarder::v6pair> TunForwarder::v6pair::makePair(
        const std::array<std::string, 2>& addrs) {
    v6pair pair;
    if (inet_pton(AF_INET6, addrs[0].c_str(), &pair.src) != 1 ||
        inet_pton(AF_INET6, addrs[1].c_str(), &pair.dst) != 1) {
        return Error() << "Failed to make v6pair";
    }
    return pair;
}

bool TunForwarder::v6pair::operator==(const v6pair& o) const {
    return src == o.src && dst == o.dst;
}

bool TunForwarder::v6pair::operator<(const v6pair& o) const {
    if (src != o.src) return src < o.src;
    return dst < o.dst;
}

TunForwarder::TunForwarder(TunFdMap&& tunFds) : mTunFds(std::move(tunFds)) {
    mEventFd.reset(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
}

TunForwarder::~TunForwarder() {
    stopForwarding();
    if (mForwarder.joinable()) {
        mForwarder.join();
    }
}

bool TunForwarder::startForwarding() {
    if (mForwarder.joinable()) return false;
    mForwarder = std::thread(&TunForwarder::loop, this);
    return true;
}

bool TunForwarder::stopForwarding() {
    return signalEventFd();
}

// Assume all of the strings in |from| and |to| are the IP addresses of the same IP version.
bool TunForwarder::addForwardingRule(const std::array<std::string, 2>& from,
                                     const std::array<std::string, 2>& to, const std::string& iif) {
    const auto toFdItr = mTunFds.find(iif);
    if (toFdItr == mTunFds.end()) {
        return false;
    };
    const bool isV4 = (from[0].find(':') == from[0].npos);
    if (isV4) {
        auto k = v4pair::makePair(from);
        auto v = v4pair::makePair(to);
        if (!k.ok() || !v.ok()) return false;
        mRulesIpv4[k.value()] = {v.value(), iif};
    } else {
        auto k = v6pair::makePair(from);
        auto v = v6pair::makePair(to);
        if (!k.ok() || !v.ok()) return false;
        mRulesIpv6[k.value()] = {v.value(), iif};
    }
    return true;
}

unique_fd TunForwarder::createTun(const std::string& ifname) {
    unique_fd fd(open("/dev/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC));
    if (!fd.ok()) {
        return {};
    }

    ifreq ifr = {
            .ifr_ifru = {.ifru_flags = IFF_TUN},
    };
    strlcpy(ifr.ifr_name, ifname.data(), sizeof(ifr.ifr_name));

    if (ioctl(fd.get(), TUNSETIFF, &ifr) == -1) {
        PLOG(WARNING) << "failed to set tun ifname to " << ifr.ifr_name;
        return {};
    }

    unique_fd inet6CtrlSock(socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    ifr.ifr_flags = IFF_UP;
    if (ioctl(inet6CtrlSock.get(), SIOCSIFFLAGS, &ifr) == -1) {
        PLOG(WARNING) << "failed to bring up tun interface " << ifr.ifr_name;
        return {};
    }

    return fd;
}

void TunForwarder::loop() {
    std::vector<struct pollfd> waitFds;
    waitFds.push_back({mEventFd.get(), POLLIN, 0});
    for (const auto& [name, fd] : mTunFds) {
        waitFds.push_back({fd.get(), POLLIN, 0});
    }

    while (true) {
        if (const int ret = poll(waitFds.data(), waitFds.size(), kPollTimeoutMs); ret <= 0) {
            if (ret < 0 && errno != EINTR) PLOG(ERROR) << "poll failed";
            break;
        }

        if (waitFds[0].revents & (POLLIN | POLLERR)) {
            uint64_t value = 0;
            eventfd_read(mEventFd.get(), &value);
            break;
        }
        for (size_t i = 1; i < waitFds.size(); ++i) {
            if (waitFds[i].revents & (POLLIN | POLLERR)) handlePacket(waitFds[i].fd);
        }
    }
}

void TunForwarder::handlePacket(int fd) const {
    uint8_t buf[MAXMTU + TUN_HDRLEN];

    ssize_t readlen = read(fd, buf, std::size(buf));
    if (readlen < 0) {
        PLOG(ERROR) << "failed to read packets from tun";
        return;
    } else if (readlen == 0) {
        PLOG(ERROR) << "tun interface removed";
        return;
    }

    // Filter the packet. Only TCP and UDP packets are allowed.
    const Slice tunPacket(buf, readlen);
    auto routeResult = validateAndRoutePacket(tunPacket);
    if (!routeResult.ok()) {
        LOG(DEBUG) << "validatePacket failed: " << routeResult.error();
        return;
    }

    // Change the packet's source/destination address and checksum.
    if (auto result = translatePacket(tunPacket); !result.ok()) {
        LOG(ERROR) << "translatePacket failed: " << result.error();
        return;
    }
    const auto fdItr = mTunFds.find(routeResult.value());
    if (fdItr == mTunFds.end()) {
        LOG(ERROR) << "Interface " << routeResult.value() << " not found";
        return;
    }
    // Write the new packet to the fd, causing the kernel to receive it on the tun interface.
    write(fdItr->second.get(), buf, readlen);
}

Result<std::string> TunForwarder::validateAndRoutePacket(Slice tunPacket) const {
    if (tunPacket.size() < TUN_HDRLEN) {
        return Error() << "Too short for a tun header";
    }

    const tun_pi* const tunHeader = reinterpret_cast<tun_pi*>(tunPacket.base());
    if (tunHeader->flags != 0) {
        return Error() << "Unexpected tun flags " << static_cast<int>(tunHeader->flags);
    }

    switch (uint16_t proto = ntohs(tunHeader->proto); proto) {
        case ETH_P_IP:
            return validateAndRouteIpv4Packet(drop(tunPacket, TUN_HDRLEN));
        case ETH_P_IPV6:
            return validateAndRouteIpv6Packet(drop(tunPacket, TUN_HDRLEN));
        default:
            return Error() << "Unsupported packet type 0x" << std::hex << static_cast<int>(proto);
    }
}

Result<std::string> TunForwarder::validateAndRouteIpv4Packet(Slice ipv4Packet) const {
    if (ipv4Packet.size() < IP4_HDRLEN) {
        return Error() << "Too short for an ip header";
    }

    const iphdr* const ipHeader = reinterpret_cast<iphdr*>(ipv4Packet.base());
    if (ipHeader->ihl < 5) {
        return Error() << "IP header length set to less than 5";
    }
    if (ipHeader->ihl * 4 > ipv4Packet.size()) {
        return Error() << "IP header length set too large: " << ipHeader->ihl;
    }
    if (ipHeader->version != 4) {
        return Error() << "IP header version not 4: " << ipHeader->version;
    }
    const auto routeFdItr = mRulesIpv4.find({ipHeader->saddr, ipHeader->daddr});
    if (routeFdItr == mRulesIpv4.end()) {
        return Error() << "Can't find any v4 rule. Packet hex dump: " << toHex(ipv4Packet, 32);
    }

    switch (ipHeader->protocol) {
        case IPPROTO_UDP:
            if (const auto result = validateUdpPacket(drop(ipv4Packet, ipHeader->ihl * 4));
                !result.ok()) {
                return result.error();
            }
            break;
        case IPPROTO_TCP:
            if (const auto result = validateTcpPacket(drop(ipv4Packet, ipHeader->ihl * 4));
                !result.ok()) {
                return result.error();
            }
            break;
        default:
            return Error() << "Unsupported transport protocol "
                           << static_cast<int>(ipHeader->protocol);
    }
    return routeFdItr->second.second;
}

Result<std::string> TunForwarder::validateAndRouteIpv6Packet(Slice ipv6Packet) const {
    if (ipv6Packet.size() < IP6_HDRLEN) {
        return Error() << "Too short for an ipv6 header";
    }

    const ip6_hdr* const ipv6Header = reinterpret_cast<ip6_hdr*>(ipv6Packet.base());
    const auto routeFdItr = mRulesIpv6.find({ipv6Header->ip6_src, ipv6Header->ip6_dst});
    if (routeFdItr == mRulesIpv6.end()) {
        return Error() << "Can't find any v6 rule. Packet hex dump: " << toHex(ipv6Packet, 32);
    }

    switch (ipv6Header->ip6_nxt) {
        case IPPROTO_UDP:
            if (const auto result = validateUdpPacket(drop(ipv6Packet, IP6_HDRLEN)); !result.ok()) {
                return result.error();
            }
            break;
        case IPPROTO_TCP:
            if (const auto result = validateTcpPacket(drop(ipv6Packet, IP6_HDRLEN)); !result.ok()) {
                return result.error();
            }
            break;
        default:
            return Error() << "Expect TCP/UDP in ipv6 next header: "
                           << static_cast<int>(ipv6Header->ip6_nxt);
    }
    return routeFdItr->second.second;
}

Result<void> TunForwarder::validateUdpPacket(Slice udpPacket) const {
    if (udpPacket.size() < UDP_HDRLEN) {
        return Error() << "Too short for a udp header";
    }
    return {};
}

Result<void> TunForwarder::validateTcpPacket(Slice tcpPacket) const {
    if (tcpPacket.size() < TCP_HDRLEN) {
        return Error() << "Too short for a tcp header";
    }

    const tcphdr* const tcpHeader = reinterpret_cast<tcphdr*>(tcpPacket.base());
    if (tcpHeader->doff < 5) {
        return Error() << "TCP header length set to less than 5";
    }
    if (tcpHeader->doff * 4 > tcpPacket.size()) {
        return Error() << "TCP header length set too large: " << tcpHeader->doff;
    }
    return {};
}

Result<void> TunForwarder::translatePacket(Slice tunPacket) const {
    const tun_pi* const tunHeader = reinterpret_cast<tun_pi*>(tunPacket.base());
    switch (uint16_t proto = ntohs(tunHeader->proto); proto) {
        case ETH_P_IP:
            return translateIpv4Packet(drop(tunPacket, TUN_HDRLEN));
        case ETH_P_IPV6:
            return translateIpv6Packet(drop(tunPacket, TUN_HDRLEN));
        default:
            return Error() << "translate: Unsupported packet type 0x" << std::hex
                           << static_cast<int>(proto);
    }
}

Result<void> TunForwarder::translateIpv4Packet(Slice ipv4Packet) const {
    iphdr* ipHeader = reinterpret_cast<iphdr*>(ipv4Packet.base());
    const size_t ipHeaderLen = ipHeader->ihl * 4;
    const size_t transport_len = ipv4Packet.size() - ipHeaderLen;

    uint32_t oldPseudoSum = ipv4_pseudo_header_checksum(ipHeader, transport_len);
    for (const auto& [from, to] : mRulesIpv4) {
        if (ipHeader->saddr == static_cast<int>(from.src.s_addr) &&
            ipHeader->daddr == static_cast<int>(from.dst.s_addr)) {
            ipHeader->saddr = to.first.src.s_addr;
            ipHeader->daddr = to.first.dst.s_addr;
            break;
        }
    }
    uint32_t newPseudoSum = ipv4_pseudo_header_checksum(ipHeader, transport_len);

    ipHeader->check = 0;
    ipHeader->check = ip_checksum(ipHeader, sizeof(struct iphdr));

    switch (ipHeader->protocol) {
        case IPPROTO_UDP:
            translateUdpPacket(drop(ipv4Packet, ipHeaderLen), oldPseudoSum, newPseudoSum);
            break;
        case IPPROTO_TCP:
            translateTcpPacket(drop(ipv4Packet, ipHeaderLen), oldPseudoSum, newPseudoSum);
            break;
        default:
            return Error() << "translate: Unsupported transport protocol "
                           << static_cast<int>(ipHeader->protocol);
    }

    return {};
}

Result<void> TunForwarder::translateIpv6Packet(Slice ipv6Packet) const {
    ip6_hdr* ipv6Header = reinterpret_cast<ip6_hdr*>(ipv6Packet.base());
    const size_t ipHeaderLen = IP6_HDRLEN;
    const size_t transport_len = ipv6Packet.size() - ipHeaderLen;

    uint32_t oldPseudoSum =
            ipv6_pseudo_header_checksum(ipv6Header, transport_len, ipv6Header->ip6_nxt);
    for (const auto& [from, to] : mRulesIpv6) {
        if (ipv6Header->ip6_src == from.src && ipv6Header->ip6_dst == from.dst) {
            ipv6Header->ip6_src = to.first.src;
            ipv6Header->ip6_dst = to.first.dst;
            break;
        }
    }
    uint32_t newPseudoSum =
            ipv6_pseudo_header_checksum(ipv6Header, transport_len, ipv6Header->ip6_nxt);

    switch (ipv6Header->ip6_nxt) {
        case IPPROTO_UDP:
            translateUdpPacket(drop(ipv6Packet, ipHeaderLen), oldPseudoSum, newPseudoSum);
            break;
        case IPPROTO_TCP:
            translateTcpPacket(drop(ipv6Packet, ipHeaderLen), oldPseudoSum, newPseudoSum);
            break;
        default:
            return Error() << "transliate: Expect TCP/UDP in ipv6 next header: "
                           << static_cast<int>(ipv6Header->ip6_nxt);
    }

    return {};
}

void TunForwarder::translateUdpPacket(Slice udpPacket, uint32_t oldPseudoSum,
                                      uint32_t newPseudoSum) const {
    udphdr* udpHeader = reinterpret_cast<udphdr*>(udpPacket.base());
    if (udpHeader->check) {
        udpHeader->check = ip_checksum_adjust(udpHeader->check, oldPseudoSum, newPseudoSum);
    } else {
        uint32_t tmp = ip_checksum_add(newPseudoSum, udpPacket.base(), udpPacket.size());
        udpHeader->check = ip_checksum_finish(tmp);
    }

    // RFC 768: "If the computed checksum is zero, it is transmitted as all ones (the equivalent
    // in one's complement arithmetic)."
    if (!udpHeader->check) {
        udpHeader->check = 0xffff;
    }
}

void TunForwarder::translateTcpPacket(Slice tcpPacket, uint32_t oldPseudoSum,
                                      uint32_t newPseudoSum) const {
    tcphdr* tcpHeader = reinterpret_cast<tcphdr*>(tcpPacket.base());
    tcpHeader->check = ip_checksum_adjust(tcpHeader->check, oldPseudoSum, newPseudoSum);
}

bool TunForwarder::signalEventFd() {
    return eventfd_write(mEventFd.get(), 1) == 0;
}

}  // namespace android::net
