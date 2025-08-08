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

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use nix::cmsg_space;
use nix::libc::in6_pktinfo;
use nix::sys::socket::recv;
use nix::sys::socket::recvmsg;
use nix::sys::socket::setsockopt;
use nix::sys::socket::sockopt::Ipv6RecvPacketInfo;
use nix::sys::socket::ControlMessageOwned;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::RecvMsg;
use nix::sys::socket::SockaddrLike;
use std::io::IoSliceMut;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use tokio::net::UdpSocket;

/// A UDP socket that can receive packets with their destination interface index.
pub struct UdpServerSocket {
    socket: UdpSocket,
}

impl UdpServerSocket {
    /// Creates a new UdpServerSocket from a std::net::UdpSocket.
    pub fn new(socket: std::net::UdpSocket) -> Result<Self> {
        // UdpServerSocket must be a dual-stack socket.
        ensure!(socket.local_addr()?.ip() == Ipv6Addr::UNSPECIFIED, "Socket must be dual-stack");

        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket)?;
        setsockopt(&socket, Ipv6RecvPacketInfo, &true)?;
        Ok(Self { socket })
    }

    /// Receives a single datagram from the socket. On success, returns the number
    /// of bytes read, the sender's address, and the interface index. Must be used in combination
    /// with readable().
    #[allow(clippy::unnecessary_cast)]
    fn try_recv_from_with_ifindex(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV6, u32)> {
        let mut cmsg_buf = cmsg_space!(in6_pktinfo);
        let iov = &mut [IoSliceMut::new(buf)];
        let msg = self.socket.try_recvmsg::<nix::sys::socket::SockaddrIn6>(
            iov,
            Some(&mut cmsg_buf),
            MsgFlags::empty(),
        )?;

        // If cmsgs are not present, or the Ipv6PacketInfo option is not found, the function
        // returns an error. This should never happen, i.e. it likely indicates a kernel bug.
        // Note that anyhow::context() converts the Option return type to a Result.
        // Note2: different versions of Rust libc define ipi6_ifindex as u32 or i32. Force the cast
        // to u32 for compatibility.
        let ifindex = msg
            .cmsgs()?
            .find_map(|cmsg| {
                if let ControlMessageOwned::Ipv6PacketInfo(packet_info) = cmsg {
                    Some(packet_info.ipi6_ifindex)
                } else {
                    None
                }
            })
            .context("No Ipv6PacketInfo found in cmsgs.")? as u32;

        let addr = msg.address.map(SocketAddrV6::from).unwrap();
        Ok((msg.bytes, addr, ifindex))
    }

    pub async fn recv_from_with_ifindex(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddrV6, u32)> {
        self.socket.readable().await?;
        self.try_recv_from_with_ifindex(buf)
    }
}

/// UdpSocket extension trait for implementing UdpSocket functionality that is missing in
/// tokio::net::UdpSocket.
trait UdpSocketExt {
    /// A version of try_recv that accepts flags.
    ///
    /// This function is usually paired with readable(). See UdpSocket::try_recv for details.
    fn try_recv_flags(&self, buf: &mut [u8], flags: MsgFlags) -> std::io::Result<usize>;

    /// A tokio-compatible wrapper around recvmsg.
    fn try_recvmsg<'a, 'outer, 'inner, S>(
        &'a self,
        iov: &'outer mut [IoSliceMut<'inner>],
        cmsg_buf: Option<&'a mut Vec<u8>>,
        flags: MsgFlags,
    ) -> std::io::Result<RecvMsg<'a, 'outer, S>>
    where
        S: SockaddrLike + 'a,
        'inner: 'outer;
}

impl UdpSocketExt for UdpSocket {
    fn try_recv_flags(&self, buf: &mut [u8], flags: MsgFlags) -> std::io::Result<usize> {
        // UdpSocket::try_io() is required to consume the readable readiness event of the
        // UdpSocket. See notes on "Cancel safety" in UdpSocket::readable().
        self.try_io(tokio::io::Interest::READABLE, || {
            use std::os::fd::AsRawFd as _;
            recv(self.as_raw_fd(), buf, flags).map_err(std::io::Error::from)
        })
    }

    fn try_recvmsg<'a, 'outer, 'inner, S>(
        &'a self,
        iov: &'outer mut [IoSliceMut<'inner>],
        cmsg_buf: Option<&'a mut Vec<u8>>,
        flags: MsgFlags,
    ) -> std::io::Result<RecvMsg<'a, 'outer, S>>
    where
        S: SockaddrLike + 'a,
        'inner: 'outer,
    {
        self.try_io(tokio::io::Interest::READABLE, || {
            use std::os::fd::AsRawFd as _;
            recvmsg(self.as_raw_fd(), iov, cmsg_buf, flags).map_err(std::io::Error::from)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::TEST_VALID_DNS_QUERY;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_udp_server_socket_new() {
        let std_socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let server_socket = UdpServerSocket::new(std_socket);
        assert!(server_socket.is_ok());
    }

    #[tokio::test]
    async fn test_udp_server_socket_recv_from_with_ifindex() {
        let std_socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let server_port = std_socket.local_addr().unwrap().port();
        let server_socket = UdpServerSocket::new(std_socket).unwrap();

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), server_port);

        client_socket.connect(server_addr).await.unwrap();
        client_socket.send(&TEST_VALID_DNS_QUERY).await.unwrap();

        let mut buf = [0u8; 1024];
        let (len, addr, ifindex) = server_socket.recv_from_with_ifindex(&mut buf).await.unwrap();

        assert_eq!(len, TEST_VALID_DNS_QUERY.len());
        assert_eq!(&buf[..len], &TEST_VALID_DNS_QUERY);
        // Must convert addresses to canonical representation, so the IPv6-mapped IPv4 addresses
        // compare correctly.
        assert_eq!(addr.ip().to_canonical(), client_addr.ip().to_canonical());
        assert_eq!(addr.port(), client_addr.port());
        assert_eq!(ifindex, 1 /* loopback */);
    }
}
