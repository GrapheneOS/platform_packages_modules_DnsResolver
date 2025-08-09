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

use nix::sys::socket::recv;
use nix::sys::socket::recvmsg;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::RecvMsg;
use nix::sys::socket::SockaddrLike;
use std::io::IoSliceMut;
use tokio::net::UdpSocket;

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
