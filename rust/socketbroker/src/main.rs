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

//! A utility that can be used to open sockets and bind them to privileged ports.
//! The bound socket is returned via the provided unix socket.

use clap::Parser;
use nix::fcntl::fcntl;
use nix::fcntl::FcntlArg;
use nix::fcntl::OFlag;
use nix::sys::socket::recv;
use nix::sys::socket::send;
use nix::sys::socket::sendmsg;
use nix::sys::socket::ControlMessage;
use nix::sys::socket::MsgFlags;
use socket2::Domain;
use socket2::Socket;
use socket2::Type;
use std::io::Error;
use std::io::IoSlice;
use std::io::Result;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use std::os::fd::AsRawFd as _;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;

enum SocketType {
    TCP { ifindex: u32 },
    UDP,
}

impl SocketType {
    fn from_message(buf: &[u8]) -> Option<SocketType> {
        // UDP socket requests are encoded as a single arbitrary byte.
        // TCP socket requests are encoded as a 4-byte little-endian ifindex.
        if buf.len() == 1 {
            Some(SocketType::UDP)
        } else if buf.len() == 4 {
            // The conversion cannot fail because the length was already checked above.
            let bytes: [u8; 4] = buf.try_into().unwrap();
            Some(SocketType::TCP { ifindex: u32::from_le_bytes(bytes) })
        } else {
            None
        }
    }
}

#[derive(Parser)]
struct Args {
    // File descriptor of unix seqpacket socket to pass a socket request / result.
    #[arg(long)]
    cmdfd: i32,
}

trait SocketExt {
    fn bind_ifindex(&self, ifindex: u32) -> Result<()>;
}

impl SocketExt for Socket {
    // TODO: eventually this should call SO_BINDTOIFINDEX on kernels that support it.
    fn bind_ifindex(&self, ifindex: u32) -> Result<()> {
        let mut ifname_buf = [0 as libc::c_char; libc::IFNAMSIZ];
        // Safety: Safe because ifname_buf is of sufficient size.
        let ifname_ptr = unsafe { libc::if_indextoname(ifindex, ifname_buf.as_mut_ptr()) };

        if ifname_ptr.is_null() {
            return Err(Error::last_os_error());
        }

        // if_indextoname requires passing a char buf, which is either signed (on x86) or unsigned
        // (on arm) and needs to be explicitly casted for use in bind_device.
        let ifname_ubuf: &[u8] = bytemuck::cast_slice(&ifname_buf);
        self.bind_device(Some(ifname_ubuf))?;
        Ok(())
    }
}

/// UnixSeqpacket is loosely modeled after std::os::unix::net::UnixDatagram.
struct UnixSeqpacket {
    fd: OwnedFd,
}

#[allow(dead_code)]
impl UnixSeqpacket {
    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut flags = OFlag::from_bits_truncate(fcntl(self.fd.as_raw_fd(), FcntlArg::F_GETFL)?);
        if nonblocking {
            flags.insert(OFlag::O_NONBLOCK)
        } else {
            flags.remove(OFlag::O_NONBLOCK)
        }
        fcntl(self.fd.as_raw_fd(), FcntlArg::F_SETFL(flags))?;
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let len = recv(self.fd.as_raw_fd(), buf, MsgFlags::empty())?;
        Ok(len)
    }

    fn send(&self, buf: &[u8]) -> Result<usize> {
        let len = send(self.fd.as_raw_fd(), buf, MsgFlags::empty())?;
        Ok(len)
    }

    fn send_with_fd(&self, buf: &[u8], fd: OwnedFd) -> Result<usize> {
        let iov = [IoSlice::new(buf)];
        let raw_fds = [fd.as_raw_fd()];
        let cmsgs = [ControlMessage::ScmRights(&raw_fds)];

        let size = sendmsg::<()>(self.fd.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)?;
        Ok(size)
    }
}

impl FromRawFd for UnixSeqpacket {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        // SAFETY:
        // The caller is responsible for ensuring that `fd` is a valid (and unowned) file descriptor
        unsafe { Self { fd: OwnedFd::from_raw_fd(fd) } }
    }
}

fn create_socket(socktype: SocketType) -> Result<Socket> {
    let t = match socktype {
        SocketType::TCP { .. } => Type::STREAM.nonblocking().cloexec(),
        SocketType::UDP => Type::DGRAM.nonblocking().cloexec(),
    };
    let socket = Socket::new(Domain::IPV6, t, None)?;

    // TODO: add a test to ensure bindv6only is set to 0.
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;

    if let SocketType::TCP { ifindex } = socktype {
        socket.bind_ifindex(ifindex)?;
    }

    // Bind socket to port 53
    let addr = SocketAddrV6::new(
        Ipv6Addr::UNSPECIFIED,
        53, /*port*/
        0,  /*flowinfo*/
        0,  /*scope*/
    );
    socket.bind(&addr.into())?;

    Ok(socket)
}

fn main() -> Result<()> {
    let args = Args::parse();

    // SAFETY:
    // The parent process passes a valid file descriptor which the child is expected to close.
    let cmd_sock = unsafe { UnixSeqpacket::from_raw_fd(args.cmdfd) };
    cmd_sock.set_nonblocking(false)?;

    // Allocate a 5-byte buffer to detect large packets since the maximum message length is 4 bytes.
    let mut buf = [0; 5];
    let len = cmd_sock.recv(&mut buf)?;
    let Some(socket_type) = SocketType::from_message(&buf[..len]) else {
        return Err(std::io::Error::other("message invalid"));
    };

    let sock = create_socket(socket_type)?;

    // Send a single 0 byte along with the fd.
    let _ = cmd_sock.send_with_fd(&[0; 1], sock.into())?;
    Ok(())
}
