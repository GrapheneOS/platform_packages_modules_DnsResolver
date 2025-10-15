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
use clap::ValueEnum;
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
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;

#[derive(ValueEnum, Clone)]
#[clap(rename_all = "kebab_case")]
enum SocketType {
    TCP,
    UDP,
}

#[derive(Parser)]
struct Args {
    // Socket type to open.
    #[arg(long, value_enum)]
    socktype: SocketType,

    // Interface index to bind the socket to. Must be provided when `--sockype tcp`
    #[arg(long)]
    ifindex: Option<u32>,

    // File descriptor of unix domain socket to pass the result.
    #[arg(long)]
    resultfd: i32,
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

trait UnixStreamExt {
    fn send_with_fd(&self, buf: &[u8], fd: RawFd) -> Result<usize>;
}

impl UnixStreamExt for UnixStream {
    fn send_with_fd(&self, buf: &[u8], fd: RawFd) -> Result<usize> {
        let iov = [IoSlice::new(buf)];
        let fds = [fd];
        let cmsgs = [ControlMessage::ScmRights(&fds)];

        use std::os::fd::AsRawFd as _;
        let rawfd = self.as_raw_fd();
        let size = sendmsg::<()>(rawfd, &iov, &cmsgs, MsgFlags::empty(), None)?;
        Ok(size)
    }
}

fn create_socket(socktype: SocketType, ifindex: Option<u32>) -> Result<Socket> {
    let t = match socktype {
        SocketType::TCP => Type::STREAM.nonblocking().cloexec(),
        SocketType::UDP => Type::DGRAM.nonblocking().cloexec(),
    };
    let socket = Socket::new(Domain::IPV6, t, None)?;

    // TODO: add a test to ensure bindv6only is set to 0.
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;

    if let Some(ifindex) = ifindex {
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
    let sock = create_socket(args.socktype, args.ifindex)?;

    use std::os::fd::FromRawFd as _;
    // Safety: The parent process passes a valid file descriptor which the child is expected to
    // close.
    let result_stream = unsafe { UnixStream::from_raw_fd(args.resultfd) };

    // Send a single 0 byte along with the fd.
    use std::os::fd::AsRawFd as _;
    let _ = result_stream.send_with_fd(&[0; 1], sock.as_raw_fd())?;
    Ok(())
}
