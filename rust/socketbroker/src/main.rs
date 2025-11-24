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
use log::error;
use log::LevelFilter;
use resolvrs_utils::socket::sync::UnixSeqpacket;
use socket2::Domain;
use socket2::Socket;
use socket2::Type;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use std::os::fd::FromRawFd as _;

enum SocketType {
    TCP { ifindex: u32 },
    UDP,
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
    android_logger::init_once(android_logger::Config::default().with_max_level(LevelFilter::Info));
    let args = Args::parse();

    // SAFETY:
    // The parent process passes a valid file descriptor which the child is expected to close.
    let cmd_sock = unsafe { UnixSeqpacket::from_raw_fd(args.cmdfd) };
    cmd_sock.set_nonblocking(false)?;

    // Immediately create a UDP socket.
    let sock = create_socket(SocketType::UDP)?;
    cmd_sock.send_with_fd(&[0; 1], sock.into())?;

    loop {
        // Allocate a 5-byte buffer to detect large packets since the message length is 4 bytes.
        let mut buf = [0; 5];
        let ifindex = match cmd_sock.recv(&mut buf) {
            Ok(4) => u32::from_le_bytes(buf[..4].try_into().unwrap()),
            // If the other side closed gracefully, the socket will read EOF (len == 0, handled as
            // part of Ok(len)). Otherwise, it will return with ECONNRESET. In either case, exit
            // the program.
            // Note that len == 0 could also indicate a 0-length packet. The 2 cases are
            // indistinguishable on AF_UNIX SOCK_SEQPACKET sockets when using recv(). It seems that
            // the only way to reliably detect socket closure is to poll() and wait for POLLHUP |
            // POLLERR. In reality, this should not matter, because we are in control of the
            // client and should never see a 0-length packet.
            Err(e) if e.kind() == ErrorKind::ConnectionReset => break,

            // A TCP socket request must always be 4-bytes, so exit the program if any other length
            // is received.
            Ok(_len) => {
                error!("Received an illformed TCP socket request");
                panic!();
            }
            // Ignore all other errors. This should never happen.
            Err(e) => {
                // TODO: Consider panicking as common errors are handled above.
                error!("recv failed: {e}");
                continue;
            }
        };

        match create_socket(SocketType::TCP { ifindex }) {
            Ok(sock) => {
                // Send a single 0 byte along with the fd. Ignore any errors.
                let _ = cmd_sock.send_with_fd(&[0; 1], sock.into());
            }
            Err(e) => {
                // If socket creation failed, log and send a single 0 byte to unblock the reader.
                // Ignore any errors.
                error!("Failed to create socket: {e}");
                let _ = cmd_sock.send(&[0; 1]);
            }
        }
    }

    Ok(())
}
