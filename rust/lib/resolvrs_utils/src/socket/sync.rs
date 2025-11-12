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

//! Sync socket implementations.

use nix::fcntl::fcntl;
use nix::fcntl::FcntlArg;
use nix::fcntl::OFlag;
use nix::sys::socket::recv;
use nix::sys::socket::send;
use nix::sys::socket::sendmsg;
use nix::sys::socket::ControlMessage;
use nix::sys::socket::MsgFlags;
use std::io::ErrorKind;
use std::io::IoSlice;
use std::io::Result;
use std::os::fd::AsRawFd as _;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;

fn temp_failure_retry<F, T, E>(mut f: F) -> std::io::Result<T>
where
    F: FnMut() -> std::result::Result<T, E>,
    E: Into<std::io::Error>,
{
    loop {
        match f() {
            Err(e) => {
                let error = e.into();
                if error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            Ok(res) => return Ok(res),
        }
    }
}

/// UnixSeqpacket is loosely modeled after std::os::unix::net::UnixDatagram.
pub struct UnixSeqpacket {
    fd: OwnedFd,
}

impl UnixSeqpacket {
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut flags = OFlag::from_bits_truncate(fcntl(self.fd.as_raw_fd(), FcntlArg::F_GETFL)?);
        if nonblocking {
            flags.insert(OFlag::O_NONBLOCK)
        } else {
            flags.remove(OFlag::O_NONBLOCK)
        }
        fcntl(self.fd.as_raw_fd(), FcntlArg::F_SETFL(flags))?;
        Ok(())
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        temp_failure_retry(|| recv(self.fd.as_raw_fd(), buf, MsgFlags::empty()))
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        temp_failure_retry(|| send(self.fd.as_raw_fd(), buf, MsgFlags::empty()))
    }

    pub fn send_with_fd(&self, buf: &[u8], fd: OwnedFd) -> Result<usize> {
        let iov = [IoSlice::new(buf)];
        let raw_fds = [fd.as_raw_fd()];
        let cmsgs = [ControlMessage::ScmRights(&raw_fds)];

        temp_failure_retry(|| {
            sendmsg::<()>(self.fd.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
        })
    }
}

impl FromRawFd for UnixSeqpacket {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        // SAFETY:
        // The caller is responsible for ensuring that `fd` is a valid (and unowned) file descriptor
        unsafe { Self { fd: OwnedFd::from_raw_fd(fd) } }
    }
}
