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

use anyhow::bail;
use anyhow::Result;
use command_fds::CommandFdExt as _;
use nix::sys::socket::socketpair;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use resolvrs_utils::socket;
use std::os::fd::AsRawFd as _;
use std::process::Child;
use std::process::Command;

const SOCKET_BROKER_EXEC: &str = "/apex/com.android.resolv/bin/socketbroker";

struct SocketBroker {
    child: Child,
    cmd_sock: socket::tokio::UnixSeqpacket,
}

impl SocketBroker {
    /// Fork-execs the socketbroker and blocks the calling thread until the child is ready.
    pub fn fork_exec() -> Result<Self> {
        // Creates sockets in blocking mode.
        let (parent_cmd_sock, child_cmd_sock) =
            socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)?;
        let child_cmd_sock_raw = child_cmd_sock.as_raw_fd();

        let mut cmd = Command::new(SOCKET_BROKER_EXEC);
        cmd.preserved_fds(vec![child_cmd_sock]);
        cmd.args(["--cmdfd", &child_cmd_sock_raw.to_string()]);

        let mut child = cmd.spawn()?;

        // The socketbroker will either write a single (arbitrary) byte to the cmd socket as soon
        // as it is ready or close the socket in case it exits.
        let sync_socket = socket::sync::UnixSeqpacket::from(parent_cmd_sock);
        let _ = sync_socket.recv(&mut [0; 0]);

        // try_wait returns some status if the child has already exited.
        if let Some(status) = child.try_wait()? {
            bail!("socketbroker already exited with status: {}", status);
        }

        // TODO: this needs a tokio rt reference; otherwise it'll panic.
        // Change the socket to nonblocking mode before converting to its async counterpart.
        sync_socket.set_nonblocking(true)?;
        let async_socket = socket::tokio::UnixSeqpacket::from_sync(sync_socket)?;
        Ok(Self { child, cmd_sock: async_socket })
    }
}

impl Drop for SocketBroker {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
