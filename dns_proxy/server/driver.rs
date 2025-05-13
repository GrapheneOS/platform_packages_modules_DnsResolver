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

//! Provides a backing task to implement a Server

use std::collections::hash_map::Entry as HashMapEntry;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::UdpSocket as SyncUdpSocket;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::rc::Rc;

use log::info;
use nix::libc::c_int;
use nix::libc::setsockopt;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::Command;
use super::DownstreamIndexPort;
use super::Result;
use super::UpstreamParam;

// TODO(b/409455084): workaround while waiting for upstream changes.
const SO_BINDTOIFINDEX: c_int = 62;

#[derive(Debug)]
pub(super) struct Driver {
    command_rx: mpsc::Receiver<Command>,
    /// Map of DownstreamIndexPort pair to the upstream parameters.
    upstream_map: HashMap<DownstreamIndexPort, UpstreamParam>,
    /// Map of DownstreamIndexPort pair to the UDP socket it is listening to.
    downstream_socket_map: HashMap<DownstreamIndexPort, DownstreamUdpSocket>,
}

impl Driver {
    pub fn new(command_rx: mpsc::Receiver<Command>) -> Self {
        Self { command_rx, upstream_map: HashMap::new(), downstream_socket_map: HashMap::new() }
    }

    pub async fn drive(mut self) -> Option<()> {
        loop {
            self.drive_once().await?;
        }
    }

    /// Drive the event once. Returns `Some(())` if the loop shall continue,
    /// None if it shall terminate.
    async fn drive_once(&mut self) -> Option<()> {
        if let Some(command) = self.command_rx.recv().await {
            self.handle_cmd(command)
        } else {
            info!("Exit DnsProxy due to all DnsProxyCommand transceiver out of scope");
            None
        }
    }

    fn handle_cmd(&mut self, cmd: Command) -> Option<()> {
        match cmd {
            Command::ConfigureDnsProxy { index_port, upstream_param, response_tx } => {
                let _ = response_tx
                    .send(self.handle_configure_dns_proxy_cmd(index_port, upstream_param));
                Some(())
            }
            Command::StopDnsProxy { index_port, response_tx } => {
                let _ = response_tx.send(self.handle_stop_dns_proxy_cmd(&index_port));
                Some(())
            }
        }
    }

    fn handle_configure_dns_proxy_cmd(
        &mut self,
        index_port: DownstreamIndexPort,
        upstream_param: UpstreamParam,
    ) -> Result<()> {
        self.upstream_map.insert(index_port, upstream_param);
        if let HashMapEntry::Vacant(vacant_entry) = self.downstream_socket_map.entry(index_port) {
            let sync_socket = Driver::build_udp_socket(&index_port)?;
            let socket = DownstreamUdpSocket::new(Rc::new(UdpSocket::from_std(sync_socket)?));
            vacant_entry.insert(socket);
        }
        Ok(())
    }

    fn build_udp_socket(index_port: &DownstreamIndexPort) -> Result<SyncUdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        Driver::set_downstream_sockopts(&socket, index_port.if_index)?;
        socket
            .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::from_bits(0)), index_port.port).into())?;
        Ok(socket.into())
    }

    fn set_downstream_sockopts(socket: &Socket, if_index: u32) -> Result<()> {
        socket.set_nonblocking(true)?;
        if if_index > 0 {
            // TODO(409455084): workaround while waiting for upstream changes.
            // Safety: setting if_index is safe since we own the FD and if_index is fixed length.
            unsafe {
                setsockopt(
                    socket.as_fd().as_raw_fd(),
                    nix::libc::SOL_SOCKET,
                    SO_BINDTOIFINDEX,
                    &if_index as *const _ as *const nix::libc::c_void,
                    std::mem::size_of::<c_int>() as nix::libc::socklen_t,
                );
            }
        }
        Ok(())
    }

    fn handle_stop_dns_proxy_cmd(&mut self, index_port: &DownstreamIndexPort) -> Result<()> {
        self.upstream_map.remove(index_port);
        Ok(())
    }
}

/// Downstream UDP socket
#[derive(Debug)]
struct DownstreamUdpSocket {
    /// Reference-counted socket
    socket: Rc<UdpSocket>,
}

impl DownstreamUdpSocket {
    /// Constructor
    fn new(socket: Rc<UdpSocket>) -> Self {
        Self { socket }
    }
}
