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
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::Weak;

use log::error;
use log::info;
use nix::libc::c_int;
use nix::libc::setsockopt;
use nix::sys::socket::recv;
use nix::sys::socket::MsgFlags;
use rand::rngs::ThreadRng;
use rand::seq::SliceRandom;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::packet::DnsPacket;

use super::Command;
use super::DownstreamIndexPort;
use super::Error;
use super::NetContextClient;
use super::Result;
use super::UpstreamParam;

// TODO(b/409455084): workaround while waiting for upstream changes.
const SO_BINDTOIFINDEX: c_int = 62;

/// UdpDnsQuery is a DNS query packet with client address and downstream information attached.
#[derive(Debug)]
pub(crate) struct UdpDnsQuery {
    /// The query packet received from the client.
    query_packet: DnsPacket,
    /// the interface and port of downstream from where query is received.
    index_port: DownstreamIndexPort,
    /// The address of the client, used to send reply back to client.
    client_addr: SocketAddr,
    /// A weak reference to the socket to be used to send reply back to client.
    resp_socket: Weak<UdpSocket>,
}

impl UdpDnsQuery {
    fn new(
        query_packet: DnsPacket,
        index_port: DownstreamIndexPort,
        client_addr: SocketAddr,
        resp_socket: Weak<UdpSocket>,
    ) -> Self {
        UdpDnsQuery { query_packet, index_port, client_addr, resp_socket }
    }
}

#[derive(Debug)]
pub(super) struct Driver<C: NetContextClient> {
    /// NetContext client
    net_context_client: C,
    /// Weak Command sender
    weak_command_tx: mpsc::WeakSender<Command>,
    /// Command receiver.
    command_rx: mpsc::Receiver<Command>,
    /// Map of DownstreamIndexPort pair to the upstream parameters.
    upstream_map: HashMap<DownstreamIndexPort, UpstreamParam>,
    /// Map of DownstreamIndexPort pair to the handle of UDP socket it is listening to.
    downstream_task_handles_map: HashMap<DownstreamIndexPort, JoinHandle<Result<()>>>,
    /// Random number generator
    rng: ThreadRng,
}

impl<C: NetContextClient> Driver<C> {
    pub fn new(
        net_context_client: C,
        weak_command_tx: mpsc::WeakSender<Command>,
        command_rx: mpsc::Receiver<Command>,
    ) -> Self {
        Self {
            net_context_client,
            weak_command_tx,
            command_rx,
            upstream_map: HashMap::new(),
            downstream_task_handles_map: HashMap::new(),
            rng: rand::thread_rng(),
        }
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
            self.handle_cmd(command).await
        } else {
            info!("Exit DnsProxy due to all DnsProxyCommand transceiver out of scope");
            self.stop_listen_on_all_ports().await;
            None
        }
    }

    async fn handle_cmd(&mut self, cmd: Command) -> Option<()> {
        match cmd {
            Command::ConfigureDnsProxy { index_port, upstream_param, response_tx } => {
                let _ = response_tx
                    .send(self.handle_configure_dns_proxy_cmd(index_port, upstream_param));
                Some(())
            }
            Command::StopDnsProxy { index_port, response_tx } => {
                let _ = response_tx.send(self.handle_stop_dns_proxy_cmd(&index_port).await);
                Some(())
            }
            Command::ForwardUdpQuery(udp_dns_query) => {
                if let Err(e) = self.handle_udp_dns_query(udp_dns_query) {
                    error!("Error handling UDP query: {}", e);
                }
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
        if let HashMapEntry::Vacant(vacant_entry) =
            self.downstream_task_handles_map.entry(index_port)
        {
            let socket = build_udp_socket(&index_port)?;
            let handle = spawn_downstream_udp_socket(
                self.weak_command_tx.clone(),
                Arc::new(socket),
                index_port,
            );
            vacant_entry.insert(handle);
        }
        Ok(())
    }

    async fn handle_stop_dns_proxy_cmd(&mut self, index_port: &DownstreamIndexPort) -> Result<()> {
        self.upstream_map.remove(index_port);
        if let Some(handle) = self.downstream_task_handles_map.remove(index_port) {
            handle.abort();
            let _ = handle.await;
        }
        Ok(())
    }

    async fn stop_listen_on_all_ports(&mut self) {
        let handles: Vec<_> =
            self.downstream_task_handles_map.drain().map(|(_, handle)| handle).collect();
        for handle in handles {
            handle.abort();
            let _ = handle.await;
        }
    }

    fn handle_udp_dns_query(&mut self, query: UdpDnsQuery) -> Result<()> {
        let upstream_param = match self.upstream_map.get(&query.index_port) {
            Some(p) => p.to_owned(),
            None => return Ok(()),
        };
        let socket = self.configure_upstream_udp_socket(&upstream_param)?;
        tokio::spawn(async move {
            if let Err(e) = resolve_and_send_udp(socket, query).await {
                error!("Error resolving and sending UDP query: {}", e);
            }
        });
        Ok(())
    }

    fn configure_upstream_udp_socket(
        &mut self,
        upstream_param: &UpstreamParam,
    ) -> Result<UdpSocket> {
        let name_servers = self.net_context_client.get_name_servers(upstream_param);
        let name_server = name_servers.choose(&mut self.rng).ok_or(Error::NoNameServer)?;
        let domain = if name_server.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        if let Some(mark) = self.net_context_client.get_dns_mark(upstream_param) {
            socket.set_mark(mark)?;
        }
        // TODO(b:379992903): randomize port selection.
        socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::from_bits(0)), 0).into())?;
        socket.connect(&SocketAddr::new(*name_server, 53).into())?;
        Ok(UdpSocket::from_std(socket.into())?)
    }
}

fn build_udp_socket(index_port: &DownstreamIndexPort) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    set_downstream_sockopts(&socket, index_port.if_index)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::from_bits(0)), index_port.port).into())?;
    Ok(UdpSocket::from_std(socket.into())?)
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

async fn resolve_and_send_udp(socket: UdpSocket, query: UdpDnsQuery) -> Result<()> {
    // TODO (b:379992903): randomize DNS ID.
    let query_dns_id = query.query_packet.header().id;
    socket.send(query.query_packet.as_bytes()).await?;

    // Properly supporting EDNS(0) requires query parsing. Instead, use MSG_PEEK|MSG_TRUNC to
    // figure out the size of the incoming packet before reading it.
    socket.readable().await?;
    let size = recv(socket.as_raw_fd(), &mut [], MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC)?;
    let mut buf = vec![0u8; size];
    socket.recv(&mut buf).await?;

    let response = DnsPacket::try_from(buf)?;
    if response.header().id != query_dns_id {
        return Err(Error::DnsResponseMismatch);
    }
    if let Some(resp_socket) = query.resp_socket.upgrade() {
        resp_socket.send_to(response.as_bytes(), query.client_addr).await?;
    }
    Ok(())
}

/// Create downstream UDP socket that sends `UdpDnsQuery` through |query_tx|.
fn spawn_downstream_udp_socket(
    weak_command_tx: mpsc::WeakSender<Command>,
    socket: Arc<UdpSocket>,
    index_port: DownstreamIndexPort,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let mut buf = [0u8; 0xffff];
        loop {
            let (packet_size, client_addr) = socket.recv_from(&mut buf).await?;
            if let Ok(query_packet) = DnsPacket::try_from(buf[0..packet_size].to_vec()) {
                let command_tx = match weak_command_tx.upgrade() {
                    Some(t) => t,
                    None => return Err(Error::ServerStopped),
                };

                let _ = command_tx
                    .send(Command::ForwardUdpQuery(UdpDnsQuery::new(
                        query_packet,
                        index_port,
                        client_addr,
                        Arc::downgrade(&socket),
                    )))
                    .await;
            }
        }
    })
}
