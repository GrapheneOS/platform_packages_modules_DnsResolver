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
use std::net::Ipv4Addr;
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
use rand::seq::IndexedRandom;
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
            rng: rand::rng(),
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
                    error!("Error handling UDP query: {e}");
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
                error!("Error resolving and sending UDP query: {e}");
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
        let mark = self.net_context_client.get_dns_mark(upstream_param);
        socket.set_mark(mark)?;
        // TODO(b:379992903): randomize port selection.
        let any_addr = if name_server.is_ipv4() {
            IpAddr::V4(Ipv4Addr::from_bits(0))
        } else {
            IpAddr::V6(Ipv6Addr::from_bits(0))
        };
        socket.bind(&SocketAddr::new(any_addr, 0).into())?;
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

/// UdpSocket extension trait for implementing UdpSocket functionality that is missing in
/// tokio::net::UdpSocket.
trait UdpSocketExt {
    /// A version of try_recv that accepts flags.
    ///
    /// This function is usually paired with readable(). See UdpSocket::try_recv for details.
    fn try_recv_flags(&self, buf: &mut [u8], flags: MsgFlags) -> std::io::Result<usize>;
}

impl UdpSocketExt for UdpSocket {
    fn try_recv_flags(&self, buf: &mut [u8], flags: MsgFlags) -> std::io::Result<usize> {
        // UdpSocket::try_io() is required to consume the readable readiness event of the
        // UdpSocket. See notes on "Cancel safety" in UdpSocket::readable().
        self.try_io(tokio::io::Interest::READABLE, || {
            let fd = self.as_raw_fd();
            recv(fd, buf, flags).map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))
        })
    }
}

/// Receives an arbitrarily-sized UDP packet into an appropriately sized buffer and returns it.
///
/// Note that this function does not currently return DnsPacket directly as DnsPacket::try_from()
/// errors are handled differently (i.e. they are ignored) from recv errors.
async fn udp_recv(socket: &UdpSocket) -> Result<(Vec<u8>, SocketAddr)> {
    // Properly supporting EDNS(0) requires query parsing. Instead, use MSG_PEEK|MSG_TRUNC to
    // figure out the size of the incoming packet before reading it.
    // Note that there is no async version of recv() that allows passing in flags in
    // tokio::net::UdpSocket.
    // TODO: move this code into a socket wrapper struct.
    let len = loop {
        // It is possible for readable().await? to return but for the arriving packet to fail
        // checksum validation. As without checksum offload, validation happens only when recv() is
        // called (usually while the packet is being copied from the skb to the user buffer). If
        // this happens, recv() returns POSIX error EAGAIN, equivalent to io::ErrorKind::WouldBlock.
        socket.readable().await?;
        match socket.try_recv_flags(&mut [], MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC) {
            Ok(len) => break len,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    };
    let mut buf = vec![0u8; len];
    // At this point, try_recv_from() is guaranteed to pass checksum validation, as it has already
    // been performed by recv() above.
    // TODO: consider logging (or dropping the packet) if the actual size did not match size.
    let (_, from) = socket.try_recv_from(&mut buf)?;
    Ok((buf, from))
}

async fn resolve_and_send_udp(socket: UdpSocket, query: UdpDnsQuery) -> Result<()> {
    // TODO: b/379992903 - Randomize DNS ID.
    let query_dns_id = query.query_packet.header().id;
    socket.send(query.query_packet.as_bytes()).await?;

    let (buf, _) = udp_recv(&socket).await?;
    // TODO: b/430720622 - If try_from() or the subsequent ID comparison fails, udp_recv() should be
    // called again until the packet is received or some timeout occurs.
    // Alternatively, consider responding with a ServFail.
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
        loop {
            let (buf, client_addr) = udp_recv(&socket).await?;
            let query_packet = match DnsPacket::try_from(buf) {
                Ok(query_packet) => query_packet,
                // The received packet is not a DnsPacket. Continue.
                Err(_) => continue,
            };

            let command_tx = match weak_command_tx.upgrade() {
                Some(t) => t,
                None => return Err(Error::ServerStopped),
            };

            let resp_socket = Arc::downgrade(&socket);
            let query = UdpDnsQuery { query_packet, index_port, client_addr, resp_socket };

            // If command_tx.send() fails, it means that the receiver half has been closed (i.e.
            // the server is being stopped)..
            command_tx.send(Command::ForwardUdpQuery(query)).await?;
        }
    })
}
