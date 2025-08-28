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

use crate::packet::DnsPacket;

use super::Command;
use anyhow::bail;
use anyhow::Result;
use nix::libc::in6_pktinfo;
use socket2::Domain;
use socket2::Socket;
use socket2::Type;
use std::collections::HashMap;
use std::net::SocketAddrV6;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

mod socket;
use socket::UdpServerSocket;

struct UpstreamConfig {
    uid: u32,
    netid: u32,
}

struct UdpQueryTask {
    packet: DnsPacket,
    upstream_socket: UdpSocket,
    /// The (remote) address of the DNS client.
    client_addr: SocketAddrV6,
    /// pktinfo containing local address and interface information.
    pktinfo: in6_pktinfo,
    downstream_socket: Arc<UdpServerSocket>,
}

impl UdpQueryTask {
    pub fn new(
        packet: DnsPacket,
        upstream_socket: UdpSocket,
        client_addr: SocketAddrV6,
        pktinfo: in6_pktinfo,
        downstream_socket: Arc<UdpServerSocket>,
    ) -> Self {
        Self { packet, upstream_socket, client_addr, pktinfo, downstream_socket }
    }

    pub fn run(self) -> JoinHandle<Result<()>> {
        // TODO: add a timeout.
        tokio::spawn(async move {
            self.upstream_socket.send(self.packet.as_bytes()).await?;

            // TODO: support receiving arbitrarily sized buffer.
            let mut buf = vec![0u8; 1500];
            let size = self.upstream_socket.recv(&mut buf).await?;
            buf.truncate(size);

            self.downstream_socket
                .send_to_with_pktinfo(&buf, self.client_addr, self.pktinfo)
                .await?;
            Ok(())
        })
    }
}

pub struct Driver {
    command_rx: mpsc::Receiver<Command>,
    downstream_udp_socket: Arc<UdpServerSocket>,
    /// Maps downstream ifindex to upstream config
    upstream_config_map: HashMap<u32, UpstreamConfig>,
}

impl Driver {
    pub fn new(command_rx: mpsc::Receiver<Command>, udp_socket: std::net::UdpSocket) -> Self {
        // panic!() if UdpServerSocket cannot be created. This should never happen.
        // TODO: consider returning Result instead.
        let downstream_udp_socket = Arc::new(UdpServerSocket::new(udp_socket).unwrap());
        let upstream_config_map = HashMap::new();
        Self { command_rx, downstream_udp_socket, upstream_config_map }
    }

    fn configure_forwarding(&mut self, ifindex: u32, uid: u32, netid: u32) -> Result<()> {
        // Insert or update the configuration for ifindex.
        self.upstream_config_map.insert(ifindex, UpstreamConfig { uid, netid });
        Ok(())
    }

    // Required because in6_pktinfo.ipi6_ifindex is not consistently defined for different
    // linux-like platforms. In particular, the Linux host vs Android variants are different for
    // some reason (i32 vs u32).
    #[allow(clippy::unnecessary_cast)]
    fn forward_udp(&self, bytes: Vec<u8>, from: SocketAddrV6, pktinfo: in6_pktinfo) {
        // Some "linux-like" architecture variants of the nix library define ipi6_ifindex as i32
        // requiring an explicit cast.
        let ifindex = pktinfo.ipi6_ifindex as u32;
        // TODO: use upstream config to fetch nameserver and mark.
        let Some(_upstream_config) = self.upstream_config_map.get(&ifindex) else {
            // If forwarding is not configured for the given downstream ifindex,
            // ignore the packet.
            log::info!("DNS forwarding is not configured for downstream ifindex {ifindex}");
            return;
        };

        let Ok(packet) = DnsPacket::try_from(bytes) else {
            // If the received packet is not a valid DnsPacket, ignore it.
            log::debug!("Dropped non-DNS packet.");
            return;
        };

        // TODO: pick name server for upstream config.
        let server = "[2001:4860:4860::8888]:53".parse::<SocketAddrV6>().unwrap();

        // Create a sync socket and convert it to tokio::net::UdpSocket later, so this method does
        // not become async. Additonally, use socket2::Socket, because std::net::UdpSocket does not
        // support setting the mark.
        let Ok(sock) = Socket::new(Domain::IPV6, Type::DGRAM.nonblocking().cloexec(), None) else {
            // Failed to open socket. Ignore packet and return.
            log::error!("Failed to open upstream socket. Dropped query.");
            return;
        };

        // TODO: set mark on upstream_socket before calling connect.
        let Ok(_) = sock.connect(&server.into()) else {
            log::error!("Failed to connect upstream socket. Dropped query.");
            return;
        };

        let upstream_socket = UdpSocket::from_std(sock.into()).unwrap();
        let downstream_socket = self.downstream_udp_socket.clone();
        let query_task =
            UdpQueryTask::new(packet, upstream_socket, from, pktinfo, downstream_socket);
        // TODO: keep track of JoinHandles and abort running tasks when the driver exits.
        query_task.run();
    }

    pub async fn drive(mut self) -> Result<()> {
        loop {
            self.drive_once().await?
        }
    }

    async fn drive_once(&mut self) -> Result<()> {
        tokio::select! {
            res = self.command_rx.recv() => {
                let command = match res {
                    Some(cmd) => cmd,
                    None => bail!("Death due command_tx dying."),
                };
                match command {
                    Command::ConfigureForwarding { ifindex, uid, netid, status_tx } => {
                        let res = self.configure_forwarding(ifindex, uid, netid);
                        // Ignore the result of the send() operation as it returns Result<(), T>
                        // and cannot be handled with `?`. However if it fails, it likely means the
                        // reader end is dead, in which case command_rx.recv() will bail on the
                        // next iteration of the loop.
                        let _ = status_tx.send(res);
                    }
                }
                Ok(())
            }
            res = self.downstream_udp_socket.recv_from_with_pktinfo() => {
                match res {
                    Ok((packet, from, pktinfo)) => self.forward_udp(packet, from, pktinfo),
                    Err(e) => log::error!("Failed to recv packet from UDP socket: {}", e),
                }

                // Do not stop driver on recv errors.
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::tests::TEST_VALID_DNS_QUERY;

    use super::*;
    use nix::libc::in6_addr;
    use std::net::{Ipv6Addr, SocketAddr};

    pub const DNS_REPLY: [u8; 42] = [
        // Header
        0x12, 0x34, // Transaction ID
        0x81, 0x80, // Flags: Standard query response, no error
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Question
        0x04, b't', b'e', b's', b't', // "test"
        0x03, b'c', b'o', b'm', // "com"
        0x00, // Null terminator
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        // Answer
        0xc0, 0x0c, // Pointer to the name in the question section
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
        0x00, 0x04, // Data length: 4
        0x08, 0x08, 0x08, 0x08, // IP Address: 8.8.8.8
    ];

    #[tokio::test]
    async fn test_driver_new() {
        let (_command_tx, command_rx) = mpsc::channel(1);
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let _driver = Driver::new(command_rx, socket);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_driver_new_panic() {
        let (_command_tx, command_rx) = mpsc::channel(1);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let _driver = Driver::new(command_rx, socket);
    }

    #[tokio::test]
    async fn test_udp_query_task() {
        let client_side_socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let server_side_socket = UdpSocket::bind("[::1]:0").await.unwrap();

        let packet = DnsPacket::try_from(TEST_VALID_DNS_QUERY.to_vec()).unwrap();
        let upstream_socket = UdpSocket::bind("[::]:0").await.unwrap();
        upstream_socket.connect(server_side_socket.local_addr().unwrap()).await.unwrap();

        let Ok(SocketAddr::V6(client_addr)) = client_side_socket.local_addr() else {
            panic!("local address is not a V6 address");
        };

        let lo_index = 1;
        let lo_addr = in6_addr { s6_addr: Ipv6Addr::LOCALHOST.octets() };
        let pktinfo = in6_pktinfo { ipi6_addr: lo_addr, ipi6_ifindex: lo_index };

        let std_socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let downstream_socket = Arc::new(UdpServerSocket::new(std_socket).unwrap());

        let task =
            UdpQueryTask::new(packet, upstream_socket, client_addr, pktinfo, downstream_socket);
        let handle = task.run();

        let mut buf = vec![0u8; 1500];
        let (size, srcaddr) = server_side_socket.recv_from(&mut buf).await.unwrap();
        buf.truncate(size);
        assert_eq!(buf, TEST_VALID_DNS_QUERY);
        server_side_socket.send_to(&DNS_REPLY, srcaddr).await.unwrap();

        let _ = handle.await.unwrap();

        let mut buf = vec![0u8; 1500];
        let size = client_side_socket.recv(&mut buf).await.unwrap();
        buf.truncate(size);

        assert_eq!(buf, DNS_REPLY);
    }
}
