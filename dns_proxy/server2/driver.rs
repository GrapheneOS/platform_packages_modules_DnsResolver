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

use super::Command;
use anyhow::bail;
use anyhow::Result;
use std::collections::HashMap;
use tokio::sync::mpsc;

mod socket;
use socket::UdpServerSocket;

struct UpstreamConfig {
    uid: u32,
    netid: u32,
}

pub struct Driver {
    command_rx: mpsc::Receiver<Command>,
    downstream_udp_socket: UdpServerSocket,
    /// Maps downstream ifindex to upstream config
    upstream_config_map: HashMap<u32, UpstreamConfig>,
}

impl Driver {
    pub fn new(command_rx: mpsc::Receiver<Command>, udp_socket: std::net::UdpSocket) -> Self {
        // panic!() if UdpServerSocket cannot be created. This should never happen.
        // TODO: consider returning Result instead.
        let downstream_udp_socket = UdpServerSocket::new(udp_socket).unwrap();
        let upstream_config_map = HashMap::new();
        Self { command_rx, downstream_udp_socket, upstream_config_map }
    }

    fn configure_forwarding(&mut self, ifindex: u32, uid: u32, netid: u32) -> Result<()> {
        // Insert or update the configuration for ifindex.
        self.upstream_config_map.insert(ifindex, UpstreamConfig { uid, netid });
        Ok(())
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
            res = self.downstream_udp_socket.recv_from_with_ifindex() => {
                match res {
                    Ok((_vec, _from, _ifindex)) => todo!(),
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
    use super::*;

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
}
