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

use anyhow::Result;
use log::info;
use std::net::{IpAddr, UdpSocket};
use std::thread;
use tokio::runtime;
use tokio::sync::{mpsc, oneshot};

mod driver;
use driver::Driver;

#[derive(Debug)]
pub struct UpstreamConfig {
    pub uid: u32,
    pub netid: u32,
}

#[cfg_attr(test, mockall::automock)]
pub trait NetworkContext: Send {
    fn get_name_servers(&self, upstream: &UpstreamConfig) -> Vec<IpAddr>;
    fn get_dns_mark(&self, upstream: &UpstreamConfig) -> u32;
}

pub enum Command {
    ConfigureForwarding {
        /// The ifindex of the downstream interface.
        ifindex: u32,
        /// The upstream netid.
        netid: u32,
        /// The uid on behalf to forward.
        uid: u32,
        /// oneshot::Sender to block the calling/binder thread until the command has been processed.
        status_tx: oneshot::Sender<Result<()>>,
    },
    StopForwarding {
        ifindex: u32,
        /// oneshot::Sender to block the calling/binder thread until the command has been processed.
        status_tx: oneshot::Sender<Result<()>>,
    },
}

pub struct Server {
    command_tx: mpsc::Sender<Command>,
    join_handle: thread::JoinHandle<()>,
}

impl Server {
    /// Creates a server running a current thread runtime.
    pub fn new(
        runtime: runtime::Runtime,
        downstream_udp_socket: UdpSocket,
        network_context: impl NetworkContext + 'static,
    ) -> Result<Server> {
        let (command_tx, command_rx) = mpsc::channel::<Command>(100 /*capacity*/);
        let join_handle = thread::spawn(move || {
            runtime.block_on(async {
                if let Err(e) =
                    Driver::new(command_rx, downstream_udp_socket, network_context).drive().await
                {
                    info!("Server exited due to {e:?}");
                }
            });
        });
        Ok(Server { command_tx, join_handle })
    }

    pub fn send_command(&self, command: Command) -> Result<()> {
        self.command_tx.blocking_send(command)?;
        Ok(())
    }

    pub fn configure_dns_forwarding(&self, ifindex: u32, netid: u32, uid: u32) -> Result<()> {
        // These methods are called from a synchronous AIDL interface, so they must block the
        // calling thread until completion.
        let (status_tx, status_rx) = oneshot::channel();
        let cmd = Command::ConfigureForwarding { ifindex, netid, uid, status_tx };
        self.command_tx.blocking_send(cmd)?;
        status_rx.blocking_recv()?
    }

    pub fn stop_forwarding(&self, ifindex: u32) -> Result<()> {
        let (status_tx, status_rx) = oneshot::channel();
        let cmd = Command::StopForwarding { ifindex, status_tx };
        self.command_tx.blocking_send(cmd)?;
        status_rx.blocking_recv()?
    }

    // TODO: consider calling stop() in a Drop trait impl; however, joining threads inside drop()
    // is generally considered bad practice.
    pub fn stop(self) {
        // Dropping command_tx causes command_rx.recv() to fail and subsequently causes termination
        // of the driver.
        drop(self.command_tx);
        let _ = self.join_handle.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_stop() {
        let sock = std::net::UdpSocket::bind("[::]:0").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let server = Server::new(runtime, sock, MockNetworkContext::new()).unwrap();
        server.stop();
    }
}
