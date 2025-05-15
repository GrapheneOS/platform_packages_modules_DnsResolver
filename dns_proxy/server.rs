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

//! DNS proxy server implementation.

use std::io::Error as IoError;
use std::thread;

use thiserror::Error;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::RecvError;

mod driver;
use driver::Driver;

/// Indicates the error is not an OS error, but due to DNS proxy itself.
pub const DNS_PROXY_INTERNAL_ERRNO: i32 = 1000;

/// Error type for server
#[derive(Debug, Error)]
pub enum Error {
    /// Io Errors:
    #[error(transparent)]
    Io(#[from] IoError),
    /// Command send error:
    #[error(transparent)]
    CommandSend(#[from] SendError<Command>),
    /// Receive response error:
    #[error(transparent)]
    ReceiveResponse(#[from] RecvError),
}

/// Result type for server
pub type Result<T> = std::result::Result<T, Error>;

/// DownstreamIndexPort is the pair of interface index and port number that uniquely
/// identifies a downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct DownstreamIndexPort {
    pub if_index: u32,
    pub port: u16,
}

impl DownstreamIndexPort {
    /// Constructor.
    pub fn new(if_index: u32, port: u16) -> Self {
        Self { if_index, port }
    }
}

/// Commands for controlling Server
#[derive(Debug)]
pub(crate) enum Command {
    /// Start or update the DNS proxy on the DownstreamIndexPort pair with
    /// configuration parameters for upstream.
    ConfigureDnsProxy {
        /// The interface index and port number pair of the downstream.
        index_port: DownstreamIndexPort,
        /// The configuration parameters to be used to retrrieve net context when building upstram.
        upstream_param: UpstreamParam,
        /// Sender for the result of the command.
        response_tx: oneshot::Sender<Result<()>>,
    },
    /// Stops the DNS proxy on the DownstreamIndexPort pair.
    StopDnsProxy {
        /// The interface index and port number pair of the downstream.
        index_port: DownstreamIndexPort,
        /// Sender for the result of the command.
        response_tx: oneshot::Sender<Result<()>>,
    },
}

/// Parameters to configure upstream, which is used to retrieve net context when
/// pakcets are forwarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct UpstreamParam {
    /// The UID on behalf of which to forward packets received on this downstrem interface.
    pub uid: u32,
    /// The network ID of the upstream network for sending DNS queries.
    pub upstream_net_id: u32,
}

impl UpstreamParam {
    /// Constructor.
    pub fn new(uid: u32, upstream_net_id: u32) -> Self {
        Self { uid, upstream_net_id }
    }
}

/// Interface class for operating with DNS Proxy Server.
#[derive(Debug)]
pub struct Server {
    command_tx: mpsc::Sender<Command>,
    join_handle: thread::JoinHandle<()>,
}

impl Server {
    /// Creates a server running a current thread runtime.
    pub fn new() -> Result<Server> {
        let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;
        let (command_tx, command_rx) = mpsc::channel(100 /* capacity */);
        let join_handle = thread::spawn(move || {
            runtime.block_on(async { Driver::new(command_rx).drive().await });
        });
        Ok(Server { command_tx, join_handle })
    }

    /// Stops Server, return after the Driver stops.
    pub fn stop(self) {
        drop(self.command_tx);
        let _ = self.join_handle.join();
    }

    /// Configures the DNS proxy and blocks the calling thread until the operation completes.
    pub fn configure_dns_proxy(
        &self,
        upstream_net_id: u32,
        uid: u32,
        downstream_if_index: u32,
        downstream_port: u16,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx.blocking_send(Command::ConfigureDnsProxy {
            index_port: DownstreamIndexPort::new(downstream_if_index, downstream_port),
            upstream_param: UpstreamParam::new(uid, upstream_net_id),
            response_tx,
        })?;
        response_rx.blocking_recv()?
    }

    // Stops DNS proxy on the interface-port pair.
    pub fn stop_dns_proxy(&self, downstream_if_index: u32, downstream_port: u16) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx.blocking_send(Command::StopDnsProxy {
            index_port: DownstreamIndexPort::new(downstream_if_index, downstream_port),
            response_tx,
        })?;
        response_rx.blocking_recv()?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that the server can be created and deleted.
    #[test]
    fn server_new_delete() {
        let server = Server::new().unwrap();
        server.stop();
    }
}
