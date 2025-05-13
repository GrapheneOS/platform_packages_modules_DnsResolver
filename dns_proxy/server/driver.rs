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

use std::collections::HashMap;

use log::info;
use tokio::sync::mpsc;

use super::Command;
use super::DownstreamIndexPort;
use super::Result;
use super::UpstreamParam;

pub(super) struct Driver {
    command_rx: mpsc::Receiver<Command>,
    /// Map of DownstreamIndexPort pair to the upstream parameters.
    upstream_map: HashMap<DownstreamIndexPort, UpstreamParam>,
}

impl Driver {
    pub fn new(command_rx: mpsc::Receiver<Command>) -> Self {
        Self { command_rx, upstream_map: HashMap::new() }
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
        }
    }

    fn handle_configure_dns_proxy_cmd(
        &mut self,
        index_port: DownstreamIndexPort,
        upstream_param: UpstreamParam,
    ) -> Result<()> {
        self.upstream_map.insert(index_port, upstream_param);
        Ok(())
    }
}
