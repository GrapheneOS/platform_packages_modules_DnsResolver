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
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct Driver {
    command_rx: mpsc::Receiver<Command>,
    downstream_udp_socket: UdpSocket,
}

impl Driver {
    pub fn new(command_rx: mpsc::Receiver<Command>, udp_socket: std::net::UdpSocket) -> Self {
        let _ = udp_socket.set_nonblocking(true);
        // Conversion from std::net::UdpSocket to tokio::net::UdpSocket is not expected to fail.
        let downstream_udp_socket = UdpSocket::from_std(udp_socket).unwrap();
        Self { command_rx, downstream_udp_socket }
    }

    pub async fn drive(mut self) -> Result<()> {
        loop {
            self.drive_once().await?
        }
    }

    async fn drive_once(&mut self) -> Result<()> {
        if let Some(_command) = self.command_rx.recv().await {
            todo!();
        } else {
            bail!("Death due command_tx dying.")
        }
    }
}
