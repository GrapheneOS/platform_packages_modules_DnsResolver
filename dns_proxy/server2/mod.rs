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
use log::error;
use std::thread;
use tokio::runtime;
use tokio::sync::mpsc;

mod driver;
use driver::Driver;

pub enum Command {}

pub struct Server {
    command_tx: mpsc::Sender<Command>,
}

impl Server {
    /// Creates a server running a current thread runtime.
    pub fn new() -> Result<Server> {
        let runtime = runtime::Builder::new_current_thread().enable_all().build()?;
        let (command_tx, command_rx) = mpsc::channel::<Command>(100 /*capacity*/);
        thread::spawn(move || {
            runtime.block_on(async {
                if let Err(e) = Driver::new(command_rx).drive().await {
                    error!("Server exited due to {:?}", e);
                }
            });
        });
        Ok(Server { command_tx })
    }
}
