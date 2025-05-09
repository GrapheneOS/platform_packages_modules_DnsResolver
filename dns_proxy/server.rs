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

/// Interface class for operating with DNS Proxy Server.
pub struct Server {}

impl Server {
    /// Creates a server running a current thread runtime.
    pub fn new() -> Result<Server> {
        let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;
        thread::spawn(move || {
            runtime.block_on(async {
                todo!();
            });
        });
        Ok(Server {})
    }
}

/// Error type for server
#[derive(Debug, Error)]
pub enum Error {
    /// Io Errors:
    #[error(transparent)]
    IoError(#[from] IoError),
}

/// Result type for server
pub type Result<T> = std::result::Result<T, Error>;
