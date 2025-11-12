// Copyright 2025 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Async socket implementations compatible with tokio.

use crate::socket::sync;
use std::io::Result;
use std::os::fd::OwnedFd;
use tokio::io::unix::AsyncFd;

pub struct UnixSeqpacket {
    inner: AsyncFd<sync::UnixSeqpacket>,
}

impl UnixSeqpacket {
    pub fn from_sync(socket: sync::UnixSeqpacket) -> Result<Self> {
        let inner = AsyncFd::new(socket)?;
        Ok(Self { inner })
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().recv(buf)) {
                Ok(result) => return result,
                // try_io's error is always EWOULDBLOCK.
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn recv_with_fd(&self, buf: &mut [u8]) -> Result<(usize, Option<OwnedFd>)> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().recv_with_fd(buf)) {
                Ok(result) => return result,
                // try_io's error is always EWOULDBLOCK.
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => return result,
                // try_io's error is always EWOULDBLOCK.
                Err(_would_block) => continue,
            }
        }
    }
}
