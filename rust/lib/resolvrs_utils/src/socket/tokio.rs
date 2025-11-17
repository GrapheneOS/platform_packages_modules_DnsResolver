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
    /// Construct a new async UnixSeqpacket from its synchronous counterpart.
    ///
    /// This method must be called in the context of a tokio runtime.
    pub fn from_sync(socket: sync::UnixSeqpacket) -> Result<Self> {
        let inner = AsyncFd::new(socket)?;
        Ok(Self { inner })
    }

    async fn readable_io<F, T>(&self, mut f: F) -> Result<T>
    where
        F: FnMut(&sync::UnixSeqpacket) -> Result<T>,
    {
        loop {
            let mut guard = self.inner.readable().await?;
            // try_io's error is always EWOULDBLOCK in which case the loop must continue.
            if let Ok(result) = guard.try_io(|inner| f(inner.get_ref())) {
                return result;
            }
        }
    }

    // TODO: consider loosening mut constraints and combining readable_io with writable_io.
    async fn writable_io<F, T>(&self, f: F) -> Result<T>
    where
        F: Fn(&sync::UnixSeqpacket) -> Result<T>,
    {
        loop {
            let mut guard = self.inner.writable().await?;
            // try_io's error is always EWOULDBLOCK in which case the loop must continue.
            if let Ok(result) = guard.try_io(|inner| f(inner.get_ref())) {
                return result;
            }
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.readable_io(|sync| sync.recv(buf)).await
    }

    pub async fn recv_with_fd(&self, buf: &mut [u8]) -> Result<(usize, Option<OwnedFd>)> {
        self.readable_io(|sync| sync.recv_with_fd(buf)).await
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        self.writable_io(|sync| sync.send(buf)).await
    }
}
