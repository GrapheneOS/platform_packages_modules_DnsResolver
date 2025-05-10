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

//! DNS Proxy C FFI .

use std::ptr;
use std::sync::Mutex;

use log::error;

use crate::server::Server;

pub struct ServerDispatcher(Mutex<Server>);

/// Constructs the DNS proxy server.
/// Returns a pointer to the DNS proxy instance.
#[no_mangle]
pub extern "C" fn proxy_server_new() -> *mut ServerDispatcher {
    match Server::new() {
        Ok(server) => Box::into_raw(Box::new(ServerDispatcher(Mutex::new(server)))),
        Err(e) => {
            error!("proxy_server_new failed: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Deletes the DNS proxy server instance created by proxy_server_new.
///
/// # Safety
/// |server| must be a non-null pointer previously created by proxy_server_new
/// and not yet deleted by proxy_server_delete.
#[no_mangle]
pub unsafe extern "C" fn proxy_server_delete(server: *mut ServerDispatcher) {
    // SAFETY: the caller guarantees that server was created from proxy_server_new and
    // proxy_server_delete is only called once for this instance of server.
    unsafe { Box::from_raw(server) }.0.into_inner().unwrap().stop();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_server_new_delete() {
        let server = proxy_server_new();
        assert!(!server.is_null());
        // SAFETY: The caller owns the pointer passed, which is created by proxy_server_new.
        unsafe {
            proxy_server_delete(server);
        }
    }
}
