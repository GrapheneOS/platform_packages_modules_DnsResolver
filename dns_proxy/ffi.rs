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

use log::error;

use crate::server::Server;

/// Constructs the DNS proxy server.
/// Returns a pointer to the DNS proxy instance.
#[no_mangle]
pub extern "C" fn proxy_server_new() -> *mut Server {
    match Server::new() {
        Ok(server) => Box::into_raw(Box::new(server)),
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
pub unsafe extern "C" fn proxy_server_delete(server: *mut Server) {
    // SAFETY: the caller guarantees that server was created from proxy_server_new and
    // proxy_server_delete is only called once for this instance of server.
    unsafe { Box::from_raw(server) }.stop();
}

/// Starts or updates the DNS proxy for an interface on a port.
///
/// returns 0 on success, a posix errno with a fallback to
/// DNS_PROXY_INTERNAL_ERROR on failure.
#[no_mangle]
pub extern "C" fn proxy_server_configure_dns_proxy(
    server: &Server,
    upstream_net_id: u32,
    uid: u32,
    downstream_if_index: u32,
    downstream_port: u16,
) {
    if let Err(e) =
        server.configure_dns_proxy(upstream_net_id, uid, downstream_if_index, downstream_port)
    {
        error!("Error configure DNS proxy: {}", e);
        panic!();
    }
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

    #[test]
    fn test_proxy_server_start_proxy() {
        let server = proxy_server_new();
        assert!(!server.is_null());
        // SAFETY: The caller owns the pointer passed, which is created by proxy_server_new.
        let server_ref = unsafe { server.as_ref() }.unwrap();
        proxy_server_configure_dns_proxy(
            server_ref, /*upstream_net_id*/ 1, /*uid*/ 1000,
            /*downstream_if_index*/ 1, /*downstream_port*/ 53,
        );
        // SAFETY: The caller owns the pointer passed, which is created by proxy_server_new.
        unsafe {
            proxy_server_delete(server);
        }
    }
}
