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

use crate::server::NetContextClient;
use crate::server::Server;
use crate::server::UpstreamParam;

#[derive(Debug)]
struct AndroidNetContextClient;

impl AndroidNetContextClient {
    fn new() -> Self {
        Self {}
    }
}

impl NetContextClient for AndroidNetContextClient {
    fn get_dns_mark(&self, _upstream_param: &UpstreamParam) -> Option<u32> {
        todo!();
    }

    fn get_name_servers(&self, _upstream_param: &UpstreamParam) -> Vec<std::net::IpAddr> {
        todo!();
    }
}

/// Constructs the DNS proxy server.
/// Returns a pointer to the DNS proxy instance.
#[no_mangle]
pub extern "C" fn proxy_server_new() -> *mut Server {
    match Server::new(AndroidNetContextClient::new()) {
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
        error!("Error configure DNS proxy: {}", &e);
        panic!("Error configure DNS proxy: {}", e);
    }
}

/// Stops the DNS proxy for an interface on a port.
///
/// returns 0 on success, a posix errno with a fallback to
/// DNS_PROXY_INTERNAL_ERROR on failure.
#[no_mangle]
pub extern "C" fn proxy_server_stop_dns_proxy(
    server: &Server,
    downstream_if_index: u32,
    downstream_port: u16,
) {
    if let Err(e) = server.stop_dns_proxy(downstream_if_index, downstream_port) {
        error!("Error stop DNS proxy: {}", &e);
        panic!("Error stop DNS proxy: {}", e);
    }
}
