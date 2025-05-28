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

use crate::server::NetContextClient;
use crate::server::Server;
use crate::server::UpstreamParam;

#[cxx::bridge(namespace = "android::net::dns_proxy_ffi")]
#[allow(clippy::needless_maybe_sized)]
mod cpp2rust {
    extern "Rust" {
        type DnsProxyServer;

        /// Constructs the DNS proxy server.
        /// Returns a pointer to the DNS proxy instance.
        fn proxy_server_new() -> Box<DnsProxyServer>;

        /// Starts or updates the DNS proxy for an interface on a port.
        fn configure_dns_proxy_ffi(
            self: &DnsProxyServer,
            upstream_net_id: u32,
            uid: u32,
            downstream_if_index: u32,
            downstream_port: u16,
        );

        /// Stops the DNS proxy for an interface on a port.
        fn stop_dns_proxy_ffi(
            self: &DnsProxyServer,
            downstream_if_index: u32,
            downstream_port: u16,
        );
    }
}

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

type DnsProxyServer = Server; // Opaque type required for FFI.

fn proxy_server_new() -> Box<DnsProxyServer> {
    Box::new(
        Server::new(AndroidNetContextClient::new()).expect("DNS proxy server constructor failed"),
    )
}

impl DnsProxyServer {
    fn configure_dns_proxy_ffi(
        &self,
        upstream_net_id: u32,
        uid: u32,
        downstream_if_index: u32,
        downstream_port: u16,
    ) {
        self.configure_dns_proxy(upstream_net_id, uid, downstream_if_index, downstream_port)
            .expect("Configure DNS proxy failed")
    }

    fn stop_dns_proxy_ffi(&self, downstream_if_index: u32, downstream_port: u16) {
        self.stop_dns_proxy(downstream_if_index, downstream_port).expect("Stop DNS proxy failed")
    }
}
