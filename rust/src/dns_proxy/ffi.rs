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

use crate::dns_proxy::server::NetworkContext;
use crate::dns_proxy::server::Server;
use crate::dns_proxy::server::UpstreamConfig;
use crate::dns_proxy::socketbroker::SocketBroker;
use cxx::UniquePtr;
use static_assertions::assert_impl_all;
use std::net::IpAddr;

#[cxx::bridge(namespace = "android::net::dns_proxy_ffi")]
#[allow(clippy::needless_maybe_sized)]
mod cpp2rust {
    unsafe extern "C++" {
        include!("rust/src/dns_proxy/net_context_client.h");

        type DnsMarkCallback;
        type NameServersCallback;

        /// Gets the DNS mark given the net_id of the DNS and uid of the requesting app.
        fn get_dns_mark(callback: &DnsMarkCallback, net_id: u32, uid: u32) -> u32;

        /// Gets the nameservers given the net_id of the DNS.
        ///
        /// Returns the vector of IP address literals (e.g.: {"8.8.8.8"})
        /// return value wrapped in UniquePtr since rust cannot obtain a C++ vector by value.
        fn get_name_servers(
            callback: &NameServersCallback,
            net_id: u32,
        ) -> UniquePtr<CxxVector<CxxString>>;
    }
    extern "Rust" {
        type OpaqueServer;

        fn ffi_proxy_server_new(
            get_dns_mark_cb: UniquePtr<DnsMarkCallback>,
            get_name_servers_cb: UniquePtr<NameServersCallback>,
        ) -> Box<OpaqueServer>;

        fn ffi_configure_forwarding(self: &OpaqueServer, ifindex: u32, netid: u32, uid: u32);
        fn ffi_stop_forwarding(self: &OpaqueServer, ifindex: u32);
    }
}

// Safety: The C++ code which constructs the callback must guarantee that it can be moved between
// threads: no usage of thread-local resources.
unsafe impl Send for cpp2rust::DnsMarkCallback {}
// Safety: The C++ code which constructs the callback must guarantee that it can be moved between
// threads: no usage of thread-local resources.
unsafe impl Send for cpp2rust::NameServersCallback {}

struct ResolverCallbacks {
    get_dns_mark_cb: UniquePtr<cpp2rust::DnsMarkCallback>,
    get_name_servers_cb: UniquePtr<cpp2rust::NameServersCallback>,
}

impl NetworkContext for ResolverCallbacks {
    fn get_dns_mark(&self, upstream: &UpstreamConfig) -> u32 {
        // TODO: move to the constructor
        let cb = self.get_dns_mark_cb.as_ref().unwrap();
        cpp2rust::get_dns_mark(cb, upstream.netid, upstream.uid)
    }

    fn get_name_servers(&self, upstream: &UpstreamConfig) -> Vec<IpAddr> {
        let cb = self.get_name_servers_cb.as_ref().unwrap();
        // Parse the resulting vector<string> and skip invalid IP address entries.
        // TODO: the result should always be valid; consider panicking if parsing fails.
        cpp2rust::get_name_servers(cb, upstream.netid)
            .into_iter()
            .filter_map(|ns| {
                // If invalid string -> skip
                ns.to_str()
                    .ok()
                    // Elif invalid IpAddr -> skip
                    .and_then(|s| s.parse::<IpAddr>().ok())
            })
            .collect()
    }
}

type OpaqueServer = Server;
assert_impl_all!(Server: Send, Sync);

fn ffi_proxy_server_new(
    get_dns_mark_cb: UniquePtr<cpp2rust::DnsMarkCallback>,
    get_name_servers_cb: UniquePtr<cpp2rust::NameServersCallback>,
) -> Box<OpaqueServer> {
    let network_context = ResolverCallbacks { get_dns_mark_cb, get_name_servers_cb };

    // TODO: consider whether panicking on error is ok here and below.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

    // Note that SocketBroker::fork_exec() blocks until the socketbroker is ready.
    let mut socketbroker = SocketBroker::fork_exec(&runtime).unwrap();

    // udp_socket is guaranteed to exist if socketbroker::fork_exec succeeded.
    let socket = socketbroker.udp_socket.take().unwrap();
    Box::new(Server::new(runtime, socket, network_context).unwrap())
}

impl OpaqueServer {
    fn ffi_configure_forwarding(self: &OpaqueServer, ifindex: u32, netid: u32, uid: u32) {
        // TODO: consider returning the result to the caller.
        let _ = self.configure_dns_forwarding(ifindex, netid, uid);
    }

    fn ffi_stop_forwarding(self: &OpaqueServer, ifindex: u32) {
        // TODO: consider returning the result to the caller.
        let _ = self.stop_forwarding(ifindex);
    }
}
