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

use crate::dns_proxy::server::NetContextClient;
use crate::dns_proxy::server::Server;
use crate::dns_proxy::server::UpstreamParam;
// TODO: import server2::Server directly once legacy implementation is removed.
use crate::dns_proxy::server2;
use crate::dns_proxy::server2::{NetworkContext, UpstreamConfig};
use cxx::UniquePtr;
use static_assertions::assert_impl_all;
use std::net::{IpAddr, UdpSocket};

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
        /// Returns the vector of IP addresses literals (e.g.: {"8.8.8.8"})
        /// return value wrapped in UniquePtr since rust cannot obtain a C++ vector by value.
        fn get_name_servers(
            callback: &NameServersCallback,
            net_id: u32,
        ) -> UniquePtr<CxxVector<CxxString>>;
    }
    extern "Rust" {
        type DnsProxyServer;

        /// Constructs the DNS proxy server.
        /// Returns a pointer to the DNS proxy instance.
        fn proxy_server_new(
            dns_mark_callback: UniquePtr<DnsMarkCallback>,
            name_server_callback: UniquePtr<NameServersCallback>,
        ) -> Box<DnsProxyServer>;

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

        type OpaqueServer;

        fn proxy2_server_new(
            downstream_udp_socket_fd: i32,
            get_dns_mark_cb: UniquePtr<DnsMarkCallback>,
            get_name_servers_cb: UniquePtr<NameServersCallback>,
        ) -> Box<OpaqueServer>;

        fn proxy2_server_configure_forwarding(
            self: &OpaqueServer,
            ifindex: u32,
            uid: u32,
            netid: u32,
        );

        fn proxy2_server_stop_forwarding(self: &OpaqueServer, ifindex: u32);
    }
}

// Safety: The C++ code which constructs the callback must guarantee that it can be moved between
// threads: no usage of thread-local resources.
unsafe impl Send for cpp2rust::DnsMarkCallback {}
// Safety: The C++ code which constructs the callback must guarantee that it can be concurrently
// referenced from different threads.
// TODO: can this be removed once legacy implementation is removed?
unsafe impl Sync for cpp2rust::DnsMarkCallback {}
// Safety: The C++ code which constructs the callback must guarantee that it can be moved between
// threads: no usage of thread-local resources.
unsafe impl Send for cpp2rust::NameServersCallback {}
// Safety: The C++ code which constructs the callback must guarantee that it can be concurrently
// referenced from different threads.
// TODO: can this be removed once legacy implementation is removed?
unsafe impl Sync for cpp2rust::NameServersCallback {}

struct AndroidNetContextClient {
    dns_mark_callback: UniquePtr<cpp2rust::DnsMarkCallback>,
    name_servers_callback: UniquePtr<cpp2rust::NameServersCallback>,
}

impl AndroidNetContextClient {
    fn new(
        dns_mark_callback: UniquePtr<cpp2rust::DnsMarkCallback>,
        name_servers_callback: UniquePtr<cpp2rust::NameServersCallback>,
    ) -> Self {
        Self { dns_mark_callback, name_servers_callback }
    }
}

// Manual Debug implementation required for ContextClient trait.
impl std::fmt::Debug for AndroidNetContextClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidNetContextClient").finish()
    }
}

impl NetContextClient for AndroidNetContextClient {
    fn get_dns_mark(&self, upstream_param: &UpstreamParam) -> u32 {
        let callback = self.dns_mark_callback.as_ref().expect("DNS mark callback pointer is null");
        cpp2rust::get_dns_mark(callback, upstream_param.upstream_net_id, upstream_param.uid)
    }

    fn get_name_servers(&self, upstream_param: &UpstreamParam) -> Vec<IpAddr> {
        let callback =
            self.name_servers_callback.as_ref().expect("Name server callback pointer is null");
        cpp2rust::get_name_servers(callback, upstream_param.upstream_net_id)
            .into_iter()
            .map(|ns| {
                ns.to_string_lossy()
                    .into_owned()
                    .parse::<IpAddr>()
                    .expect("Name server address parse fail")
            })
            .collect()
    }
}

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

type DnsProxyServer = Server; // Opaque type required for FFI.

fn proxy_server_new(
    net_context_callback: UniquePtr<cpp2rust::DnsMarkCallback>,
    name_server_callback: UniquePtr<cpp2rust::NameServersCallback>,
) -> Box<DnsProxyServer> {
    assert_impl_all!(Server: Send, Sync);
    Box::new(
        Server::new(AndroidNetContextClient::new(net_context_callback, name_server_callback))
            .expect("DNS proxy start failed"),
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

type OpaqueServer = server2::Server;

fn proxy2_server_new(
    downstream_udp_socket_fd: i32,
    get_dns_mark_cb: UniquePtr<cpp2rust::DnsMarkCallback>,
    get_name_servers_cb: UniquePtr<cpp2rust::NameServersCallback>,
) -> Box<OpaqueServer> {
    assert!(downstream_udp_socket_fd >= 0);
    assert_impl_all!(server2::Server: Send, Sync);

    // Safety: The caller guarantees that downstream_udp_socket_fd is a valid socket file
    // descriptor and ownership is passed to the dns proxy.
    let socket = unsafe {
        use std::os::fd::FromRawFd as _;
        UdpSocket::from_raw_fd(downstream_udp_socket_fd)
    };
    let network_context = ResolverCallbacks { get_dns_mark_cb, get_name_servers_cb };

    // TODO: consider whether panicking on error is ok here.
    Box::new(server2::Server::new(socket, network_context).unwrap())
}

impl OpaqueServer {
    fn proxy2_server_configure_forwarding(self: &OpaqueServer, ifindex: u32, uid: u32, netid: u32) {
        // TODO: consider returning the result to the caller.
        let _ = self.configure_dns_forwarding(ifindex, uid, netid);
    }

    fn proxy2_server_stop_forwarding(self: &OpaqueServer, ifindex: u32) {
        // TODO: consider returning the result to the caller.
        let _ = self.stop_forwarding(ifindex);
    }
}
