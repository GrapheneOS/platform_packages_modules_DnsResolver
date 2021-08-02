/*
 * Copyright (C) 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! DoH server frontend.

use crate::client::{ClientMap, ConnectionID, DNS_HEADER_SIZE, MAX_UDP_PAYLOAD_SIZE};
use crate::config::Config;
use crate::stats::Stats;
use anyhow::{bail, ensure, Result};
use lazy_static::lazy_static;
use log::{debug, error};
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc::channel;
use tokio::task::JoinHandle;

lazy_static! {
    static ref RUNTIME_STATIC: Arc<Runtime> = Arc::new(
        Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .thread_name("DohFrontend")
            .build()
            .expect("Failed to create tokio runtime")
    );
}

const QUICHE_IDLE_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug)]
enum Command {
    MaybeWrite { connection_id: ConnectionID },
}

/// Frontend object.
#[derive(Debug)]
pub struct DohFrontend {
    // Socket address the frontend listens to.
    listen_socket_addr: std::net::SocketAddr,

    // Socket address the backend listens to.
    backend_socket_addr: std::net::SocketAddr,

    /// The content of the certificate.
    certificate: String,

    /// The content of the private key.
    private_key: String,

    // The thread listening to frontend socket and backend socket
    // and processing the messages.
    worker_thread: Option<JoinHandle<Result<()>>>,

    // Custom runtime configuration to control the behavior of the worker thread.
    // It's shared with the worker thread.
    config: Arc<Mutex<Config>>,

    // Stores some statistic to check DohFrontend status.
    // It's shared with the worker thread.
    stats: Arc<Mutex<Stats>>,
}

/// The parameters passed to the worker thread.
struct WorkerParams {
    frontend_socket: std::net::UdpSocket,
    backend_socket: std::net::UdpSocket,
    clients: ClientMap,
    config: Arc<Mutex<Config>>,
    stats: Arc<Mutex<Stats>>,
}

impl DohFrontend {
    pub fn new(
        listen: std::net::SocketAddr,
        backend: std::net::SocketAddr,
    ) -> Result<Box<DohFrontend>> {
        let doh = Box::new(DohFrontend {
            listen_socket_addr: listen,
            backend_socket_addr: backend,
            certificate: String::new(),
            private_key: String::new(),
            worker_thread: None,
            config: Arc::new(Mutex::new(Config::new())),
            stats: Arc::new(Mutex::new(Stats::new())),
        });
        debug!("DohFrontend created: {:?}", doh);
        Ok(doh)
    }

    pub fn start(&mut self) -> Result<()> {
        ensure!(self.worker_thread.is_none(), "Worker thread has been running");
        ensure!(!self.certificate.is_empty(), "certificate is empty");
        ensure!(!self.private_key.is_empty(), "private_key is empty");

        // Doing error handling here is much simpler.
        let params = match self.init_worker_thread_params() {
            Ok(v) => v,
            Err(e) => return Err(e.context("init_worker_thread_params failed")),
        };

        self.worker_thread = Some(RUNTIME_STATIC.spawn(worker_thread(params)));
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if let Some(worker_thread) = self.worker_thread.take() {
            worker_thread.abort();
        }

        debug!("DohFrontend: stopped: {:?}", self);
        Ok(())
    }

    pub fn set_certificate(&mut self, certificate: &str) -> Result<()> {
        self.certificate = certificate.to_string();
        Ok(())
    }

    pub fn set_private_key(&mut self, private_key: &str) -> Result<()> {
        self.private_key = private_key.to_string();
        Ok(())
    }

    pub fn set_delay_queries(&self, value: i32) -> Result<()> {
        self.config.lock().unwrap().delay_queries = value;
        Ok(())
    }

    pub fn stats(&self) -> Stats {
        self.stats.lock().unwrap().clone()
    }

    pub fn stats_clear_queries(&self) -> Result<()> {
        self.stats.lock().unwrap().queries_received = 0;
        Ok(())
    }

    fn init_worker_thread_params(&self) -> Result<WorkerParams> {
        let bind_addr =
            if self.backend_socket_addr.ip().is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let backend_socket = std::net::UdpSocket::bind(bind_addr)?;
        backend_socket.connect(self.backend_socket_addr)?;
        backend_socket.set_nonblocking(true)?;

        let frontend_socket = std::net::UdpSocket::bind(self.listen_socket_addr)?;
        frontend_socket.set_nonblocking(true)?;

        let clients = ClientMap::new(create_quiche_config(
            self.certificate.to_string(),
            self.private_key.to_string(),
        )?)?;

        Ok(WorkerParams {
            frontend_socket,
            backend_socket,
            clients,
            config: self.config.clone(),
            stats: self.stats.clone(),
        })
    }
}

async fn worker_thread(params: WorkerParams) -> Result<()> {
    let backend_socket = into_tokio_udp_socket(params.backend_socket)?;
    let frontend_socket = into_tokio_udp_socket(params.frontend_socket)?;
    let config = params.config;
    let stats = params.stats;
    let (event_tx, mut event_rx) = channel::<Command>(100);
    let mut clients = params.clients;
    let mut frontend_buf = [0; 65535];
    let mut backend_buf = [0; 16384];
    let mut delay_queries_buffer: Vec<Vec<u8>> = vec![];

    debug!("frontend={:?}, backend={:?}", frontend_socket, backend_socket);

    loop {
        let timeout = clients
            .get_mut_iter()
            .filter_map(|(_, c)| c.timeout())
            .min()
            .unwrap_or_else(|| Duration::from_millis(QUICHE_IDLE_TIMEOUT_MS));

        tokio::select! {
            _ = tokio::time::sleep(timeout) => {
                debug!("timeout");
                for (_, client) in clients.get_mut_iter() {
                    // If no timeout has occurred it does nothing.
                    client.on_timeout();

                    let connection_id = client.connection_id().clone();
                    event_tx.send(Command::MaybeWrite{connection_id}).await?;
                }
            }

            Ok((len, src)) = frontend_socket.recv_from(&mut frontend_buf) => {
                debug!("Got {} bytes from {}", len, src);

                // Parse QUIC packet.
                let pkt_buf = &mut frontend_buf[..len];
                let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Failed to parse QUIC header: {:?}", e);
                        continue;
                    }
                };
                debug!("Got QUIC packet: {:?}", hdr);

                let client = match clients.get_or_create(&hdr, &src) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Failed to get the client by the hdr {:?}: {}", hdr, e);
                        continue;
                    }
                };
                debug!("Got client: {:?}", client);

                match client.handle_frontend_message(pkt_buf) {
                    Ok(v) if !v.is_empty() => {
                        delay_queries_buffer.push(v);
                        stats.lock().unwrap().queries_received += 1;
                    }
                    Err(e) => {
                        error!("Failed to process QUIC packet: {}", e);
                        continue;
                    }
                    _ => {}
                }

                if delay_queries_buffer.len() >= config.lock().unwrap().delay_queries as usize {
                    for query in delay_queries_buffer.drain(..) {
                        debug!("sending {} bytes to backend", query.len());
                        backend_socket.send(&query).await?;
                    }
                }

                let connection_id = client.connection_id().clone();
                event_tx.send(Command::MaybeWrite{connection_id}).await?;
            }

            Ok((len, src)) = backend_socket.recv_from(&mut backend_buf) => {
                debug!("Got {} bytes from {}", len, src);
                if len < DNS_HEADER_SIZE {
                    error!("Received insufficient bytes for DNS header");
                    continue;
                }

                let query_id = [backend_buf[0], backend_buf[1]];
                for (_, client) in clients.get_mut_iter() {
                    if client.is_waiting_for_query(&query_id) {
                        if let Err(e) = client.handle_backend_message(&backend_buf[..len]) {
                            error!("Failed to handle message from backend: {}", e);
                        }
                        let connection_id = client.connection_id().clone();
                        event_tx.send(Command::MaybeWrite{connection_id}).await?;

                        // It's a bug if more than one client is waiting for this query.
                        break;
                    }
                }
            }

            Some(command) = event_rx.recv() => {
                match command {
                    Command::MaybeWrite {connection_id} => {
                        if let Some(client) = clients.get_mut(&connection_id) {
                            match client.flush_egress() {
                                Ok(v) => {
                                    // The DoH engine in DnsResolver can't handle empty response.
                                    if !v.is_empty() {
                                        let addr = client.addr();
                                        debug!("Sending {} bytes to client {}", v.len(), addr);
                                        if let Err(e) = frontend_socket.send_to(&v, addr).await {
                                            error!("Failed to send packet to {:?}: {:?}", client, e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("flush_egress failed: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn create_quiche_config(certificate: String, private_key: String) -> Result<quiche::Config> {
    let mut quiche_config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

    // Use pipe as a file path for Quiche to read the certificate and the private key.
    let (rd, mut wr) = build_pipe()?;
    let handle = std::thread::spawn(move || {
        wr.write_all(certificate.as_bytes()).expect("Failed to write to pipe");
    });
    let filepath = format!("/proc/self/fd/{}", rd.as_raw_fd());
    quiche_config.load_cert_chain_from_pem_file(&filepath)?;
    handle.join().unwrap();

    let (rd, mut wr) = build_pipe()?;
    let handle = std::thread::spawn(move || {
        wr.write_all(private_key.as_bytes()).expect("Failed to write to pipe");
    });
    let filepath = format!("/proc/self/fd/{}", rd.as_raw_fd());
    quiche_config.load_priv_key_from_pem_file(&filepath)?;
    handle.join().unwrap();

    quiche_config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    quiche_config.set_max_idle_timeout(QUICHE_IDLE_TIMEOUT_MS);
    quiche_config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_SIZE);
    quiche_config.set_initial_max_data(10000000);
    quiche_config.set_initial_max_stream_data_bidi_local(1000000);
    quiche_config.set_initial_max_stream_data_bidi_remote(1000000);
    quiche_config.set_initial_max_stream_data_uni(1000000);
    quiche_config.set_initial_max_streams_bidi(100);
    quiche_config.set_initial_max_streams_uni(100);
    quiche_config.set_disable_active_migration(true);

    Ok(quiche_config)
}

fn into_tokio_udp_socket(socket: std::net::UdpSocket) -> Result<UdpSocket> {
    match UdpSocket::from_std(socket) {
        Ok(v) => Ok(v),
        Err(e) => {
            error!("into_tokio_udp_socket failed: {}", e);
            bail!("into_tokio_udp_socket failed: {}", e)
        }
    }
}

fn build_pipe() -> Result<(File, File)> {
    let mut fds = [0, 0];
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) == 0 {
            return Ok((File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])));
        }
    }
    Err(anyhow::Error::new(std::io::Error::last_os_error()).context("build_pipe failed"))
}
