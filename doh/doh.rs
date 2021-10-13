/*
 * Copyright (C) 2021 The Android Open Source Project
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

//! DoH backend for the Android DnsResolver module.

use anyhow::{anyhow, bail, Context, Result};
use futures::future::{join_all, BoxFuture};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::{debug, error, info, trace, warn};
use quiche::h3;
use ring::rand::SecureRandom;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{mpsc, oneshot};
use tokio::task;
use url::Url;

pub mod boot_time;
mod config;
mod encoding;
mod ffi;

use boot_time::{timeout, BootTime, Duration};
use config::Config;

const MAX_BUFFERED_CMD_SIZE: usize = 400;
const DOH_PORT: u16 = 443;

type ValidationReporter = Box<dyn Fn(&ServerInfo, bool) -> BoxFuture<()> + Send + Sync>;
type SocketTagger = Arc<dyn Fn(&std::net::UdpSocket) -> BoxFuture<()> + Send + Sync>;

type SCID = [u8; quiche::MAX_CONN_ID_LEN];
type Base64Query = String;
type CmdSender = mpsc::Sender<DohCommand>;
type CmdReceiver = mpsc::Receiver<DohCommand>;
type QueryResponder = oneshot::Sender<Response>;
type DnsRequest = Vec<quiche::h3::Header>;

#[derive(Eq, PartialEq, Debug)]
enum QueryError {
    BrokenServer,
    ConnectionError,
    ServerNotReady,
    Unexpected,
}

#[derive(Eq, PartialEq, Debug, Clone)]
struct ServerInfo {
    net_id: u32,
    url: Url,
    peer_addr: SocketAddr,
    domain: Option<String>,
    sk_mark: u32,
    cert_path: Option<String>,
}

#[derive(Eq, PartialEq, Debug)]
enum Response {
    Error { error: QueryError },
    Success { answer: Vec<u8> },
}

#[derive(Debug)]
enum DohCommand {
    Probe { info: ServerInfo, timeout: Duration },
    Query { net_id: u32, base64_query: Base64Query, expired_time: BootTime, resp: QueryResponder },
    Clear { net_id: u32 },
    Exit,
}

#[allow(clippy::large_enum_variant)]
enum ConnectionState {
    Idle,
    Connecting {
        quic_conn: Option<Pin<Box<quiche::Connection>>>,
        udp_sk: Option<UdpSocket>,
        expired_time: Option<BootTime>,
    },
    Connected {
        quic_conn: Pin<Box<quiche::Connection>>,
        udp_sk: UdpSocket,
        h3_conn: Option<h3::Connection>,
        query_map: HashMap<u64, (Vec<u8>, QueryResponder)>,
        expired_time: Option<BootTime>,
    },
    /// Indicate that the Connection can't be used due to
    /// network or unexpected reasons.
    Error,
}

impl ConnectionState {
    fn is_connected(&self) -> bool {
        matches!(*self, Self::Connected { .. })
    }
    fn is_error(&self) -> bool {
        matches!(*self, Self::Error)
    }
}

enum H3Result {
    Data { data: Vec<u8> },
    Finished,
    Ignore,
}

/// Context for a running DoH engine.
pub struct DohDispatcher {
    /// Used to submit cmds to the I/O task.
    cmd_sender: CmdSender,
    join_handle: task::JoinHandle<Result<()>>,
    runtime: Runtime,
}

// DoH dispatcher
impl DohDispatcher {
    fn new(validation: ValidationReporter, tag_socket: SocketTagger) -> Result<DohDispatcher> {
        let (cmd_sender, cmd_receiver) = mpsc::channel::<DohCommand>(MAX_BUFFERED_CMD_SIZE);
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("doh-handler")
            .build()
            .expect("Failed to create tokio runtime");
        let join_handle = runtime.spawn(doh_handler(cmd_receiver, validation, tag_socket));
        Ok(DohDispatcher { cmd_sender, join_handle, runtime })
    }

    fn send_cmd(&self, cmd: DohCommand) -> Result<()> {
        self.cmd_sender.blocking_send(cmd)?;
        Ok(())
    }

    fn exit_handler(&mut self) {
        if self.cmd_sender.blocking_send(DohCommand::Exit).is_err() {
            return;
        }
        let _ = self.runtime.block_on(&mut self.join_handle);
    }
}

struct DohConnection {
    info: ServerInfo,
    config: Config,
    scid: SCID,
    state: ConnectionState,
    pending_queries: Vec<(DnsRequest, QueryResponder, BootTime)>,
    cached_session: Option<Vec<u8>>,
    tag_socket: SocketTagger,
}

impl DohConnection {
    fn new(info: &ServerInfo, config: Config, tag_socket: SocketTagger) -> Result<DohConnection> {
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new().fill(&mut scid).context("failed to generate scid")?;
        Ok(DohConnection {
            info: info.clone(),
            config,
            scid,
            state: ConnectionState::Idle,
            pending_queries: Vec::new(),
            cached_session: None,
            tag_socket,
        })
    }

    async fn state_to_connecting(&mut self) -> Result<()> {
        if self.state.is_error() {
            self.state_to_idle();
        }
        self.state = match self.state {
            ConnectionState::Idle => {
                let udp_sk_std = make_doh_udp_socket(self.info.peer_addr, self.info.sk_mark)?;
                (self.tag_socket)(&udp_sk_std).await;
                let udp_sk = UdpSocket::from_std(udp_sk_std)?;
                let connid = quiche::ConnectionId::from_ref(&self.scid);
                debug!("init the connection for Network {}", self.info.net_id);
                let mut quic_conn = quiche::connect(
                    self.info.domain.as_deref(),
                    &connid,
                    self.info.peer_addr,
                    &mut self.config.take(),
                )?;
                if let Some(session) = &self.cached_session {
                    if quic_conn.set_session(session).is_err() {
                        warn!("can't restore session for network {}", self.info.net_id);
                    }
                }
                ConnectionState::Connecting {
                    quic_conn: Some(quic_conn),
                    udp_sk: Some(udp_sk),
                    expired_time: None,
                }
            }
            ConnectionState::Error => panic!("state_to_idle did not transition"),
            ConnectionState::Connecting { .. } => return Ok(()),
            ConnectionState::Connected { .. } => {
                panic!("Invalid state transition to Connecting state!")
            }
        };
        Ok(())
    }

    fn state_to_connected(&mut self) -> Result<()> {
        self.state = match &mut self.state {
            // Only Connecting -> Connected is valid.
            ConnectionState::Connecting { quic_conn, udp_sk, .. } => {
                if let (Some(mut quic_conn), Some(udp_sk)) = (quic_conn.take(), udp_sk.take()) {
                    let h3_config = h3::Config::new()?;
                    let h3_conn =
                        quiche::h3::Connection::with_transport(&mut quic_conn, &h3_config)?;
                    ConnectionState::Connected {
                        quic_conn,
                        udp_sk,
                        h3_conn: Some(h3_conn),
                        query_map: HashMap::new(),
                        expired_time: None,
                    }
                } else {
                    bail!("state transition fail!");
                }
            }
            // The rest should fail.
            _ => panic!("Invalid state transition to Connected state!"),
        };
        Ok(())
    }

    fn state_to_idle(&mut self) {
        self.state = match self.state {
            // Only either Connected or Error -> Idle is valid.
            // TODO: Error -> Idle is the re-probing case, add the relevant statistic.
            ConnectionState::Connected { .. } | ConnectionState::Error => ConnectionState::Idle,
            // The rest should fail.
            _ => panic!("Invalid state transition to Idle state!"),
        }
    }

    fn state_to_error(&mut self) {
        self.pending_queries.clear();
        self.state = ConnectionState::Error
    }

    fn is_reprobe_required(&self) -> bool {
        matches!(self.state, ConnectionState::Error)
    }

    fn has_not_handled_queries(&self) -> bool {
        match &self.state {
            ConnectionState::Connecting { .. } | ConnectionState::Idle => {
                !self.pending_queries.is_empty()
            }
            ConnectionState::Connected { query_map, .. } => {
                !query_map.is_empty() || !self.pending_queries.is_empty()
            }
            _ => false,
        }
    }

    fn handle_if_connection_expired(&mut self) {
        let expired_time = match &mut self.state {
            ConnectionState::Connecting { expired_time, .. } => expired_time,
            ConnectionState::Connected { expired_time, .. } => expired_time,
            // ignore
            _ => return,
        };

        if let Some(expired_time) = expired_time {
            if let Some(elapsed) = BootTime::now().checked_duration_since(*expired_time) {
                warn!(
                    "Change the state to Idle due to connection timeout, {:?}, {}",
                    elapsed, self.info.net_id
                );
                self.state_to_idle();
            }
        }
    }

    async fn probe(&mut self, t: Duration) -> Result<()> {
        match timeout(t, async {
            self.try_connect().await?;
            info!("probe start for {}", self.info.net_id);
            if let ConnectionState::Connected { quic_conn, udp_sk, h3_conn, expired_time, .. } =
                &mut self.state
            {
                let h3_conn = h3_conn.as_mut().ok_or_else(|| anyhow!("h3 conn isn't available"))?;
                let req = match encoding::probe_query() {
                    Ok(q) => match encoding::dns_request(&q, &self.info.url) {
                        Ok(req) => req,
                        Err(e) => bail!(e),
                    },
                    Err(e) => bail!(e),
                };
                // Send the probe query.
                let req_id = h3_conn.send_request(quic_conn, &req, true /*fin*/)?;
                loop {
                    flush_tx(quic_conn, udp_sk).await?;
                    recv_rx(quic_conn, udp_sk, expired_time).await?;
                    loop {
                        match recv_h3(quic_conn, h3_conn) {
                            Ok((stream_id, H3Result::Finished)) => {
                                if stream_id == req_id {
                                    return Ok(());
                                }
                            }
                            // TODO: Verify the answer
                            Ok((_stream_id, H3Result::Data { .. })) => {}
                            Ok((_stream_id, H3Result::Ignore)) => {}
                            Err(_) => break,
                        }
                    }
                }
            } else {
                bail!("state error while performing probe()");
            }
        })
        .await
        {
            Ok(v) => match v {
                Ok(_) => Ok(()),
                Err(e) => {
                    self.state_to_error();
                    bail!(e);
                }
            },
            Err(e) => {
                self.state_to_error();
                bail!(e);
            }
        }
    }

    async fn try_connect(&mut self) -> Result<()> {
        if matches!(self.state, ConnectionState::Connected { .. }) {
            return Ok(());
        }
        self.state_to_connecting().await?;
        debug!("connecting to Network {}", self.info.net_id);

        let (quic_conn, udp_sk, expired_time) = match &mut self.state {
            ConnectionState::Connecting { quic_conn, udp_sk, expired_time, .. } => {
                if let (Some(quic_conn), Some(udp_sk)) = (quic_conn.as_mut(), udp_sk.as_mut()) {
                    (quic_conn, udp_sk, expired_time)
                } else {
                    bail!("unexpected error while performing connect()");
                }
            }
            _ => bail!("state error while performing try_connect()"),
        };

        while !quic_conn.is_established() {
            flush_tx(quic_conn, udp_sk).await?;
            recv_rx(quic_conn, udp_sk, expired_time).await?;
        }
        self.cached_session = quic_conn.session();
        self.state_to_connected()?;
        info!("connected to Network {}", self.info.net_id);
        Ok(())
    }

    async fn try_send_doh_query(
        &mut self,
        req: DnsRequest,
        resp: QueryResponder,
        expired_time: BootTime,
    ) -> Result<()> {
        self.handle_if_connection_expired();
        match &mut self.state {
            ConnectionState::Connected { quic_conn, udp_sk, h3_conn, query_map, .. } => {
                let h3_conn = h3_conn.as_mut().ok_or_else(|| anyhow!("h3 conn isn't available"))?;
                send_dns_query(
                    quic_conn,
                    udp_sk,
                    h3_conn,
                    query_map,
                    &mut self.pending_queries,
                    resp,
                    expired_time,
                    req,
                )
                .await?
            }
            ConnectionState::Connecting { .. } | ConnectionState::Idle => {
                self.pending_queries.push((req, resp, expired_time))
            }
            ConnectionState::Error => {
                error!(
                    "state is error while performing try_send_doh_query(), network: {}",
                    self.info.net_id
                );
                let _ = resp.send(Response::Error { error: QueryError::BrokenServer });
            }
        }
        Ok(())
    }

    async fn process_queries(&mut self) -> Result<()> {
        debug!("process_queries entry, Network {}", self.info.net_id);
        self.try_connect().await?;
        if let ConnectionState::Connected { quic_conn, udp_sk, h3_conn, query_map, expired_time } =
            &mut self.state
        {
            let h3_conn = h3_conn.as_mut().ok_or_else(|| anyhow!("h3 conn isn't available"))?;
            loop {
                while !self.pending_queries.is_empty() {
                    if let Some((req, resp, exp_time)) = self.pending_queries.pop() {
                        // Ignore the expired queries.
                        if BootTime::now().checked_duration_since(exp_time).is_some() {
                            warn!("Drop the obsolete query for network {}", self.info.net_id);
                            continue;
                        }
                        send_dns_query(
                            quic_conn,
                            udp_sk,
                            h3_conn,
                            query_map,
                            &mut self.pending_queries,
                            resp,
                            exp_time,
                            req,
                        )
                        .await?;
                    }
                }
                flush_tx(quic_conn, udp_sk).await?;
                recv_rx(quic_conn, udp_sk, expired_time).await?;
                loop {
                    match recv_h3(quic_conn, h3_conn) {
                        Ok((stream_id, H3Result::Data { mut data })) => {
                            if let Some((answer, _)) = query_map.get_mut(&stream_id) {
                                answer.append(&mut data);
                            } else {
                                // Should not happen
                                warn!("No associated receiver found while receiving Data, Network {}, stream id: {}", self.info.net_id, stream_id);
                            }
                        }
                        Ok((stream_id, H3Result::Finished)) => {
                            if let Some((answer, resp)) = query_map.remove(&stream_id) {
                                debug!(
                                    "sending answer back to resolv, Network {}, stream id: {}",
                                    self.info.net_id, stream_id
                                );
                                resp.send(Response::Success { answer }).unwrap_or_else(|e| {
                                    trace!(
                                        "the receiver dropped {:?}, stream id: {}",
                                        e,
                                        stream_id
                                    );
                                });
                            } else {
                                // Should not happen
                                warn!("No associated receiver found while receiving Finished, Network {}, stream id: {}", self.info.net_id, stream_id);
                            }
                        }
                        Ok((_stream_id, H3Result::Ignore)) => {}
                        Err(_) => break,
                    }
                }
                if quic_conn.is_closed() || !quic_conn.is_established() {
                    self.state_to_idle();
                    bail!("connection become idle");
                }
            }
        } else {
            self.state_to_error();
            bail!("state error while performing process_queries(), network: {}", self.info.net_id);
        }
    }
}

fn recv_h3(
    quic_conn: &mut Pin<Box<quiche::Connection>>,
    h3_conn: &mut h3::Connection,
) -> Result<(u64, H3Result)> {
    match h3_conn.poll(quic_conn) {
        // Process HTTP/3 events.
        Ok((stream_id, quiche::h3::Event::Data)) => {
            debug!("quiche::h3::Event::Data");
            let mut buf = vec![0; config::MAX_DATAGRAM_SIZE];
            match h3_conn.recv_body(quic_conn, stream_id, &mut buf) {
                Ok(read) => {
                    trace!(
                        "got {} bytes of response data on stream {}: {:x?}",
                        read,
                        stream_id,
                        &buf[..read]
                    );
                    buf.truncate(read);
                    Ok((stream_id, H3Result::Data { data: buf }))
                }
                Err(e) => {
                    warn!("recv_h3::recv_body {:?}", e);
                    bail!(e);
                }
            }
        }
        Ok((stream_id, quiche::h3::Event::Headers { list, has_body })) => {
            trace!(
                "got response headers {:?} on stream id {} has_body {}",
                list,
                stream_id,
                has_body
            );
            Ok((stream_id, H3Result::Ignore))
        }
        Ok((stream_id, quiche::h3::Event::Finished)) => {
            debug!("quiche::h3::Event::Finished on stream id {}", stream_id);
            Ok((stream_id, H3Result::Finished))
        }
        Ok((stream_id, quiche::h3::Event::Datagram)) => {
            debug!("quiche::h3::Event::Datagram on stream id {}", stream_id);
            Ok((stream_id, H3Result::Ignore))
        }
        // TODO: Check if it's necessary to handle GoAway event.
        Ok((stream_id, quiche::h3::Event::GoAway)) => {
            debug!("quiche::h3::Event::GoAway on stream id {}", stream_id);
            Ok((stream_id, H3Result::Ignore))
        }
        Err(e) => {
            debug!("recv_h3 {:?}", e);
            bail!(e);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_dns_query(
    quic_conn: &mut Pin<Box<quiche::Connection>>,
    udp_sk: &mut UdpSocket,
    h3_conn: &mut h3::Connection,
    query_map: &mut HashMap<u64, (Vec<u8>, QueryResponder)>,
    pending_queries: &mut Vec<(DnsRequest, QueryResponder, BootTime)>,
    resp: QueryResponder,
    expired_time: BootTime,
    req: DnsRequest,
) -> Result<()> {
    if !quic_conn.is_established() {
        bail!("quic connection is not ready");
    }
    match h3_conn.send_request(quic_conn, &req, true /*fin*/) {
        Ok(stream_id) => {
            query_map.insert(stream_id, (Vec::new(), resp));
            flush_tx(quic_conn, udp_sk).await?;
            debug!("send dns query successfully stream id: {}", stream_id);
            Ok(())
        }
        Err(quiche::h3::Error::StreamBlocked) => {
            warn!("try to send query but error on StreamBlocked");
            pending_queries.push((req, resp, expired_time));
            Ok(())
        }
        Err(e) => {
            resp.send(Response::Error { error: QueryError::ConnectionError }).ok();
            bail!(e);
        }
    }
}

async fn recv_rx(
    quic_conn: &mut Pin<Box<quiche::Connection>>,
    udp_sk: &mut UdpSocket,
    expired_time: &mut Option<BootTime>,
) -> Result<()> {
    // TODO: Evaluate if we could make the buffer smaller.
    let mut buf = [0; 65535];
    let quic_idle_timeout_ms = Duration::from_millis(config::QUICHE_IDLE_TIMEOUT_MS);
    let ts = quic_conn.timeout().unwrap_or(quic_idle_timeout_ms);

    if let Some(next_expired) = BootTime::now().checked_add(quic_idle_timeout_ms) {
        expired_time.replace(next_expired);
    } else {
        expired_time.take();
    }
    debug!("recv_rx entry next timeout {:?} {:?}", ts, expired_time);
    match timeout(ts, udp_sk.recv_from(&mut buf)).await {
        Ok(v) => match v {
            Ok((size, from)) => {
                let recv_info = quiche::RecvInfo { from };
                let processed = match quic_conn.recv(&mut buf[..size], recv_info) {
                    Ok(l) => l,
                    Err(e) => {
                        debug!("recv_rx error {:?}", e);
                        bail!("quic recv failed: {:?}", e);
                    }
                };
                debug!("processed {} bytes", processed);
                Ok(())
            }
            Err(e) => bail!("socket recv failed: {:?}", e),
        },
        Err(_) => {
            warn!("timeout did not receive value within {:?}", ts);
            quic_conn.on_timeout();
            Ok(())
        }
    }
}

async fn flush_tx(
    quic_conn: &mut Pin<Box<quiche::Connection>>,
    udp_sk: &mut UdpSocket,
) -> Result<()> {
    let mut out = [0; config::MAX_DATAGRAM_SIZE];
    loop {
        let (write, _) = match quic_conn.send(&mut out) {
            Ok(v) => v,
            Err(quiche::Error::Done) => {
                debug!("done writing");
                break;
            }
            Err(e) => {
                quic_conn.close(false, 0x1, b"fail").ok();
                bail!(e);
            }
        };
        udp_sk.send(&out[..write]).await?;
        debug!("written {}", write);
    }
    Ok(())
}

async fn handle_probe_result(
    result: (ServerInfo, Result<DohConnection, (anyhow::Error, DohConnection)>),
    doh_conn_map: &mut HashMap<u32, (ServerInfo, Option<DohConnection>)>,
    validation: &ValidationReporter,
) {
    let (info, doh_conn) = match result {
        (info, Ok(doh_conn)) => {
            info!("probing_task success on net_id: {}", info.net_id);
            (info, doh_conn)
        }
        (info, Err((e, doh_conn))) => {
            error!("probe failed on network {}, {:?}", e, info.net_id);
            (info, doh_conn)
            // TODO: Retry probe?
        }
    };
    // If the network is removed or the server is replaced before probing,
    // ignore the probe result.
    match doh_conn_map.get(&info.net_id) {
        Some((server_info, _)) => {
            if *server_info != info {
                warn!(
                    "The previous configuration for network {} was replaced before probe finished",
                    info.net_id
                );
                return;
            }
        }
        _ => {
            warn!("network {} was removed before probe finished", info.net_id);
            return;
        }
    }
    validation(&info, doh_conn.state.is_connected()).await;
    doh_conn_map.insert(info.net_id, (info, Some(doh_conn)));
}

async fn probe_task(
    info: ServerInfo,
    mut doh: DohConnection,
    t: Duration,
) -> (ServerInfo, Result<DohConnection, (anyhow::Error, DohConnection)>) {
    match doh.probe(t).await {
        Ok(_) => (info, Ok(doh)),
        Err(e) => (info, Err((anyhow!(e), doh))),
    }
}

fn make_connection_if_needed(
    info: &ServerInfo,
    doh_conn_map: &mut HashMap<u32, (ServerInfo, Option<DohConnection>)>,
    config_cache: &config::Cache,
    tag_socket: SocketTagger,
) -> Result<Option<DohConnection>> {
    // Check if connection exists.
    match doh_conn_map.get(&info.net_id) {
        // The connection exists but has failed. Re-probe.
        Some((server_info, Some(doh))) if *server_info == *info && doh.is_reprobe_required() => {
            let (_, doh) = doh_conn_map
                .insert(info.net_id, (info.clone(), None))
                .ok_or_else(|| anyhow!("unexpected error, missing connection"))?;
            return Ok(doh);
        }
        // The connection exists or the connection is under probing, ignore.
        Some((server_info, _)) if *server_info == *info => return Ok(None),
        // TODO: change the inner connection instead of removing?
        _ => doh_conn_map.remove(&info.net_id),
    };
    let config = config_cache.from_cert_path(&info.cert_path)?;
    let doh = DohConnection::new(info, config, tag_socket)?;
    doh_conn_map.insert(info.net_id, (info.clone(), None));
    Ok(Some(doh))
}

async fn handle_query_cmd(
    net_id: u32,
    base64_query: Base64Query,
    expired_time: BootTime,
    resp: QueryResponder,
    doh_conn_map: &mut HashMap<u32, (ServerInfo, Option<DohConnection>)>,
) {
    if let Some((info, quic_conn)) = doh_conn_map.get_mut(&net_id) {
        match (&info.domain, quic_conn) {
            // Connection is not ready, strict mode
            (Some(_), None) => {
                let _ = resp.send(Response::Error { error: QueryError::ServerNotReady });
            }
            // Connection is not ready, Opportunistic mode
            (None, None) => {
                let _ = resp.send(Response::Error { error: QueryError::ServerNotReady });
            }
            // Connection is ready
            (_, Some(quic_conn)) => {
                if let Ok(req) = encoding::dns_request(&base64_query, &info.url) {
                    let _ = quic_conn.try_send_doh_query(req, resp, expired_time).await;
                } else {
                    let _ = resp.send(Response::Error { error: QueryError::Unexpected });
                }
            }
        }
    } else {
        error!("No connection is associated with the given net id {}", net_id);
        let _ = resp.send(Response::Error { error: QueryError::ServerNotReady });
    }
}
fn need_process_queries(doh_conn_map: &HashMap<u32, (ServerInfo, Option<DohConnection>)>) -> bool {
    if doh_conn_map.is_empty() {
        return false;
    }
    for (_, doh_conn) in doh_conn_map.values() {
        if let Some(doh_conn) = doh_conn {
            if doh_conn.has_not_handled_queries() {
                return true;
            }
        }
    }
    false
}

async fn doh_handler(
    mut cmd_rx: CmdReceiver,
    validation: ValidationReporter,
    tag_socket: SocketTagger,
) -> Result<()> {
    info!("doh_dispatcher entry");
    let config_cache = config::Cache::new();

    // Currently, only support 1 server per network.
    let mut doh_conn_map: HashMap<u32, (ServerInfo, Option<DohConnection>)> = HashMap::new();
    let mut probe_futures = FuturesUnordered::new();
    loop {
        tokio::select! {
            _ = async {
                let mut futures = vec![];
                for (_, doh_conn) in doh_conn_map.values_mut() {
                    if let Some(doh_conn) = doh_conn {
                        futures.push(doh_conn.process_queries());
                    }
                }
                join_all(futures).await
            }, if need_process_queries(&doh_conn_map) => {},
            Some(result) = probe_futures.next() => {
                handle_probe_result(result, &mut doh_conn_map, &validation).await;
                info!("probe_futures remaining size: {}", probe_futures.len());
            },
            Some(cmd) = cmd_rx.recv() => {
                trace!("recv {:?}", cmd);
                match cmd {
                    DohCommand::Probe { info, timeout: t } => {
                        match make_connection_if_needed(&info, &mut doh_conn_map, &config_cache, tag_socket.clone()) {
                            Ok(Some(doh)) => {
                                // Create a new async task associated to the DoH connection.
                                probe_futures.push(probe_task(info, doh, t));
                                debug!("probe_futures size: {}", probe_futures.len());
                            }
                            Ok(None) => {
                                // No further probe is needed.
                                warn!("connection for network {} already exists", info.net_id);
                                // TODO: Report the status again?
                            }
                            Err(e) => {
                                error!("create connection for network {} error {:?}", info.net_id, e);
                                validation(&info, false).await
                            }
                        }
                    },
                    DohCommand::Query { net_id, base64_query, expired_time, resp } => {
                        handle_query_cmd(net_id, base64_query, expired_time, resp, &mut doh_conn_map).await;
                    },
                    DohCommand::Clear { net_id } => {
                        doh_conn_map.remove(&net_id);
                        info!("Doh Clear server for netid: {}", net_id);
                        config_cache.garbage_collect();
                    },
                    DohCommand::Exit => return Ok(()),
                }
            }
        }
    }
}

fn make_doh_udp_socket(peer_addr: SocketAddr, mark: u32) -> Result<std::net::UdpSocket> {
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    let udp_sk = std::net::UdpSocket::bind(bind_addr)?;
    udp_sk.set_nonblocking(true)?;
    if mark_socket(udp_sk.as_raw_fd(), mark).is_err() {
        warn!("Mark socket failed, is it a test?");
    }
    udp_sk.connect(peer_addr)?;

    trace!("connecting to {:} from {:}", peer_addr, udp_sk.local_addr()?);
    Ok(udp_sk)
}

fn mark_socket(fd: RawFd, mark: u32) -> Result<()> {
    // libc::setsockopt is a wrapper function calling into bionic setsockopt.
    // Both fd and mark are valid, which makes the function call mostly safe.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(anyhow::Error::new(std::io::Error::last_os_error()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    const TEST_NET_ID: u32 = 50;
    const TEST_MARK: u32 = 0xD0033;
    const LOOPBACK_ADDR: &str = "127.0.0.1:443";
    const LOCALHOST_URL: &str = "https://mylocal.com/dns-query";

    // TODO: Make some tests for DohConnection.

    fn make_testing_variables(
    ) -> (ServerInfo, HashMap<u32, (ServerInfo, Option<DohConnection>)>, config::Cache, Runtime)
    {
        let test_map: HashMap<u32, (ServerInfo, Option<DohConnection>)> = HashMap::new();
        let info = ServerInfo {
            net_id: TEST_NET_ID,
            url: Url::parse(LOCALHOST_URL).unwrap(),
            peer_addr: LOOPBACK_ADDR.parse().unwrap(),
            domain: None,
            sk_mark: 0,
            cert_path: None,
        };
        let config_cache = config::Cache::new();
        let rt = Builder::new_current_thread()
            .thread_name("test-runtime")
            .enable_all()
            .build()
            .expect("Failed to create testing tokio runtime");
        (info, test_map, config_cache, rt)
    }

    fn build_socket_tagger() -> SocketTagger {
        Arc::new(|_| async {}.boxed())
    }

    #[test]
    fn make_connection_if_needed() {
        let (info, mut test_map, config_cache, rt) = make_testing_variables();
        rt.block_on(async {
            // Expect to make a new connection.
            let mut doh = super::make_connection_if_needed(
                &info,
                &mut test_map,
                &config_cache,
                build_socket_tagger(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(doh.info.net_id, info.net_id);
            assert!(matches!(doh.state, ConnectionState::Idle));
            doh.state = ConnectionState::Error;
            test_map.insert(info.net_id, (info.clone(), Some(doh)));
            // Expect that we will get a connection with fail status that we added to the map before.
            let mut doh = super::make_connection_if_needed(
                &info,
                &mut test_map,
                &config_cache,
                build_socket_tagger(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(doh.info.net_id, info.net_id);
            assert!(matches!(doh.state, ConnectionState::Error));
            doh.state = make_dummy_connected_state();
            test_map.insert(info.net_id, (info.clone(), Some(doh)));
            // Expect that we will get None because the map contains a connection with ready status.
            assert!(super::make_connection_if_needed(
                &info,
                &mut test_map,
                &config_cache,
                build_socket_tagger()
            )
            .unwrap()
            .is_none());
        });
    }

    #[test]
    fn handle_query_cmd() {
        let (info, mut test_map, config_cache, rt) = make_testing_variables();
        let t = Duration::from_millis(100);
        rt.block_on(async {
            // Test no available server cases.
            let (resp_tx, resp_rx) = oneshot::channel();
            let query = encoding::probe_query().unwrap();
            super::handle_query_cmd(
                info.net_id,
                query.clone(),
                BootTime::now().checked_add(t).unwrap(),
                resp_tx,
                &mut test_map,
            )
            .await;
            assert_eq!(
                timeout(t, resp_rx).await.unwrap().unwrap(),
                Response::Error { error: QueryError::ServerNotReady }
            );

            let (resp_tx, resp_rx) = oneshot::channel();
            test_map.insert(info.net_id, (info.clone(), None));
            super::handle_query_cmd(
                info.net_id,
                query.clone(),
                BootTime::now().checked_add(t).unwrap(),
                resp_tx,
                &mut test_map,
            )
            .await;
            assert_eq!(
                timeout(t, resp_rx).await.unwrap().unwrap(),
                Response::Error { error: QueryError::ServerNotReady }
            );

            // Test the connection broken case.
            test_map.clear();
            let (resp_tx, resp_rx) = oneshot::channel();
            let mut doh = super::make_connection_if_needed(
                &info,
                &mut test_map,
                &config_cache,
                build_socket_tagger(),
            )
            .unwrap()
            .unwrap();
            doh.state = ConnectionState::Error;
            test_map.insert(info.net_id, (info.clone(), Some(doh)));
            super::handle_query_cmd(
                info.net_id,
                query.clone(),
                BootTime::now().checked_add(t).unwrap(),
                resp_tx,
                &mut test_map,
            )
            .await;
            assert_eq!(
                timeout(t, resp_rx).await.unwrap().unwrap(),
                Response::Error { error: QueryError::BrokenServer }
            );
        });
    }

    fn make_testing_connection_variables() -> (Pin<Box<quiche::Connection>>, UdpSocket) {
        let sk = super::make_doh_udp_socket(LOOPBACK_ADDR.parse().unwrap(), TEST_MARK).unwrap();
        let udp_sk = UdpSocket::from_std(sk).unwrap();
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new().fill(&mut scid).context("failed to generate scid").unwrap();
        let connid = quiche::ConnectionId::from_ref(&scid);
        let mut config = Config::from_cert_path(None).unwrap();
        let quic_conn =
            quiche::connect(None, &connid, LOOPBACK_ADDR.parse().unwrap(), &mut config.take())
                .unwrap();
        (quic_conn, udp_sk)
    }

    fn make_dummy_connected_state() -> super::ConnectionState {
        let (quic_conn, udp_sk) = make_testing_connection_variables();
        ConnectionState::Connected {
            quic_conn,
            udp_sk,
            h3_conn: None,
            query_map: HashMap::new(),
            expired_time: None,
        }
    }

    #[test]
    fn make_doh_udp_socket() {
        // Make a socket connecting to loopback with a test mark.
        let sk = super::make_doh_udp_socket(LOOPBACK_ADDR.parse().unwrap(), TEST_MARK).unwrap();
        // Check if the socket is connected to loopback.
        assert_eq!(
            sk.peer_addr().unwrap(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), DOH_PORT))
        );

        // Check if the socket mark is correct.
        let fd: RawFd = sk.as_raw_fd();

        let mut mark: u32 = 50;
        let mut size = std::mem::size_of::<u32>() as libc::socklen_t;
        unsafe {
            // Safety: It's fine since the fd belongs to this test.
            assert_eq!(
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mut mark as *mut _ as *mut libc::c_void,
                    &mut size as *mut libc::socklen_t,
                ),
                0
            );
        }
        assert_eq!(mark, TEST_MARK);

        // Check if the socket is non-blocking.
        unsafe {
            // Safety: It's fine since the fd belongs to this test.
            assert_eq!(libc::fcntl(fd, libc::F_GETFL, 0) & libc::O_NONBLOCK, libc::O_NONBLOCK);
        }
    }
}
