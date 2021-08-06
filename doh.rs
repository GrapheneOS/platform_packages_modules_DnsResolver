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
use futures::future::join_all;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use libc::{c_char, int32_t, size_t, ssize_t, uint32_t, uint64_t};
use log::{debug, error, info, trace, warn};
use quiche::h3;
use ring::rand::SecureRandom;
use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Once};
use std::{ptr, slice};
use tokio::net::UdpSocket;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{mpsc, oneshot};
use tokio::task;
use tokio::time::{timeout, Duration, Instant};
use url::Url;

static INIT: Once = Once::new();

/// The return code of doh_query means that there is no answer.
pub const RESULT_INTERNAL_ERROR: ssize_t = -1;
/// The return code of doh_query means that query can't be sent.
pub const RESULT_CAN_NOT_SEND: ssize_t = -2;
/// The return code of doh_query to indicate that the query timed out.
pub const RESULT_TIMEOUT: ssize_t = -255;
/// The error log level.
pub const LOG_LEVEL_ERROR: u32 = 0;
/// The warning log level.
pub const LOG_LEVEL_WARN: u32 = 1;
/// The info log level.
pub const LOG_LEVEL_INFO: u32 = 2;
/// The debug log level.
pub const LOG_LEVEL_DEBUG: u32 = 3;
/// The trace log level.
pub const LOG_LEVEL_TRACE: u32 = 4;

const MAX_BUFFERED_CMD_SIZE: usize = 400;
const MAX_INCOMING_BUFFER_SIZE_WHOLE: u64 = 10000000;
const MAX_INCOMING_BUFFER_SIZE_EACH: u64 = 1000000;
const MAX_CONCURRENT_STREAM_SIZE: u64 = 100;
const MAX_DATAGRAM_SIZE: usize = 1350;
const DOH_PORT: u16 = 443;
const QUICHE_IDLE_TIMEOUT_MS: u64 = 180000;
const SYSTEM_CERT_PATH: &str = "/system/etc/security/cacerts";
const NS_T_AAAA: u8 = 28;
const NS_C_IN: u8 = 1;
// Used to randomly generate query prefix and query id.
const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                         abcdefghijklmnopqrstuvwxyz\
                         0123456789";

type SCID = [u8; quiche::MAX_CONN_ID_LEN];
type Base64Query = String;
type CmdSender = mpsc::Sender<DohCommand>;
type CmdReceiver = mpsc::Receiver<DohCommand>;
type QueryResponder = oneshot::Sender<Response>;
type DnsRequest = Vec<quiche::h3::Header>;
type DnsRequestArg = [quiche::h3::Header];
type ValidationCallback =
    extern "C" fn(net_id: uint32_t, success: bool, ip_addr: *const c_char, host: *const c_char);

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
    Query { net_id: u32, base64_query: Base64Query, expired_time: Instant, resp: QueryResponder },
    Clear { net_id: u32 },
    Exit,
}

#[derive(Eq, PartialEq, Debug, Clone)]
enum ConnectionStatus {
    Idle,
    Ready,
    Pending,
    Fail,
}

trait OptionDeref<T: Deref> {
    fn as_deref(&self) -> Option<&T::Target>;
}

impl<T: Deref> OptionDeref<T> for Option<T> {
    fn as_deref(&self) -> Option<&T::Target> {
        self.as_ref().map(Deref::deref)
    }
}

#[derive(Copy, Clone, Debug)]
struct BootTime {
    d: Duration,
}

impl BootTime {
    fn now() -> BootTime {
        unsafe {
            let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t as *mut libc::timespec) != 0 {
                panic!("get boot time failed: {:?}", std::io::Error::last_os_error());
            }
            BootTime { d: Duration::new(t.tv_sec as u64, t.tv_nsec as u32) }
        }
    }

    fn elapsed(&self) -> Option<Duration> {
        BootTime::now().duration_since(*self)
    }

    fn checked_add(&self, duration: Duration) -> Option<BootTime> {
        Some(BootTime { d: self.d.checked_add(duration)? })
    }

    fn duration_since(&self, earlier: BootTime) -> Option<Duration> {
        self.d.checked_sub(earlier.d)
    }
}

/// Context for a running DoH engine.
pub struct DohDispatcher {
    /// Used to submit cmds to the I/O task.
    cmd_sender: CmdSender,
    join_handle: task::JoinHandle<Result<()>>,
    runtime: Arc<Runtime>,
}

// DoH dispatcher
impl DohDispatcher {
    fn new(validation_fn: ValidationCallback) -> Result<Box<DohDispatcher>> {
        let (cmd_sender, cmd_receiver) = mpsc::channel::<DohCommand>(MAX_BUFFERED_CMD_SIZE);
        let runtime = Arc::new(
            Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("doh-handler")
                .build()
                .expect("Failed to create tokio runtime"),
        );
        let join_handle = runtime.spawn(doh_handler(cmd_receiver, runtime.clone(), validation_fn));
        Ok(Box::new(DohDispatcher { cmd_sender, join_handle, runtime }))
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
    net_id: u32,
    scid: SCID,
    quic_conn: Pin<Box<quiche::Connection>>,
    udp_sk: UdpSocket,
    h3_conn: Option<h3::Connection>,
    status: ConnectionStatus,
    query_map: HashMap<u64, QueryResponder>,
    pending_queries: Vec<(DnsRequest, QueryResponder, Instant)>,
    cached_session: Option<Vec<u8>>,
    expired_time: Option<BootTime>,
}

impl DohConnection {
    fn new(info: &ServerInfo, config: &mut quiche::Config) -> Result<DohConnection> {
        let udp_sk_std = make_doh_udp_socket(info.peer_addr, info.sk_mark)?;
        let udp_sk = UdpSocket::from_std(udp_sk_std)?;
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new().fill(&mut scid).context("failed to generate scid")?;
        let connid = quiche::ConnectionId::from_ref(&scid);
        let quic_conn = quiche::connect(info.domain.as_deref(), &connid, info.peer_addr, config)?;

        Ok(DohConnection {
            net_id: info.net_id,
            scid,
            quic_conn,
            udp_sk,
            h3_conn: None,
            status: ConnectionStatus::Pending,
            query_map: HashMap::new(),
            pending_queries: Vec::new(),
            cached_session: None,
            expired_time: None,
        })
    }

    fn handle_if_connection_expired(&mut self) {
        if let Some(expired_time) = self.expired_time {
            if let Some(elapsed) = expired_time.elapsed() {
                warn!(
                    "Change the status to Idle due to connection timeout, {:?}, {}",
                    elapsed, self.net_id
                );
                self.quic_conn.on_timeout();
                self.status = ConnectionStatus::Idle;
            }
        }
    }

    async fn probe(&mut self, req: DnsRequest) -> Result<()> {
        self.connect().await?;
        info!("probe start for {}", self.net_id);
        // Send the probe query.
        let req_id = self.send_dns_query(&req).await?;
        loop {
            self.recv_rx().await?;
            self.flush_tx().await?;
            if let Ok((stream_id, _buf)) = self.recv_query() {
                if stream_id == req_id {
                    // TODO: Verify the answer
                    break;
                }
            }
        }
        Ok(())
    }

    async fn connect(&mut self) -> Result<()> {
        debug!("connecting to Network {}", self.net_id);
        while !self.quic_conn.is_established() {
            self.flush_tx().await?;
            self.recv_rx().await?;
        }
        self.cached_session = self.quic_conn.session();
        let h3_config = h3::Config::new()?;
        self.h3_conn =
            Some(quiche::h3::Connection::with_transport(&mut self.quic_conn, &h3_config)?);
        self.status = ConnectionStatus::Ready;
        info!("connected to Network {}", self.net_id);
        Ok(())
    }

    async fn send_dns_query(&mut self, req: &DnsRequestArg) -> Result<u64> {
        if !self.quic_conn.is_established() {
            bail!("quic connection is not ready");
        }
        let h3_conn = self.h3_conn.as_mut().ok_or_else(|| anyhow!("h3 conn isn't available"))?;
        let stream_id = h3_conn.send_request(&mut self.quic_conn, req, true /*fin*/)?;
        self.flush_tx().await?;
        debug!("send dns query successfully to Network {}, stream id: {}", self.net_id, stream_id);
        Ok(stream_id)
    }

    async fn try_send_doh_query(
        &mut self,
        req: DnsRequest,
        resp: QueryResponder,
        expired_time: Instant,
    ) -> Result<()> {
        match self.status {
            ConnectionStatus::Ready => match self.send_dns_query(&req).await {
                Ok(req_id) => {
                    self.query_map.insert(req_id, resp);
                }
                Err(e) => {
                    if let Ok(quiche::h3::Error::StreamBlocked) = e.downcast::<quiche::h3::Error>()
                    {
                        warn!("try to send query but error on StreamBlocked");
                        self.pending_queries.push((req, resp, expired_time));
                        bail!(quiche::h3::Error::StreamBlocked);
                    } else {
                        resp.send(Response::Error { error: QueryError::ConnectionError }).ok();
                    }
                }
            },
            ConnectionStatus::Pending => {
                self.pending_queries.push((req, resp, expired_time));
            }
            // Should not happen
            _ => {
                error!("Try to send query but status error {}", self.net_id);
            }
        }
        Ok(())
    }

    fn resume_connection(&mut self, quic_conn: Pin<Box<quiche::Connection>>) {
        self.quic_conn = quic_conn;
        if let Some(session) = &self.cached_session {
            if self.quic_conn.set_session(session).is_err() {
                warn!("can't restore session for network {}", self.net_id);
            }
        }
        self.status = ConnectionStatus::Pending;
        debug!("resume the connection for Network {}", self.net_id);
        // TODO: Also do a re-probe?
    }

    async fn process_queries(&mut self) -> Result<()> {
        debug!("process_queries entry, Network {}", self.net_id);
        if self.status == ConnectionStatus::Pending {
            self.connect().await?;
        }

        loop {
            while !self.pending_queries.is_empty() {
                if let Some((req, resp, exp_time)) = self.pending_queries.pop() {
                    // Ignore the expired queries.
                    if Instant::now().checked_duration_since(exp_time).is_some() {
                        warn!("Drop the obsolete query for network {}", self.net_id);
                        continue;
                    }
                    if self.try_send_doh_query(req, resp, exp_time).await.is_err() {
                        break;
                    }
                }
            }
            // TODO: clean up the expired queries.
            self.recv_rx().await?;
            self.flush_tx().await?;
            if let Ok((stream_id, buf)) = self.recv_query() {
                if let Some(resp) = self.query_map.remove(&stream_id) {
                    debug!(
                        "sending answer back to resolv, Network {}, stream id: {}",
                        self.net_id, stream_id
                    );
                    resp.send(Response::Success { answer: buf }).unwrap_or_else(|e| {
                        trace!("the receiver dropped {:?}, stream id: {}", e, stream_id);
                    });
                } else {
                    // Should not happen
                    warn!("No associated receiver found");
                }
            }
            if self.quic_conn.is_closed() || !self.quic_conn.is_established() {
                self.status = ConnectionStatus::Idle;
                bail!("connection become idle");
            }
        }
    }

    fn recv_query(&mut self) -> Result<(u64, Vec<u8>)> {
        let h3_conn = self.h3_conn.as_mut().ok_or_else(|| anyhow!("h3 conn isn't available"))?;
        loop {
            match h3_conn.poll(&mut self.quic_conn) {
                // Process HTTP/3 events.
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    debug!("quiche::h3::Event::Data");
                    let mut buf = vec![0; MAX_DATAGRAM_SIZE];
                    if let Ok(read) = h3_conn.recv_body(&mut self.quic_conn, stream_id, &mut buf) {
                        trace!(
                            "got {} bytes of response data on stream {}: {:x?}",
                            read,
                            stream_id,
                            &buf[..read]
                        );
                        buf.truncate(read);
                        return Ok((stream_id, buf));
                    }
                }
                Ok((stream_id, quiche::h3::Event::Headers { list, has_body })) => {
                    debug!(
                        "got response headers {:?} on stream id {} has_body {}",
                        list, stream_id, has_body
                    );
                }
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    debug!("quiche::h3::Event::Finished on stream id {}", stream_id);
                }
                Ok((stream_id, quiche::h3::Event::Datagram)) => {
                    debug!("quiche::h3::Event::Datagram on stream id {}", stream_id);
                }
                Ok((stream_id, quiche::h3::Event::GoAway)) => {
                    debug!("quiche::h3::Event::GoAway on stream id {}", stream_id);
                }
                Err(e) => {
                    debug!("recv_query {:?}", e);
                    bail!(e);
                }
            }
        }
    }

    async fn recv_rx(&mut self) -> Result<()> {
        // TODO: Evaluate if we could make the buffer smaller.
        let mut buf = [0; 65535];
        let ts = self
            .quic_conn
            .timeout()
            .unwrap_or_else(|| Duration::from_millis(QUICHE_IDLE_TIMEOUT_MS));

        self.expired_time = BootTime::now().checked_add(ts);
        debug!("recv_rx entry next timeout {:?} {:?}, {}", ts, self.expired_time, self.net_id);
        match timeout(ts, self.udp_sk.recv_from(&mut buf)).await {
            Ok(v) => match v {
                Ok((size, from)) => {
                    let recv_info = quiche::RecvInfo { from };
                    let processed = match self.quic_conn.recv(&mut buf[..size], recv_info) {
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
                warn!("timeout did not receive value within {:?}, {}", ts, self.net_id);
                self.quic_conn.on_timeout();
                Ok(())
            }
        }
    }

    async fn flush_tx(&mut self) -> Result<()> {
        let mut out = [0; MAX_DATAGRAM_SIZE];
        loop {
            let (write, _) = match self.quic_conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                }
                Err(e) => {
                    self.quic_conn.close(false, 0x1, b"fail").ok();
                    bail!(e);
                }
            };
            self.udp_sk.send(&out[..write]).await?;
            debug!("written {}", write);
        }
        Ok(())
    }
}

fn report_private_dns_validation(
    info: &ServerInfo,
    status: &ConnectionStatus,
    runtime: Arc<Runtime>,
    validation_fn: ValidationCallback,
) {
    let (ip_addr, domain) = match (
        CString::new(info.peer_addr.ip().to_string()),
        CString::new(info.domain.clone().unwrap_or_default()),
    ) {
        (Ok(ip_addr), Ok(domain)) => (ip_addr, domain),
        _ => {
            error!("report_private_dns_validation bad input");
            return;
        }
    };
    let netd_id = info.net_id;
    let status = status.clone();
    runtime.spawn_blocking(move || {
        validation_fn(netd_id, status == ConnectionStatus::Ready, ip_addr.as_ptr(), domain.as_ptr())
    });
}

fn handle_probe_result(
    result: (ServerInfo, Result<DohConnection, (anyhow::Error, DohConnection)>),
    doh_conn_map: &mut HashMap<u32, (ServerInfo, Option<DohConnection>)>,
    runtime: Arc<Runtime>,
    validation_fn: ValidationCallback,
) {
    let (info, doh_conn) = match result {
        (info, Ok(doh_conn)) => {
            info!("probing_task success on net_id: {}", info.net_id);
            (info, doh_conn)
        }
        (info, Err((e, mut doh_conn))) => {
            error!("probe failed on network {}, {:?}", e, info.net_id);
            doh_conn.status = ConnectionStatus::Fail;
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
    report_private_dns_validation(&info, &doh_conn.status, runtime, validation_fn);
    doh_conn_map.insert(info.net_id, (info, Some(doh_conn)));
}

async fn probe_task(
    info: ServerInfo,
    mut doh: DohConnection,
    t: Duration,
) -> (ServerInfo, Result<DohConnection, (anyhow::Error, DohConnection)>) {
    let req = match make_probe_query() {
        Ok(q) => match make_dns_request(&q, &info.url) {
            Ok(req) => req,
            Err(e) => return (info, Err((anyhow!(e), doh))),
        },
        Err(e) => return (info, Err((anyhow!(e), doh))),
    };
    match timeout(t, doh.probe(req)).await {
        Ok(v) => match v {
            Ok(_) => (info, Ok(doh)),
            Err(e) => (info, Err((e, doh))),
        },
        Err(e) => (info, Err((anyhow!(e), doh))),
    }
}

fn make_connection_if_needed(
    info: &ServerInfo,
    doh_conn_map: &mut HashMap<u32, (ServerInfo, Option<DohConnection>)>,
    config_cache: &mut QuicheConfigCache,
) -> Result<Option<DohConnection>> {
    // Check if connection exists.
    match doh_conn_map.get(&info.net_id) {
        // The connection exists but has failed. Re-probe.
        Some((server_info, Some(doh)))
            if *server_info == *info && doh.status == ConnectionStatus::Fail =>
        {
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
    match &info.cert_path {
        // The cert path is not either empty or SYSTEM_CERT_PATH, which means it's used by tests,
        // it's not necessary to cache the config.
        Some(cert_path) if cert_path != SYSTEM_CERT_PATH => {
            let mut config = create_quiche_config(Some(cert_path))?;
            let doh = DohConnection::new(info, &mut config)?;
            doh_conn_map.insert(info.net_id, (info.clone(), None));
            Ok(Some(doh))
        }
        // The normal cases, get the config from config cache.
        cert_path => {
            let config = config_cache.get(cert_path)?.ok_or_else(|| anyhow!("no quiche config"))?;
            let doh = DohConnection::new(info, config)?;
            doh_conn_map.insert(info.net_id, (info.clone(), None));
            Ok(Some(doh))
        }
    }
}

struct QuicheConfigCache {
    cert_path: Option<String>,
    config: Option<quiche::Config>,
}

impl QuicheConfigCache {
    fn get(&mut self, cert_path: &Option<String>) -> Result<Option<&mut quiche::Config>> {
        if !cert_path.as_ref().map_or(true, |path| path == SYSTEM_CERT_PATH) {
            bail!("Custom cert_path is not allowed for config cache");
        }
        // No config is cached or the cached config isn't matched with the input cert_path
        // Create it with the input cert_path.
        if self.config.is_none() || self.cert_path != *cert_path {
            self.config = Some(create_quiche_config(cert_path.as_deref())?);
            self.cert_path = cert_path.clone();
        }
        return Ok(self.config.as_mut());
    }
}

fn resume_connection_if_needed(
    info: &ServerInfo,
    quic_conn: &mut DohConnection,
    config_cache: &mut QuicheConfigCache,
) -> Result<()> {
    quic_conn.handle_if_connection_expired();
    if quic_conn.status == ConnectionStatus::Idle {
        let mut c =
            config_cache.get(&info.cert_path)?.ok_or_else(|| anyhow!("no quiche config"))?;
        let connid = quiche::ConnectionId::from_ref(&quic_conn.scid);
        let new_quic_conn =
            quiche::connect(info.domain.as_deref(), &connid, info.peer_addr, &mut c)?;
        quic_conn.resume_connection(new_quic_conn);
    }
    Ok(())
}

async fn handle_query_cmd(
    net_id: u32,
    base64_query: Base64Query,
    expired_time: Instant,
    resp: QueryResponder,
    doh_conn_map: &mut HashMap<u32, (ServerInfo, Option<DohConnection>)>,
    config_cache: &mut QuicheConfigCache,
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
                if quic_conn.status == ConnectionStatus::Fail {
                    let _ = resp.send(Response::Error { error: QueryError::BrokenServer });
                    return;
                }
                if let Err(e) = resume_connection_if_needed(info, quic_conn, config_cache) {
                    error!("resume_connection failed {:?}", e);
                    let _ = resp.send(Response::Error { error: QueryError::BrokenServer });
                    return;
                }
                if let Ok(req) = make_dns_request(&base64_query, &info.url) {
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

async fn doh_handler(
    mut cmd_rx: CmdReceiver,
    runtime: Arc<Runtime>,
    validation_fn: ValidationCallback,
) -> Result<()> {
    info!("doh_dispatcher entry");
    let mut config_cache: QuicheConfigCache = QuicheConfigCache { cert_path: None, config: None };

    // Currently, only support 1 server per network.
    let mut doh_conn_map: HashMap<u32, (ServerInfo, Option<DohConnection>)> = HashMap::new();
    let mut probe_futures = FuturesUnordered::new();
    loop {
        tokio::select! {
            _ = async {
                let mut futures = vec![];
                for (_, doh_conn) in doh_conn_map.values_mut() {
                    if let Some(doh_conn) = doh_conn {
                        if doh_conn.status != ConnectionStatus::Fail {
                            futures.push(doh_conn.process_queries());
                        }
                    }
                }
                join_all(futures).await
            } , if !doh_conn_map.is_empty() => {},
            Some(result) = probe_futures.next() => {
                let runtime_clone = runtime.clone();
                handle_probe_result(result, &mut doh_conn_map, runtime_clone, validation_fn);
                info!("probe_futures remaining size: {}", probe_futures.len());
            },
            Some(cmd) = cmd_rx.recv() => {
                trace!("recv {:?}", cmd);
                match cmd {
                    DohCommand::Probe { info, timeout: t } => {
                        match make_connection_if_needed(&info, &mut doh_conn_map, &mut config_cache) {
                            Ok(Some(doh)) => {
                                // Create a new async task associated to the DoH connection.
                                probe_futures.push(probe_task(info, doh, t));
                                debug!("probe_map size: {}", probe_futures.len());
                            }
                            Ok(None) => {
                                // No further probe is needed.
                                warn!("connection for network {} already exists", info.net_id);
                                // TODO: Report the status again?
                            }
                            Err(e) => {
                                error!("create connection for network {} error {:?}", info.net_id, e);
                                report_private_dns_validation(&info, &ConnectionStatus::Fail, runtime.clone(), validation_fn);
                            }
                        }
                    },
                    DohCommand::Query { net_id, base64_query, expired_time, resp } => {
                        handle_query_cmd(net_id, base64_query, expired_time, resp, &mut doh_conn_map, &mut config_cache).await;
                    },
                    DohCommand::Clear { net_id } => {
                        doh_conn_map.remove(&net_id);
                        info!("Doh Clear server for netid: {}", net_id);
                    },
                    DohCommand::Exit => return Ok(()),
                }
            }
        }
    }
}

fn make_dns_request(base64_query: &str, url: &url::Url) -> Result<DnsRequest> {
    let mut path = String::from(url.path());
    path.push_str("?dns=");
    path.push_str(base64_query);
    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(
            b":authority",
            url.host_str().ok_or_else(|| anyhow!("failed to get host"))?.as_bytes(),
        ),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
        quiche::h3::Header::new(b"accept", b"application/dns-message"),
        // TODO: is content-length required?
    ];

    Ok(req)
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

    debug!("connecting to {:} from {:}", peer_addr, udp_sk.local_addr()?);
    Ok(udp_sk)
}

fn create_quiche_config(cert_path: Option<&str>) -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_application_protos(h3::APPLICATION_PROTOCOL)?;
    match cert_path {
        Some(path) => {
            config.verify_peer(true);
            config.load_verify_locations_from_directory(path)?;
        }
        None => config.verify_peer(false),
    }

    // Some of these configs are necessary, or the server can't respond the HTTP/3 request.
    config.set_max_idle_timeout(QUICHE_IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(MAX_INCOMING_BUFFER_SIZE_WHOLE);
    config.set_initial_max_stream_data_bidi_local(MAX_INCOMING_BUFFER_SIZE_EACH);
    config.set_initial_max_stream_data_bidi_remote(MAX_INCOMING_BUFFER_SIZE_EACH);
    config.set_initial_max_stream_data_uni(MAX_INCOMING_BUFFER_SIZE_EACH);
    config.set_initial_max_streams_bidi(MAX_CONCURRENT_STREAM_SIZE);
    config.set_initial_max_streams_uni(MAX_CONCURRENT_STREAM_SIZE);
    config.set_disable_active_migration(true);
    Ok(config)
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

#[rustfmt::skip]
fn make_probe_query() -> Result<String> {
    let mut rnd = [0; 8];
    ring::rand::SystemRandom::new().fill(&mut rnd).context("failed to generate probe rnd")?;
    let c = |byte| CHARSET[(byte as usize) % CHARSET.len()];
    let query = vec![
        rnd[6], rnd[7],  // [0-1]   query ID
        1,      0,       // [2-3]   flags; query[2] = 1 for recursion desired (RD).
        0,      1,       // [4-5]   QDCOUNT (number of queries)
        0,      0,       // [6-7]   ANCOUNT (number of answers)
        0,      0,       // [8-9]   NSCOUNT (number of name server records)
        0,      0,       // [10-11] ARCOUNT (number of additional records)
        19,     c(rnd[0]), c(rnd[1]), c(rnd[2]), c(rnd[3]), c(rnd[4]), c(rnd[5]), b'-', b'd', b'n',
        b's',   b'o',      b'h',      b't',      b't',      b'p',      b's',      b'-', b'd', b's',
        6,      b'm',      b'e',      b't',      b'r',      b'i',      b'c',      7,    b'g', b's',
        b't',   b'a',      b't',      b'i',      b'c',      3,         b'c',      b'o', b'm',
        0,                  // null terminator of FQDN (root TLD)
        0,      NS_T_AAAA,  // QTYPE
        0,      NS_C_IN     // QCLASS
    ];
    Ok(base64::encode_config(query, base64::URL_SAFE_NO_PAD))
}

/// Performs static initialization for android logger.
#[no_mangle]
pub extern "C" fn doh_init_logger(level: u32) {
    INIT.call_once(|| {
        let level = match level {
            LOG_LEVEL_WARN => log::Level::Warn,
            LOG_LEVEL_DEBUG => log::Level::Debug,
            _ => log::Level::Error,
        };
        android_logger::init_once(android_logger::Config::default().with_min_level(level));
    });
}

/// Set the log level.
#[no_mangle]
pub extern "C" fn doh_set_log_level(level: u32) {
    let level = match level {
        LOG_LEVEL_ERROR => log::LevelFilter::Error,
        LOG_LEVEL_WARN => log::LevelFilter::Warn,
        LOG_LEVEL_INFO => log::LevelFilter::Info,
        LOG_LEVEL_DEBUG => log::LevelFilter::Debug,
        LOG_LEVEL_TRACE => log::LevelFilter::Trace,
        _ => log::LevelFilter::Off,
    };
    log::set_max_level(level);
}

/// Performs the initialization for the DoH engine.
/// Creates and returns a DoH engine instance.
#[no_mangle]
pub extern "C" fn doh_dispatcher_new(ptr: ValidationCallback) -> *mut DohDispatcher {
    match DohDispatcher::new(ptr) {
        Ok(c) => Box::into_raw(c),
        Err(e) => {
            error!("doh_dispatcher_new: failed: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Deletes a DoH engine created by doh_dispatcher_new().
/// # Safety
/// `doh` must be a non-null pointer previously created by `doh_dispatcher_new()`
/// and not yet deleted by `doh_dispatcher_delete()`.
#[no_mangle]
pub unsafe extern "C" fn doh_dispatcher_delete(doh: *mut DohDispatcher) {
    Box::from_raw(doh).exit_handler()
}

/// Probes and stores the DoH server with the given configurations.
/// Use the negative errno-style codes as the return value to represent the result.
/// # Safety
/// `doh` must be a non-null pointer previously created by `doh_dispatcher_new()`
/// and not yet deleted by `doh_dispatcher_delete()`.
/// `url`, `domain`, `ip_addr`, `cert_path` are null terminated strings.
#[no_mangle]
pub unsafe extern "C" fn doh_net_new(
    doh: &mut DohDispatcher,
    net_id: uint32_t,
    url: *const c_char,
    domain: *const c_char,
    ip_addr: *const c_char,
    sk_mark: libc::uint32_t,
    cert_path: *const c_char,
    timeout_ms: libc::uint64_t,
) -> int32_t {
    let (url, domain, ip_addr, cert_path) = match (
        std::ffi::CStr::from_ptr(url).to_str(),
        std::ffi::CStr::from_ptr(domain).to_str(),
        std::ffi::CStr::from_ptr(ip_addr).to_str(),
        std::ffi::CStr::from_ptr(cert_path).to_str(),
    ) {
        (Ok(url), Ok(domain), Ok(ip_addr), Ok(cert_path)) => {
            if domain.is_empty() {
                (url, None, ip_addr.to_string(), None)
            } else if !cert_path.is_empty() {
                (url, Some(domain.to_string()), ip_addr.to_string(), Some(cert_path.to_string()))
            } else {
                (
                    url,
                    Some(domain.to_string()),
                    ip_addr.to_string(),
                    Some(SYSTEM_CERT_PATH.to_string()),
                )
            }
        }
        _ => {
            error!("bad input"); // Should not happen
            return -libc::EINVAL;
        }
    };

    let (url, ip_addr) = match (url::Url::parse(url), IpAddr::from_str(&ip_addr)) {
        (Ok(url), Ok(ip_addr)) => (url, ip_addr),
        _ => {
            error!("bad ip or url"); // Should not happen
            return -libc::EINVAL;
        }
    };
    let cmd = DohCommand::Probe {
        info: ServerInfo {
            net_id,
            url,
            peer_addr: SocketAddr::new(ip_addr, DOH_PORT),
            domain,
            sk_mark,
            cert_path,
        },
        timeout: Duration::from_millis(timeout_ms),
    };
    if let Err(e) = doh.send_cmd(cmd) {
        error!("Failed to send the probe: {:?}", e);
        return -libc::EPIPE;
    }
    0
}

/// Sends a DNS query via the network associated to the given |net_id| and waits for the response.
/// The return code should be either one of the public constant RESULT_* to indicate the error or
/// the size of the answer.
/// # Safety
/// `doh` must be a non-null pointer previously created by `doh_dispatcher_new()`
/// and not yet deleted by `doh_dispatcher_delete()`.
/// `dns_query` must point to a buffer at least `dns_query_len` in size.
/// `response` must point to a buffer at least `response_len` in size.
#[no_mangle]
pub unsafe extern "C" fn doh_query(
    doh: &mut DohDispatcher,
    net_id: uint32_t,
    dns_query: *mut u8,
    dns_query_len: size_t,
    response: *mut u8,
    response_len: size_t,
    timeout_ms: uint64_t,
) -> ssize_t {
    let q = slice::from_raw_parts_mut(dns_query, dns_query_len);

    let (resp_tx, resp_rx) = oneshot::channel();
    let t = Duration::from_millis(timeout_ms);
    if let Some(expired_time) = Instant::now().checked_add(t) {
        let cmd = DohCommand::Query {
            net_id,
            base64_query: base64::encode_config(q, base64::URL_SAFE_NO_PAD),
            expired_time,
            resp: resp_tx,
        };

        if let Err(e) = doh.send_cmd(cmd) {
            error!("Failed to send the query: {:?}", e);
            return RESULT_CAN_NOT_SEND;
        }
    } else {
        error!("Bad timeout parameter: {}", timeout_ms);
        return RESULT_CAN_NOT_SEND;
    }

    if let Ok(rt) = Runtime::new() {
        let local = task::LocalSet::new();
        match local.block_on(&rt, async { timeout(t, resp_rx).await }) {
            Ok(v) => match v {
                Ok(v) => match v {
                    Response::Success { answer } => {
                        if answer.len() > response_len || answer.len() > isize::MAX as usize {
                            return RESULT_INTERNAL_ERROR;
                        }
                        let response = slice::from_raw_parts_mut(response, answer.len());
                        response.copy_from_slice(&answer);
                        answer.len() as ssize_t
                    }
                    Response::Error { error: QueryError::ServerNotReady } => RESULT_CAN_NOT_SEND,
                    _ => RESULT_INTERNAL_ERROR,
                },
                Err(e) => {
                    error!("no result {}", e);
                    RESULT_INTERNAL_ERROR
                }
            },
            Err(e) => {
                error!("timeout: {}", e);
                RESULT_TIMEOUT
            }
        }
    } else {
        RESULT_INTERNAL_ERROR
    }
}

/// Clears the DoH servers associated with the given |netid|.
/// # Safety
/// `doh` must be a non-null pointer previously created by `doh_dispatcher_new()`
/// and not yet deleted by `doh_dispatcher_delete()`.
#[no_mangle]
pub extern "C" fn doh_net_delete(doh: &mut DohDispatcher, net_id: uint32_t) {
    if let Err(e) = doh.send_cmd(DohCommand::Clear { net_id }) {
        error!("Failed to send the query: {:?}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::h3::NameValue;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    const TEST_NET_ID: u32 = 50;
    const PROBE_QUERY_SIZE: usize = 56;
    const H3_DNS_REQUEST_HEADER_SIZE: usize = 6;
    const TEST_MARK: u32 = 0xD0033;
    const LOOPBACK_ADDR: &str = "127.0.0.1:443";
    const LOCALHOST_URL: &str = "https://mylocal.com/dns-query";

    // TODO: Make some tests for DohConnection and QuicheConfigCache.

    fn make_testing_variables() -> (
        ServerInfo,
        HashMap<u32, (ServerInfo, Option<DohConnection>)>,
        QuicheConfigCache,
        Arc<Runtime>,
    ) {
        let test_map: HashMap<u32, (ServerInfo, Option<DohConnection>)> = HashMap::new();
        let info = ServerInfo {
            net_id: TEST_NET_ID,
            url: Url::parse(LOCALHOST_URL).unwrap(),
            peer_addr: LOOPBACK_ADDR.parse().unwrap(),
            domain: None,
            sk_mark: 0,
            cert_path: None,
        };
        let config: QuicheConfigCache = QuicheConfigCache { cert_path: None, config: None };

        let rt = Arc::new(
            Builder::new_current_thread()
                .thread_name("test-runtime")
                .enable_all()
                .build()
                .expect("Failed to create testing tokio runtime"),
        );
        (info, test_map, config, rt)
    }

    #[test]
    fn make_connection_if_needed() {
        let (info, mut test_map, mut config, rt) = make_testing_variables();
        rt.block_on(async {
            // Expect to make a new connection.
            let mut doh = super::make_connection_if_needed(&info, &mut test_map, &mut config)
                .unwrap()
                .unwrap();
            assert_eq!(doh.net_id, info.net_id);
            assert_eq!(doh.status, ConnectionStatus::Pending);
            doh.status = ConnectionStatus::Fail;
            test_map.insert(info.net_id, (info.clone(), Some(doh)));
            // Expect that we will get a connection with fail status that we added to the map before.
            let mut doh = super::make_connection_if_needed(&info, &mut test_map, &mut config)
                .unwrap()
                .unwrap();
            assert_eq!(doh.net_id, info.net_id);
            assert_eq!(doh.status, ConnectionStatus::Fail);
            doh.status = ConnectionStatus::Ready;
            test_map.insert(info.net_id, (info.clone(), Some(doh)));
            // Expect that we will get None because the map contains a connection with ready status.
            assert!(super::make_connection_if_needed(&info, &mut test_map, &mut config)
                .unwrap()
                .is_none());
        });
    }

    #[test]
    fn handle_query_cmd() {
        let (info, mut test_map, mut config, rt) = make_testing_variables();
        let t = Duration::from_millis(100);

        rt.block_on(async {
            // Test no available server cases.
            let (resp_tx, resp_rx) = oneshot::channel();
            let query = super::make_probe_query().unwrap();
            super::handle_query_cmd(
                info.net_id,
                query.clone(),
                Instant::now().checked_add(t).unwrap(),
                resp_tx,
                &mut test_map,
                &mut config,
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
                Instant::now().checked_add(t).unwrap(),
                resp_tx,
                &mut test_map,
                &mut config,
            )
            .await;
            assert_eq!(
                timeout(t, resp_rx).await.unwrap().unwrap(),
                Response::Error { error: QueryError::ServerNotReady }
            );

            // Test the connection broken case.
            test_map.clear();
            let (resp_tx, resp_rx) = oneshot::channel();
            let mut doh = super::make_connection_if_needed(&info, &mut test_map, &mut config)
                .unwrap()
                .unwrap();
            doh.status = ConnectionStatus::Fail;
            test_map.insert(info.net_id, (info.clone(), Some(doh)));
            super::handle_query_cmd(
                info.net_id,
                query.clone(),
                Instant::now().checked_add(t).unwrap(),
                resp_tx,
                &mut test_map,
                &mut config,
            )
            .await;
            assert_eq!(
                timeout(t, resp_rx).await.unwrap().unwrap(),
                Response::Error { error: QueryError::BrokenServer }
            );
        });
    }

    extern "C" fn success_cb(
        net_id: uint32_t,
        success: bool,
        ip_addr: *const c_char,
        host: *const c_char,
    ) {
        assert!(success);
        unsafe {
            assert_validation_info(net_id, ip_addr, host);
        }
    }

    extern "C" fn fail_cb(
        net_id: uint32_t,
        success: bool,
        ip_addr: *const c_char,
        host: *const c_char,
    ) {
        assert!(!success);
        unsafe {
            assert_validation_info(net_id, ip_addr, host);
        }
    }

    // # Safety
    // `ip_addr`, `host` are null terminated strings
    unsafe fn assert_validation_info(
        net_id: uint32_t,
        ip_addr: *const c_char,
        host: *const c_char,
    ) {
        assert_eq!(net_id, TEST_NET_ID);
        let ip_addr = std::ffi::CStr::from_ptr(ip_addr).to_str().unwrap();
        let expected_addr: SocketAddr = LOOPBACK_ADDR.parse().unwrap();
        assert_eq!(ip_addr, expected_addr.ip().to_string());
        let host = std::ffi::CStr::from_ptr(host).to_str().unwrap();
        assert_eq!(host, "");
    }

    #[test]
    fn report_private_dns_validation() {
        let info = ServerInfo {
            net_id: TEST_NET_ID,
            url: Url::parse(LOCALHOST_URL).unwrap(),
            peer_addr: LOOPBACK_ADDR.parse().unwrap(),
            domain: None,
            sk_mark: 0,
            cert_path: None,
        };
        let rt = Arc::new(
            Builder::new_current_thread()
                .thread_name("test-runtime")
                .build()
                .expect("Failed to create testing tokio runtime"),
        );
        let default_panic = std::panic::take_hook();
        // Exit the test if the worker inside tokio runtime panicked.
        std::panic::set_hook(Box::new(move |info| {
            default_panic(info);
            std::process::exit(1);
        }));
        super::report_private_dns_validation(
            &info,
            &ConnectionStatus::Ready,
            rt.clone(),
            success_cb,
        );
        super::report_private_dns_validation(&info, &ConnectionStatus::Fail, rt.clone(), fail_cb);
        super::report_private_dns_validation(
            &info,
            &ConnectionStatus::Pending,
            rt.clone(),
            fail_cb,
        );
        super::report_private_dns_validation(&info, &ConnectionStatus::Idle, rt, fail_cb);
    }

    #[test]
    fn make_probe_query_and_request() {
        let probe_query = super::make_probe_query().unwrap();
        let url = Url::parse(LOCALHOST_URL).unwrap();
        let request = make_dns_request(&probe_query, &url).unwrap();
        // Verify H3 DNS request.
        assert_eq!(request.len(), H3_DNS_REQUEST_HEADER_SIZE);
        assert_eq!(request[0].name(), b":method");
        assert_eq!(request[0].value(), b"GET");
        assert_eq!(request[1].name(), b":scheme");
        assert_eq!(request[1].value(), b"https");
        assert_eq!(request[2].name(), b":authority");
        assert_eq!(request[2].value(), url.host_str().unwrap().as_bytes());
        assert_eq!(request[3].name(), b":path");
        let mut path = String::from(url.path());
        path.push_str("?dns=");
        path.push_str(&probe_query);
        assert_eq!(request[3].value(), path.as_bytes());
        assert_eq!(request[5].name(), b"accept");
        assert_eq!(request[5].value(), b"application/dns-message");

        // Verify DNS probe packet.
        let bytes = base64::decode_config(probe_query, base64::URL_SAFE_NO_PAD).unwrap();
        assert_eq!(bytes.len(), PROBE_QUERY_SIZE);
        // TODO: Parse the result to ensure it's a valid DNS packet.
    }

    #[test]
    fn create_quiche_config() {
        assert!(
            super::create_quiche_config(None).is_ok(),
            "quiche config without cert creating failed"
        );
        assert!(
            super::create_quiche_config(Some("data/local/tmp/")).is_ok(),
            "quiche config with cert creating failed"
        );
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
