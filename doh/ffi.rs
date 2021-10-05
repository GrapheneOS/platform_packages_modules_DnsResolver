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

//! C API for the DoH backend for the Android DnsResolver module.

use libc::{c_char, int32_t, size_t, ssize_t, uint32_t, uint64_t};
use log::error;
use std::net::{IpAddr, SocketAddr};
use std::ops::DerefMut;
use std::str::FromStr;
use std::sync::Mutex;
use std::{ptr, slice};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio::task;
use tokio::time::{timeout, Duration, Instant};

use super::DohDispatcher as Dispatcher;
use super::{DohCommand, Response, ServerInfo, TagSocketCallback, ValidationCallback, DOH_PORT};

pub struct DohDispatcher(Mutex<Dispatcher>);

impl DohDispatcher {
    fn lock(&self) -> impl DerefMut<Target = Dispatcher> + '_ {
        self.0.lock().unwrap()
    }
}

const SYSTEM_CERT_PATH: &str = "/system/etc/security/cacerts";

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

/// Performs static initialization for android logger.
#[no_mangle]
pub extern "C" fn doh_init_logger(level: u32) {
    let level = match level {
        LOG_LEVEL_WARN => log::Level::Warn,
        LOG_LEVEL_DEBUG => log::Level::Debug,
        _ => log::Level::Error,
    };
    android_logger::init_once(android_logger::Config::default().with_min_level(level));
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
pub extern "C" fn doh_dispatcher_new(
    validation_fn: ValidationCallback,
    tag_socket_fn: TagSocketCallback,
) -> *mut DohDispatcher {
    match Dispatcher::new(validation_fn, tag_socket_fn) {
        Ok(c) => Box::into_raw(Box::new(DohDispatcher(Mutex::new(c)))),
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
    Box::from_raw(doh).lock().exit_handler()
}

/// Probes and stores the DoH server with the given configurations.
/// Use the negative errno-style codes as the return value to represent the result.
/// # Safety
/// `doh` must be a non-null pointer previously created by `doh_dispatcher_new()`
/// and not yet deleted by `doh_dispatcher_delete()`.
/// `url`, `domain`, `ip_addr`, `cert_path` are null terminated strings.
#[no_mangle]
pub unsafe extern "C" fn doh_net_new(
    doh: &DohDispatcher,
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
    if let Err(e) = doh.lock().send_cmd(cmd) {
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
    doh: &DohDispatcher,
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

        if let Err(e) = doh.lock().send_cmd(cmd) {
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
                    _ => RESULT_CAN_NOT_SEND,
                },
                Err(e) => {
                    error!("no result {}", e);
                    RESULT_CAN_NOT_SEND
                }
            },
            Err(e) => {
                error!("timeout: {}", e);
                RESULT_TIMEOUT
            }
        }
    } else {
        RESULT_CAN_NOT_SEND
    }
}

/// Clears the DoH servers associated with the given |netid|.
/// # Safety
/// `doh` must be a non-null pointer previously created by `doh_dispatcher_new()`
/// and not yet deleted by `doh_dispatcher_delete()`.
#[no_mangle]
pub extern "C" fn doh_net_delete(doh: &DohDispatcher, net_id: uint32_t) {
    if let Err(e) = doh.lock().send_cmd(DohCommand::Clear { net_id }) {
        error!("Failed to send the query: {:?}", e);
    }
}
