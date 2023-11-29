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

//! Format DoH requests

use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use log::debug;
use quiche::h3;
use ring::rand::SecureRandom;
use rustutils::system_properties;
use url::Url;

pub type DnsRequest = Vec<quiche::h3::Header>;

const NS_T_AAAA: u8 = 28;
const NS_C_IN: u8 = 1;
// Used to randomly generate query prefix and query id.
const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                         abcdefghijklmnopqrstuvwxyz\
                         0123456789";

// keep in sync with android.ext.settings.ConnChecksSetting
pub const CONN_CHECKS_SETTING_GRAPHENEOS: i32 = 0;
pub const CONN_CHECKS_SETTING_STANDARD: i32 = 1;
pub const CONN_CHECKS_SETTING_DISABLED: i32 = 2;
pub const CONN_CHECKS_SETTING_DEFAULT: i32 = CONN_CHECKS_SETTING_GRAPHENEOS;

/// Produces a DNS query with randomized query ID and random 6-byte charset-legal prefix to produce
/// a request for a domain of the form:
/// ??????-dnsohttps-ds.metric.gstatic.com
#[rustfmt::skip]
pub fn probe_query() -> Result<String> {
    let mut rnd = [0; 8];
    ring::rand::SystemRandom::new().fill(&mut rnd).context("failed to generate probe rnd")?;
    let c = |byte| CHARSET[(byte as usize) % CHARSET.len()];
    let mut query = vec![
        rnd[6], rnd[7],  // [0-1]   query ID
        1,      0,       // [2-3]   flags; query[2] = 1 for recursion desired (RD).
        0,      1,       // [4-5]   QDCOUNT (number of queries)
        0,      0,       // [6-7]   ANCOUNT (number of answers)
        0,      0,       // [8-9]   NSCOUNT (number of name server records)
        0,      0,       // [10-11] ARCOUNT (number of additional records)
        19,     c(rnd[0]), c(rnd[1]), c(rnd[2]), c(rnd[3]), c(rnd[4]), c(rnd[5]), b'-', b'd', b'n',
        b's',   b'o',      b'h',      b't',      b't',      b'p',      b's',      b'-', b'd', b's',
    ];

    let conn_check_setting: i32 = system_properties::read("persist.sys.connectivity_checks")
        .unwrap_or_else(|_| Some("".to_string()))
        .as_deref()
        .unwrap_or("")
        .parse::<i32>()
        .map_or_else(|_| CONN_CHECKS_SETTING_DEFAULT, |v| match v {
            CONN_CHECKS_SETTING_GRAPHENEOS
            | CONN_CHECKS_SETTING_STANDARD => v,
            CONN_CHECKS_SETTING_DISABLED => {
                // skipping the check would break detection of broken DoH
                debug!("probe_query: CONN_CHECKS_SETTING_DISABLED, falling back to default hostname");
                CONN_CHECKS_SETTING_DEFAULT
            },
            _ => CONN_CHECKS_SETTING_DEFAULT,
        });

    if conn_check_setting == CONN_CHECKS_SETTING_STANDARD {
        debug!("probe_query: using metric.gstatic.com");
        append_qname_label("metric", &mut query);
        append_qname_label("gstatic", &mut query);
        append_qname_label("com", &mut query);
    } else {
        debug!("probe_query: using dnscheck.grapheneos.org");
        append_qname_label("dnscheck", &mut query);
        append_qname_label("grapheneos", &mut query);
        append_qname_label("org", &mut query);
    }

    let mut end = vec![
        0,                  // null terminator of FQDN (root TLD)
        0,      NS_T_AAAA,  // QTYPE
        0,      NS_C_IN     // QCLASS
    ];
    query.append(&mut end);

    Ok(BASE64_URL_SAFE_NO_PAD.encode(query))
}

fn append_qname_label(label: &str, dst: &mut Vec<u8>) {
    let len = label.len();
    // 6-bit positive number
    assert!(len > 0 && len <= 0b11_1111);
    dst.push(len as u8);
    dst.extend_from_slice(label.as_bytes());
}

/// Takes in a base64-encoded copy of a traditional DNS request and a
/// URL at which the DoH server is running and produces a set of HTTP/3 headers
/// corresponding to a DoH request for it.
pub fn dns_request(base64_query: &str, url: &Url) -> Result<DnsRequest> {
    let mut path = String::from(url.path());
    path.push_str("?dns=");
    path.push_str(base64_query);
    let req = vec![
        h3::Header::new(b":method", b"GET"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(
            b":authority",
            url.host_str().ok_or_else(|| anyhow!("failed to get host"))?.as_bytes(),
        ),
        h3::Header::new(b":path", path.as_bytes()),
        h3::Header::new(b"user-agent", b"quiche"),
        h3::Header::new(b"accept", b"application/dns-message"),
    ];

    Ok(req)
}

#[cfg(test)]
mod tests {
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
    use quiche::h3::NameValue;
    use url::Url;

    const PROBE_QUERY_SIZE: usize = 56;
    const H3_DNS_REQUEST_HEADER_SIZE: usize = 6;
    const LOCALHOST_URL: &str = "https://mylocal.com/dns-query";

    #[test]
    fn make_probe_query_and_request() {
        let probe_query = super::probe_query().unwrap();
        let url = Url::parse(LOCALHOST_URL).unwrap();
        let request = super::dns_request(&probe_query, &url).unwrap();
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
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(probe_query).unwrap();
        assert_eq!(bytes.len(), PROBE_QUERY_SIZE);
    }
}
