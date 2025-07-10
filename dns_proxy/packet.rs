// Copyright 2025 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! DNS packet definition.

use bytes::Buf;
use bytes::BufMut;
use num_enum::FromPrimitive;
use num_enum::IntoPrimitive;
use thiserror::Error;

const DNS_HEADER_LEN: usize = 12;

/// Error type for packet
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    /// Packet shorter than header size
    #[error("Packet shorter than header size")]
    PacketTooShort,
}

/// Result type for packet
pub type PacketResult<T> = std::result::Result<T, PacketError>;

/// A DnsPacket is a wrapping of a DNS packet in bytes with its header parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsPacket {
    /// DNS Header
    header: DnsHeader,
    /// The raw packet, including the header
    raw: Vec<u8>,
}

/// Parse raw as DNS packet. Only the validity of the header is checked.
impl TryFrom<Vec<u8>> for DnsPacket {
    type Error = PacketError;
    fn try_from(raw: Vec<u8>) -> PacketResult<Self> {
        let header: DnsHeader = raw.as_slice().try_into()?;
        Ok(Self { header, raw })
    }
}

impl DnsPacket {
    /// Get the raw packet.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Gets the header.
    pub fn header(&self) -> &DnsHeader {
        &self.header
    }
}

/// A DnsHeader is parsed from the first 12 bytes of a packet datagram with
/// the following fields:
///
///  1  1  1  1  1  1
///  5  4  3  2  1  0  9  8  7  6  5  4  3  2  1  0
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   OPCODE  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DnsHeader {
    /// ID
    pub id: u16,
    // flags:
    /// QR is response (or query)
    pub qr_is_response: bool,
    /// Opcode
    pub opcode: Opcode,
    /// AA: Authoritative answer
    pub aa: bool,
    /// TC: Truncation
    pub tc: bool,
    /// RD: Recursion Desired
    pub rd: bool,
    /// RA: Recursion Available
    pub ra: bool,
    /// AD: Authentic Data
    pub ad: bool,
    /// CD: Checking Disabled
    pub cd: bool,
    /// Rcode
    pub rcode: Rcode,
    /// Query count
    pub qd_count: u16,
    /// Answer count
    pub an_count: u16,
    /// Name server resource records count
    pub ns_count: u16,
    /// Additional records count
    pub ar_count: u16,
}

impl TryFrom<&[u8]> for DnsHeader {
    type Error = PacketError;
    fn try_from(mut raw: &[u8]) -> PacketResult<Self> {
        if raw.len() < DNS_HEADER_LEN {
            return Err(PacketError::PacketTooShort);
        }

        let id = raw.get_u16();
        let flags = raw.get_u16();
        let qd_count = raw.get_u16();
        let an_count = raw.get_u16();
        let ns_count = raw.get_u16();
        let ar_count = raw.get_u16();
        Ok(Self {
            id,
            qr_is_response: ((flags >> 15) & 0x1) != 0,
            opcode: ((flags >> 11) & 0xf).into(),
            aa: (flags >> 10) & 0x1 != 0,
            tc: (flags >> 9) & 0x1 != 0,
            rd: (flags >> 8) & 0x1 != 0,
            ra: (flags >> 7) & 0x1 != 0,
            ad: (flags >> 5) & 0x1 != 0,
            cd: (flags >> 4) & 0x1 != 0,
            rcode: (flags & 0xf).into(),
            qd_count,
            an_count,
            ns_count,
            ar_count,
        })
    }
}

impl From<DnsHeader> for [u8; DNS_HEADER_LEN] {
    fn from(value: DnsHeader) -> Self {
        let mut bytes = [0u8; DNS_HEADER_LEN];
        let mut bytes_mut = bytes.as_mut_slice();
        bytes_mut.put_u16(value.id);
        let flags: u16 = ((value.qr_is_response as u16) << 15)
            | (u16::from(value.opcode) << 11)
            | ((value.aa as u16) << 10)
            | ((value.tc as u16) << 9)
            | ((value.rd as u16) << 8)
            | ((value.ra as u16) << 7)
            | ((value.ad as u16) << 5)
            | ((value.cd as u16) << 4)
            | u16::from(value.rcode);
        bytes_mut.put_u16(flags);
        bytes_mut.put_u16(value.qd_count);
        bytes_mut.put_u16(value.an_count);
        bytes_mut.put_u16(value.ns_count);
        bytes_mut.put_u16(value.ar_count);
        bytes
    }
}

/// OPCODE of a DNS packet. Ref: RFC6895
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
pub(crate) enum Opcode {
    /// DNS Query
    Query = 0,
    /// Inverse DNS query
    IQuery = 1,
    /// Server status request
    Status = 2,
    /// Notification of zone change (Ref: RFC1996)
    Notify = 4,
    /// Dynamic DNS updates (Ref: RFC2136)
    Update = 5,
    /// Other unspecified Opcode
    #[num_enum(catch_all)]
    Unspecified(u16),
}

/// RCODE to a DNS Opcode::Query and valid response to it.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
pub(crate) enum Rcode {
    /// No error
    NoError = 0,
    /// Format error
    FormErr = 1,
    /// Server failure
    ServFail = 2,
    /// Name error
    NXDomain = 3,
    /// Not implemented
    NotImp = 4,
    /// Refused
    Refused = 5,
    /// Domain ought not to exist but does exist
    YXDomain = 6,
    /// RR ought not to exist but does exist
    YXRRSet = 7,
    /// RR ought to exist but does not exist
    NXRRSet = 8,
    /// Server is not authoritative for the zone
    NotAuth = 9,
    /// Name used in the prerequisite or update section is not within the zone
    NotZone = 10,
    /// Other unspecified Rcode
    #[num_enum(catch_all)]
    Unspecified(u16),
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A valid DNS query for test.
    pub const TEST_VALID_DNS_QUERY: [u8; 49] = [
        0x3b, 0x1e, // ID
        0x01,
        0x20, // flags (QR=0, opcode=Query, AA=0, TC=0, RD=1, RA=0, AD=1, CD=0, RCODE=NOERROR)
        0x00, 0x01, // query count
        0x00, 0x00, // answer count
        0x00, 0x00, // name server resource records count
        0x00, 0x01, // additional records count
        0x04, 0x63, 0x73, 0x64, 0x6e, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x4f,
        0x51, 0x32, 0x69, 0x09, 0x11, 0x9e, 0x21,
    ];

    #[test]
    fn test_query_packet_parse() {
        let test_query_packet = DnsPacket::try_from(TEST_VALID_DNS_QUERY.to_vec()).unwrap();
        assert_eq!(test_query_packet.as_bytes(), TEST_VALID_DNS_QUERY.as_slice());
    }

    #[test]
    fn test_too_short_packet_parse() {
        let short_packet = TEST_VALID_DNS_QUERY[0..11].to_vec();
        assert_eq!(DnsPacket::try_from(short_packet).unwrap_err(), PacketError::PacketTooShort);
    }

    // Tests that for a valid DnsHeader, it is invariant after a serialization and parse cycle.
    #[test]
    fn test_dns_header_serde_invariant() {
        let header_bytes: [u8; DNS_HEADER_LEN] = [
            0xde,
            0xad, // DNS ID
            0b1010_1101,
            0b0010_1000, // DNS flags
            0x00,
            0x01, // QD_COUNT
            0x00,
            0x00, // AN_COUNT
            0x00,
            0x00, // NS_COUNT
            0x00,
            0x01, // AR_COUNT
        ];
        let header = DnsHeader {
            id: 0xdead,
            qr_is_response: true,
            opcode: Opcode::Update,
            aa: true,
            tc: false,
            rd: true,
            ra: false,
            ad: true,
            cd: false,
            rcode: Rcode::NXRRSet,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 1,
        };
        assert_eq!(DnsHeader::try_from(header_bytes.as_slice()).unwrap(), header);
        assert_eq!(header_bytes, <[u8; DNS_HEADER_LEN]>::from(header));
    }

    /// Tests that for a DnsHeader with unspecified OPCODE and RCODE does not throw error.
    #[test]
    fn test_dns_header_unspecified_values() {
        let header_bytes: [u8; DNS_HEADER_LEN] = [
            0xde,
            0xad, // DNS ID
            0b1110_1101,
            0b0010_1110, // DNS flags
            0x00,
            0x02, // QD_COUNT
            0x00,
            0x00, // AN_COUNT
            0x00,
            0x03, // NS_COUNT
            0x00,
            0x01, // AR_COUNT
        ];
        let header = DnsHeader {
            id: 0xdead,
            qr_is_response: true,
            opcode: Opcode::Unspecified(0b1101),
            aa: true,
            tc: false,
            rd: true,
            ra: false,
            ad: true,
            cd: false,
            rcode: Rcode::Unspecified(0b1110),
            qd_count: 2,
            an_count: 0,
            ns_count: 3,
            ar_count: 1,
        };
        assert_eq!(DnsHeader::try_from(header_bytes.as_slice()).unwrap(), header);
        assert_eq!(header_bytes, <[u8; DNS_HEADER_LEN]>::from(header));
    }

    /// Tests that a packet is rejected when it is too short.
    #[test]
    fn test_dns_header_short() {
        let header_bytes: [u8; DNS_HEADER_LEN - 1] = [
            0xde,
            0xad, // DNS ID
            0b1010_1101,
            0b0010_1000, // DNS flags
            0x00,
            0x01, // QD_COUNT
            0x00,
            0x00, // AN_COUNT
            0x00,
            0x00, // NS_COUNT
            0x00,
        ];

        DnsHeader::try_from(header_bytes.as_slice()).unwrap_err();
    }
}
