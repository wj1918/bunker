//! Minimal DNS wire format parser (RFC 1035).
//!
//! This module provides a lightweight DNS parser to replace hickory-proto,
//! reducing binary size by ~200KB while maintaining all necessary functionality.

use std::fmt;

// DNS wire format constants
const HEADER_SIZE: usize = 12;
const FLAG_QR: u16 = 0x8000; // Query/Response flag
const FLAG_RCODE_MASK: u16 = 0x000F; // Response code mask

// RFC 1035: Maximum hostname length is 253 characters
const MAX_HOSTNAME_LEN: usize = 253;
// RFC 1035: Maximum label length is 63 characters
const MAX_LABEL_LEN: usize = 63;

// DNS record type values (RFC 1035 + extensions)
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
const TYPE_AXFR: u16 = 252;
const TYPE_IXFR: u16 = 251;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_PTR: u16 = 12;
const TYPE_CNAME: u16 = 5;
const TYPE_NS: u16 = 2;
const TYPE_SOA: u16 = 6;

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

impl ResponseCode {
    /// Create from raw 4-bit value
    pub fn from_u16(value: u16) -> Self {
        match value & FLAG_RCODE_MASK {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NxDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            _ => ResponseCode::ServFail, // Treat unknown as server failure
        }
    }
}

/// DNS record types we care about
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    A,
    AAAA,
    ANY,
    AXFR,
    IXFR,
    MX,
    TXT,
    PTR,
    CNAME,
    NS,
    SOA,
    Other(u16),
}

impl RecordType {
    /// Create from raw type value
    pub fn from_u16(value: u16) -> Self {
        match value {
            TYPE_A => RecordType::A,
            TYPE_AAAA => RecordType::AAAA,
            TYPE_ANY => RecordType::ANY,
            TYPE_AXFR => RecordType::AXFR,
            TYPE_IXFR => RecordType::IXFR,
            TYPE_MX => RecordType::MX,
            TYPE_TXT => RecordType::TXT,
            TYPE_PTR => RecordType::PTR,
            TYPE_CNAME => RecordType::CNAME,
            TYPE_NS => RecordType::NS,
            TYPE_SOA => RecordType::SOA,
            other => RecordType::Other(other),
        }
    }

    /// Convert to raw type value
    #[allow(dead_code)]
    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => TYPE_A,
            RecordType::AAAA => TYPE_AAAA,
            RecordType::ANY => TYPE_ANY,
            RecordType::AXFR => TYPE_AXFR,
            RecordType::IXFR => TYPE_IXFR,
            RecordType::MX => TYPE_MX,
            RecordType::TXT => TYPE_TXT,
            RecordType::PTR => TYPE_PTR,
            RecordType::CNAME => TYPE_CNAME,
            RecordType::NS => TYPE_NS,
            RecordType::SOA => TYPE_SOA,
            RecordType::Other(v) => v,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::ANY => write!(f, "ANY"),
            RecordType::AXFR => write!(f, "AXFR"),
            RecordType::IXFR => write!(f, "IXFR"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::NS => write!(f, "NS"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::Other(v) => write!(f, "TYPE{}", v),
        }
    }
}

/// Parsed DNS query (read-only view into bytes)
#[derive(Debug)]
pub struct DnsQuery {
    id: u16,
    qname: String,
    qtype: RecordType,
    #[allow(dead_code)] // May be useful for future extensions
    qname_end: usize, // Position after QNAME+QTYPE+QCLASS
}

impl DnsQuery {
    /// Parse a DNS query from raw bytes
    pub fn parse(buf: &[u8]) -> Result<DnsQuery, &'static str> {
        if buf.len() < HEADER_SIZE {
            return Err("Packet too short for DNS header");
        }

        // Parse header
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

        // Check this is a query (QR bit = 0)
        if flags & FLAG_QR != 0 {
            return Err("Not a query (QR bit set)");
        }

        // Must have at least one question
        if qdcount == 0 {
            return Err("No question section in query");
        }

        // Parse the first question
        let (qname, qname_end_pos) = parse_name(buf, HEADER_SIZE)?;

        // Need at least 4 more bytes for QTYPE and QCLASS
        if buf.len() < qname_end_pos + 4 {
            return Err("Packet too short for question");
        }

        let qtype_raw = u16::from_be_bytes([buf[qname_end_pos], buf[qname_end_pos + 1]]);
        let qtype = RecordType::from_u16(qtype_raw);

        // Skip QCLASS (2 bytes) to get the end position
        let qname_end = qname_end_pos + 4;

        Ok(DnsQuery {
            id,
            qname,
            qtype,
            qname_end,
        })
    }

    /// Get query ID
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Get query name (domain)
    pub fn name(&self) -> &str {
        &self.qname
    }

    /// Get query type
    pub fn query_type(&self) -> RecordType {
        self.qtype
    }

    /// Check if query type should be blocked
    #[allow(dead_code)]
    pub fn is_blocked_type(&self, block_any: bool, block_xfer: bool) -> bool {
        if block_any && self.qtype == RecordType::ANY {
            return true;
        }
        if block_xfer && (self.qtype == RecordType::AXFR || self.qtype == RecordType::IXFR) {
            return true;
        }
        false
    }
}

/// Parsed DNS response (for caching and validation)
#[derive(Debug)]
pub struct DnsResponse<'a> {
    buf: &'a [u8],
    id: u16,
    rcode: ResponseCode,
    ancount: u16,
}

impl<'a> DnsResponse<'a> {
    /// Parse a DNS response from raw bytes
    pub fn parse(buf: &'a [u8]) -> Result<DnsResponse<'a>, &'static str> {
        if buf.len() < HEADER_SIZE {
            return Err("Packet too short for DNS header");
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);

        // Check this is a response (QR bit = 1)
        if flags & FLAG_QR == 0 {
            return Err("Not a response (QR bit not set)");
        }

        let rcode = ResponseCode::from_u16(flags);

        Ok(DnsResponse {
            buf,
            id,
            rcode,
            ancount,
        })
    }

    /// Get response ID
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Get response code
    pub fn response_code(&self) -> ResponseCode {
        self.rcode
    }

    /// Get answer count
    pub fn answer_count(&self) -> u16 {
        self.ancount
    }

    /// Find minimum TTL in answer section (for caching)
    pub fn min_ttl(&self) -> u32 {
        // Skip header
        let mut pos = HEADER_SIZE;
        let buf = self.buf;

        // Get counts
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

        if ancount == 0 {
            return 60; // Default TTL if no answers
        }

        // Skip question section
        for _ in 0..qdcount {
            if let Some(new_pos) = skip_name(buf, pos) {
                pos = new_pos + 4; // Skip QTYPE and QCLASS
            } else {
                return 60;
            }
        }

        // Find min TTL in answer section
        let mut min_ttl: u32 = u32::MAX;

        for _ in 0..ancount {
            // Skip name
            if let Some(new_pos) = skip_name(buf, pos) {
                pos = new_pos;
            } else {
                break;
            }

            // Need at least 10 bytes: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
            if pos + 10 > buf.len() {
                break;
            }

            // Skip TYPE (2) and CLASS (2), read TTL (4)
            let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
            min_ttl = min_ttl.min(ttl);

            // Read RDLENGTH and skip RDATA
            let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
            pos = pos + 10 + rdlength;

            if pos > buf.len() {
                break;
            }
        }

        if min_ttl == u32::MAX {
            60 // Default if we couldn't parse any TTLs
        } else {
            min_ttl
        }
    }
}

/// Create an error response from a query
///
/// Takes the original query bytes and returns a response with the specified error code.
pub fn create_error_response(query_buf: &[u8], rcode: ResponseCode) -> Option<Vec<u8>> {
    if query_buf.len() < HEADER_SIZE {
        return None;
    }

    let mut response = query_buf.to_vec();

    // Set QR bit (response) and RCODE
    let mut flags = u16::from_be_bytes([response[2], response[3]]);
    flags |= FLAG_QR; // Set QR bit (this is a response)
    flags = (flags & !FLAG_RCODE_MASK) | (rcode as u16); // Set RCODE

    response[2] = (flags >> 8) as u8;
    response[3] = flags as u8;

    // Clear answer, authority, and additional counts
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;

    Some(response)
}

/// Parse a DNS name from the buffer, handling compression pointers
fn parse_name(buf: &[u8], start: usize) -> Result<(String, usize), &'static str> {
    let mut name_parts = Vec::new();
    let mut pos = start;
    let mut followed_pointer = false;
    let mut end_pos = 0;
    let mut total_len: usize = 0; // Track total hostname length

    loop {
        if pos >= buf.len() {
            return Err("Name extends beyond packet");
        }

        let len = buf[pos] as usize;

        if len == 0 {
            // End of name
            if !followed_pointer {
                end_pos = pos + 1;
            }
            break;
        }

        // Check for compression pointer (top 2 bits = 11)
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err("Compression pointer extends beyond packet");
            }
            if !followed_pointer {
                end_pos = pos + 2;
            }
            // Follow the pointer
            let offset = ((len & 0x3F) << 8) | (buf[pos + 1] as usize);
            if offset >= pos {
                return Err("Forward compression pointer (loop protection)");
            }
            pos = offset;
            followed_pointer = true;
            continue;
        }

        // RFC 1035: Label length must not exceed 63 octets
        if len > MAX_LABEL_LEN {
            return Err("Label exceeds maximum length (63)");
        }

        // Regular label
        pos += 1;
        if pos + len > buf.len() {
            return Err("Label extends beyond packet");
        }

        // Track total length (label + dot separator)
        total_len += len + 1; // +1 for the dot
        if total_len > MAX_HOSTNAME_LEN {
            return Err("Hostname exceeds maximum length (253)");
        }

        // Convert label to string
        let label = std::str::from_utf8(&buf[pos..pos + len])
            .map_err(|_| "Invalid UTF-8 in label")?
            .to_string();
        name_parts.push(label);
        pos += len;
    }

    let name = if name_parts.is_empty() {
        ".".to_string()
    } else {
        name_parts.join(".") + "."
    };

    Ok((name, end_pos))
}

/// Skip over a DNS name (for traversing answer section)
fn skip_name(buf: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;

    loop {
        if pos >= buf.len() {
            return None;
        }

        let len = buf[pos] as usize;

        if len == 0 {
            // End of name
            return Some(pos + 1);
        }

        // Check for compression pointer
        if len & 0xC0 == 0xC0 {
            // Pointer is 2 bytes, name ends here
            return Some(pos + 2);
        }

        // Regular label - skip it
        pos += 1 + len;
    }
}

// ==================== Helper for building DNS packets (tests) ====================

/// DNS packet builder for testing
#[cfg(test)]
pub mod builder {
    use super::*;

    /// Build a DNS query packet
    pub fn build_query(domain: &str, qtype: RecordType, id: u16) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);

        // Header
        buf.extend_from_slice(&id.to_be_bytes()); // ID
        buf.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1 (recursion desired)
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Question section - QNAME
        encode_name(&mut buf, domain);

        // QTYPE
        buf.extend_from_slice(&qtype.to_u16().to_be_bytes());
        // QCLASS = IN (1)
        buf.extend_from_slice(&[0x00, 0x01]);

        buf
    }

    /// Build a DNS response packet with one A record
    pub fn build_response(
        domain: &str,
        ip: &str,
        id: u16,
        ttl: u32,
        rcode: ResponseCode,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        // Header
        buf.extend_from_slice(&id.to_be_bytes()); // ID
        buf.extend_from_slice(&[0x81, rcode as u8]); // Flags: QR=1, RD=1, RA=1, RCODE
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        let ancount: u16 = if rcode == ResponseCode::NoError { 1 } else { 0 };
        buf.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Question section
        encode_name(&mut buf, domain);
        buf.extend_from_slice(&RecordType::A.to_u16().to_be_bytes()); // QTYPE = A
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        // Answer section (only if success)
        if rcode == ResponseCode::NoError {
            encode_name(&mut buf, domain);
            buf.extend_from_slice(&RecordType::A.to_u16().to_be_bytes()); // TYPE = A
            buf.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
            buf.extend_from_slice(&ttl.to_be_bytes()); // TTL
            buf.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4

            // RDATA - IPv4 address
            let parts: Vec<u8> = ip
                .split('.')
                .map(|s| s.parse::<u8>().unwrap_or(0))
                .collect();
            if parts.len() == 4 {
                buf.extend_from_slice(&parts);
            } else {
                buf.extend_from_slice(&[0, 0, 0, 0]);
            }
        }

        buf
    }

    /// Encode a domain name in DNS wire format
    fn encode_name(buf: &mut Vec<u8>, domain: &str) {
        let domain = domain.trim_end_matches('.');
        for label in domain.split('.') {
            if label.is_empty() {
                continue;
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // Terminating zero
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        let query = builder::build_query("example.com", RecordType::A, 0x1234);
        let parsed = DnsQuery::parse(&query).unwrap();

        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.name(), "example.com.");
        assert_eq!(parsed.query_type(), RecordType::A);
    }

    #[test]
    fn test_parse_any_query() {
        let query = builder::build_query("test.org", RecordType::ANY, 0xABCD);
        let parsed = DnsQuery::parse(&query).unwrap();

        assert_eq!(parsed.query_type(), RecordType::ANY);
        assert!(parsed.is_blocked_type(true, false));
        assert!(!parsed.is_blocked_type(false, true));
    }

    #[test]
    fn test_parse_axfr_query() {
        let query = builder::build_query("zone.example", RecordType::AXFR, 0x5678);
        let parsed = DnsQuery::parse(&query).unwrap();

        assert_eq!(parsed.query_type(), RecordType::AXFR);
        assert!(parsed.is_blocked_type(false, true));
        assert!(!parsed.is_blocked_type(true, false));
    }

    #[test]
    fn test_parse_ixfr_query() {
        let query = builder::build_query("zone.example", RecordType::IXFR, 0x9ABC);
        let parsed = DnsQuery::parse(&query).unwrap();

        assert_eq!(parsed.query_type(), RecordType::IXFR);
        assert!(parsed.is_blocked_type(false, true));
    }

    #[test]
    fn test_parse_too_short() {
        let short = vec![0u8; 5];
        assert!(DnsQuery::parse(&short).is_err());
    }

    #[test]
    fn test_parse_response() {
        let response = builder::build_response(
            "example.com",
            "93.184.216.34",
            0x1234,
            300,
            ResponseCode::NoError,
        );
        let parsed = DnsResponse::parse(&response).unwrap();

        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.response_code(), ResponseCode::NoError);
        assert_eq!(parsed.answer_count(), 1);
    }

    #[test]
    fn test_response_min_ttl() {
        let response =
            builder::build_response("example.com", "1.2.3.4", 0x1234, 600, ResponseCode::NoError);
        let parsed = DnsResponse::parse(&response).unwrap();

        assert_eq!(parsed.min_ttl(), 600);
    }

    #[test]
    fn test_create_error_response_refused() {
        let query = builder::build_query("example.com", RecordType::A, 0x5678);
        let response = create_error_response(&query, ResponseCode::Refused).unwrap();

        let parsed = DnsResponse::parse(&response).unwrap();
        assert_eq!(parsed.id(), 0x5678);
        assert_eq!(parsed.response_code(), ResponseCode::Refused);
        assert_eq!(parsed.answer_count(), 0);
    }

    #[test]
    fn test_create_error_response_servfail() {
        let query = builder::build_query("example.com", RecordType::A, 0xBEEF);
        let response = create_error_response(&query, ResponseCode::ServFail).unwrap();

        let parsed = DnsResponse::parse(&response).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::ServFail);
    }

    #[test]
    fn test_create_error_response_invalid() {
        let short = vec![0u8; 5];
        assert!(create_error_response(&short, ResponseCode::Refused).is_none());
    }

    #[test]
    fn test_record_type_display() {
        assert_eq!(format!("{}", RecordType::A), "A");
        assert_eq!(format!("{}", RecordType::AAAA), "AAAA");
        assert_eq!(format!("{}", RecordType::MX), "MX");
        assert_eq!(format!("{}", RecordType::Other(99)), "TYPE99");
    }

    #[test]
    fn test_record_type_roundtrip() {
        for rt in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::ANY,
            RecordType::AXFR,
            RecordType::IXFR,
            RecordType::MX,
            RecordType::TXT,
            RecordType::PTR,
            RecordType::CNAME,
        ] {
            assert_eq!(RecordType::from_u16(rt.to_u16()), rt);
        }
    }

    #[test]
    fn test_parse_response_is_not_query() {
        let query = builder::build_query("example.com", RecordType::A, 0x1234);
        assert!(DnsResponse::parse(&query).is_err());
    }

    #[test]
    fn test_query_no_question_section() {
        // Build a packet with QDCOUNT = 0
        let mut buf = vec![0u8; 12];
        buf[0] = 0x12;
        buf[1] = 0x34; // ID
        buf[2] = 0x00;
        buf[3] = 0x00; // Flags (query)
        buf[4] = 0x00;
        buf[5] = 0x00; // QDCOUNT = 0

        assert!(DnsQuery::parse(&buf).is_err());
    }

    #[test]
    fn test_subdomain_query() {
        let query = builder::build_query("sub.domain.example.com", RecordType::A, 0x1111);
        let parsed = DnsQuery::parse(&query).unwrap();

        assert_eq!(parsed.name(), "sub.domain.example.com.");
    }

    #[test]
    fn test_root_query() {
        // Query for "." (root)
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x01]); // ID = 1
        buf.extend_from_slice(&[0x00, 0x00]); // Flags
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        buf.push(0); // Root name (just terminator)
        buf.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let parsed = DnsQuery::parse(&buf).unwrap();
        assert_eq!(parsed.name(), ".");
    }

    #[test]
    fn test_hostname_too_long() {
        // Build a query with hostname > 253 characters
        // Each label is 63 chars (max), need 4+ labels to exceed 253
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]); // ID
        buf.extend_from_slice(&[0x00, 0x00]); // Flags (query)
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Add 5 labels of 63 chars each = 315 chars (exceeds 253)
        for _ in 0..5 {
            buf.push(63); // Label length
            buf.extend_from_slice(&[b'a'; 63]); // 63 'a' characters
        }
        buf.push(0); // End of name
        buf.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let result = DnsQuery::parse(&buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Hostname exceeds maximum length (253)");
    }

    #[test]
    fn test_label_too_long() {
        // Build a query with a single label > 63 characters
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]); // ID
        buf.extend_from_slice(&[0x00, 0x00]); // Flags (query)
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Label with 64 chars (exceeds 63 max)
        buf.push(64); // Label length (invalid)
        buf.extend_from_slice(&[b'x'; 64]);
        buf.push(0); // End of name
        buf.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let result = DnsQuery::parse(&buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Label exceeds maximum length (63)");
    }

    #[test]
    fn test_hostname_at_max_length() {
        // Build a query with hostname exactly at 253 characters
        // Each label adds: len + 1 (for the dot)
        // 3 labels of 63 chars: (63+1)*3 = 192
        // 1 label of 60 chars: 60+1 = 61
        // Total: 192 + 61 = 253
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]); // ID
        buf.extend_from_slice(&[0x00, 0x00]); // Flags (query)
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // 3 labels of 63 chars each = 192 chars with dots
        for _ in 0..3 {
            buf.push(63);
            buf.extend_from_slice(&[b'a'; 63]);
        }
        // 1 label of 60 chars = 61 chars with dot (total: 253)
        buf.push(60);
        buf.extend_from_slice(&[b'b'; 60]);
        buf.push(0); // End of name
        buf.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let result = DnsQuery::parse(&buf);
        assert!(result.is_ok(), "253-char hostname should be valid");
    }

    #[test]
    fn test_response_no_answers_default_ttl() {
        // Build a response with ANCOUNT = 0
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]); // ID
        buf.extend_from_slice(&[0x81, 0x00]); // Flags: QR=1, RCODE=0
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
                                              // Question section
        buf.push(7);
        buf.extend_from_slice(b"example");
        buf.push(3);
        buf.extend_from_slice(b"com");
        buf.push(0);
        buf.extend_from_slice(&[0x00, 0x01]); // QTYPE
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS

        let parsed = DnsResponse::parse(&buf).unwrap();
        assert_eq!(parsed.answer_count(), 0);
        assert_eq!(parsed.min_ttl(), 60); // Default when no answers
    }
}
