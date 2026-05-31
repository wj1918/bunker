//! DNS query validation and error response generation.

use crate::config::DnsSecurityConfig;
use crate::dns::wire::{create_error_response, DnsQuery, RecordType, ResponseCode};

/// Validate a DNS query and return error message if invalid
pub fn validate_dns_query(
    query: &DnsQuery,
    security: &DnsSecurityConfig,
) -> Result<(), &'static str> {
    let query_type = query.query_type();

    // Block ANY queries (amplification risk)
    if security.block_any_queries && query_type == RecordType::ANY {
        return Err("ANY queries blocked (amplification risk)");
    }

    // Block zone transfers
    if security.block_zone_transfers
        && (query_type == RecordType::AXFR || query_type == RecordType::IXFR)
    {
        return Err("Zone transfer queries blocked");
    }

    Ok(())
}

/// Create a DNS error response (REFUSED, SERVFAIL, etc.)
pub fn create_dns_error_response(query_buf: &[u8], rcode: ResponseCode) -> Option<Vec<u8>> {
    create_error_response(query_buf, rcode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::builder;

    fn default_security() -> DnsSecurityConfig {
        DnsSecurityConfig::default()
    }

    #[test]
    fn test_validate_dns_query_a_record() {
        let query_bytes = builder::build_query("example.com", RecordType::A, 1234);
        let query = DnsQuery::parse(&query_bytes).unwrap();
        let security = default_security();
        assert!(validate_dns_query(&query, &security).is_ok());
    }

    #[test]
    fn test_validate_dns_query_aaaa_record() {
        let query_bytes = builder::build_query("example.com", RecordType::AAAA, 1234);
        let query = DnsQuery::parse(&query_bytes).unwrap();
        let security = default_security();
        assert!(validate_dns_query(&query, &security).is_ok());
    }

    #[test]
    fn test_validate_dns_query_any_blocked() {
        let query_bytes = builder::build_query("example.com", RecordType::ANY, 1234);
        let query = DnsQuery::parse(&query_bytes).unwrap();
        let security = default_security();
        assert!(validate_dns_query(&query, &security).is_err());
    }

    #[test]
    fn test_validate_dns_query_any_allowed() {
        let query_bytes = builder::build_query("example.com", RecordType::ANY, 1234);
        let query = DnsQuery::parse(&query_bytes).unwrap();
        let security = DnsSecurityConfig {
            block_any_queries: false,
            ..default_security()
        };
        assert!(validate_dns_query(&query, &security).is_ok());
    }

    #[test]
    fn test_validate_dns_query_axfr_blocked() {
        let query_bytes = builder::build_query("example.com", RecordType::AXFR, 1234);
        let query = DnsQuery::parse(&query_bytes).unwrap();
        let security = default_security();
        assert!(validate_dns_query(&query, &security).is_err());
    }

    #[test]
    fn test_validate_dns_query_ixfr_blocked() {
        let query_bytes = builder::build_query("example.com", RecordType::IXFR, 1234);
        let query = DnsQuery::parse(&query_bytes).unwrap();
        let security = default_security();
        assert!(validate_dns_query(&query, &security).is_err());
    }

    #[test]
    fn test_validate_dns_query_zone_transfer_allowed() {
        let query_bytes = builder::build_query("example.com", RecordType::AXFR, 1234);
        let query = DnsQuery::parse(&query_bytes).unwrap();
        let security = DnsSecurityConfig {
            block_zone_transfers: false,
            ..default_security()
        };
        assert!(validate_dns_query(&query, &security).is_ok());
    }

    #[test]
    fn test_create_error_response_refused() {
        let query_bytes = builder::build_query("example.com", RecordType::A, 1234);

        let response = create_dns_error_response(&query_bytes, ResponseCode::Refused);
        assert!(response.is_some());

        let response_bytes = response.unwrap();
        let parsed = crate::dns::wire::DnsResponse::parse(&response_bytes).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::Refused);
        assert_eq!(parsed.id(), 1234);
    }

    #[test]
    fn test_create_error_response_servfail() {
        let query_bytes = builder::build_query("example.com", RecordType::A, 1234);

        let response = create_dns_error_response(&query_bytes, ResponseCode::ServFail);
        assert!(response.is_some());

        let response_bytes = response.unwrap();
        let parsed = crate::dns::wire::DnsResponse::parse(&response_bytes).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::ServFail);
    }

    #[test]
    fn test_create_error_response_invalid_query() {
        let invalid_bytes = vec![0, 1, 2, 3]; // Not a valid DNS message
        let response = create_dns_error_response(&invalid_bytes, ResponseCode::Refused);
        assert!(response.is_none());
    }
}
