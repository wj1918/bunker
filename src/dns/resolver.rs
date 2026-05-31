//! DNS resolver trait with generics for zero-cost abstraction.

use crate::config::DnsSecurityConfig;
use crate::dns::wire::DnsQuery;
use crate::error::DnsError;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// DNS header size in octets (RFC 1035 §4.1.1).
const DNS_HEADER_SIZE: usize = 12;

/// Validate an upstream UDP DNS response against the query we sent.
///
/// Beyond the source-address check (already done by the caller), an honest
/// response from our upstream MUST:
///   - echo our transaction ID in the header (RFC 1035 §4.1.1)
///   - echo our question section verbatim (same QNAME / QTYPE / QCLASS)
///
/// Without these, a spoofed packet that races to the ephemeral socket can
/// inject any IP — particularly dangerous because the source check alone is
/// gated on `verify_upstream_source` and can be bypassed by an on-path
/// attacker that can spoof the upstream's source IP. Treat both mismatch
/// classes as spoofing rather than parse errors.
fn validate_upstream_response(query_buf: &[u8], response_buf: &[u8]) -> Result<(), DnsError> {
    if response_buf.len() < DNS_HEADER_SIZE {
        return Err(DnsError::SpoofingDetected);
    }
    // ID check — first two bytes of the header, big-endian.
    if response_buf[0..2] != query_buf[0..2] {
        return Err(DnsError::SpoofingDetected);
    }
    // QNAME / QTYPE / QCLASS echo. Parse the query (we built it, so this
    // should always succeed) to find the end of its question section, then
    // compare byte-for-byte. The response's question is at the same offset
    // and cannot use DNS compression (nothing precedes it to point at), so
    // an exact byte-equal compare is correct.
    let query = DnsQuery::parse(query_buf).map_err(|e| DnsError::ParseError(e.to_string()))?;
    let q_end = query.qname_end();
    if response_buf.len() < q_end {
        return Err(DnsError::SpoofingDetected);
    }
    if response_buf[DNS_HEADER_SIZE..q_end] != query_buf[DNS_HEADER_SIZE..q_end] {
        return Err(DnsError::SpoofingDetected);
    }
    Ok(())
}

/// DNS resolver trait using generics for zero-cost abstraction.
///
/// This trait allows for different resolver implementations:
/// - UdpDnsResolver: Default UDP-based resolver
/// - Can be extended for DoH, DoT, etc.
pub trait DnsResolver: Send + Sync {
    /// Resolve a DNS query and return the response bytes
    fn resolve(
        &self,
        query: &[u8],
        upstream: SocketAddr,
        timeout: Duration,
        enable_logging: bool,
    ) -> impl Future<Output = Result<Vec<u8>, DnsError>> + Send;
}

/// UDP-based DNS resolver implementation
pub struct UdpDnsResolver {
    security: DnsSecurityConfig,
}

impl UdpDnsResolver {
    pub fn new(security: DnsSecurityConfig) -> Self {
        Self { security }
    }
}

impl DnsResolver for UdpDnsResolver {
    async fn resolve(
        &self,
        query: &[u8],
        upstream: SocketAddr,
        timeout: Duration,
        enable_logging: bool,
    ) -> Result<Vec<u8>, DnsError> {
        // Bind to appropriate address family based on upstream (IPv4 or IPv6)
        let bind_addr = if upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| DnsError::ParseError(e.to_string()))?;

        socket
            .send_to(query, upstream)
            .await
            .map_err(|e| DnsError::ParseError(e.to_string()))?;

        let mut response_buf = vec![0u8; 512];
        let result = tokio::time::timeout(timeout, socket.recv_from(&mut response_buf)).await;

        match result {
            Ok(Ok((len, from))) => {
                // Verify response comes from expected upstream (anti-spoofing)
                if self.security.verify_upstream_source && from != upstream {
                    if enable_logging {
                        warn!(
                            from = %from,
                            expected = %upstream,
                            "DNS response from unexpected source (spoofing detected)"
                        );
                    }
                    return Err(DnsError::SpoofingDetected);
                }
                response_buf.truncate(len);
                // Transaction-ID + question-section echo checks. These run
                // unconditionally — the spoofing surface they cover (off-path
                // ID guess; on-path attacker who spoofs the upstream's source
                // IP) is real, and the checks cost only a u16 compare plus a
                // bounded byte-equal on the question.
                if let Err(e) = validate_upstream_response(query, &response_buf) {
                    if enable_logging {
                        warn!(
                            from = %from,
                            upstream = %upstream,
                            error = %e,
                            "DNS response failed ID/QNAME verification (spoofing)"
                        );
                    }
                    return Err(e);
                }
                Ok(response_buf)
            }
            Ok(Err(e)) => Err(DnsError::ParseError(e.to_string())),
            Err(_) => Err(DnsError::Timeout),
        }
    }
}

/// Handle DNS query with failover support using a generic resolver
#[allow(dead_code)]
pub async fn handle_dns_query_with_resolver<R: DnsResolver>(
    resolver: &R,
    query_buf: &[u8],
    upstreams: &[SocketAddr],
    timeout: Duration,
    max_retries: u32,
    enable_logging: bool,
) -> Result<Vec<u8>, DnsError> {
    let total_attempts = 1 + max_retries;

    for attempt in 0..total_attempts {
        if attempt > 0 && enable_logging {
            debug!(attempt = attempt, max_retries = max_retries, "DNS retry");
        }

        for (idx, upstream) in upstreams.iter().enumerate() {
            if enable_logging {
                debug!(
                    upstream = %upstream,
                    index = idx + 1,
                    total = upstreams.len(),
                    "DNS trying upstream"
                );
            }

            match resolver
                .resolve(query_buf, *upstream, timeout, enable_logging)
                .await
            {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if enable_logging {
                        warn!(upstream = %upstream, error = %e, "DNS upstream failed");
                    }
                    // Continue to next upstream
                }
            }
        }
    }

    Err(DnsError::UpstreamFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Mock resolver for testing
    struct MockDnsResolver {
        call_count: Arc<AtomicUsize>,
        fail_count: usize,
        response: Vec<u8>,
    }

    impl MockDnsResolver {
        fn new(fail_count: usize, response: Vec<u8>) -> Self {
            Self {
                call_count: Arc::new(AtomicUsize::new(0)),
                fail_count,
                response,
            }
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl DnsResolver for MockDnsResolver {
        async fn resolve(
            &self,
            _query: &[u8],
            _upstream: SocketAddr,
            _timeout: Duration,
            _enable_logging: bool,
        ) -> Result<Vec<u8>, DnsError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            if count < self.fail_count {
                Err(DnsError::Timeout)
            } else {
                Ok(self.response.clone())
            }
        }
    }

    #[tokio::test]
    async fn test_mock_resolver_success() {
        let resolver = MockDnsResolver::new(0, vec![1, 2, 3, 4]);
        let upstream: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let result = resolver
            .resolve(&[0, 1], upstream, Duration::from_secs(1), false)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_mock_resolver_failure() {
        let resolver = MockDnsResolver::new(5, vec![1, 2, 3, 4]);
        let upstream: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let result = resolver
            .resolve(&[0, 1], upstream, Duration::from_secs(1), false)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_failover_tries_multiple_upstreams() {
        let resolver = MockDnsResolver::new(1, vec![1, 2, 3, 4]);
        let upstreams: Vec<SocketAddr> =
            vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()];

        let result = handle_dns_query_with_resolver(
            &resolver,
            &[0, 1],
            &upstreams,
            Duration::from_secs(1),
            0,
            false,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(resolver.calls(), 2); // First failed, second succeeded
    }

    #[tokio::test]
    async fn test_failover_with_retries() {
        let resolver = MockDnsResolver::new(3, vec![1, 2, 3, 4]);
        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];

        let result = handle_dns_query_with_resolver(
            &resolver,
            &[0, 1],
            &upstreams,
            Duration::from_secs(1),
            3, // 4 total attempts
            false,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(resolver.calls(), 4); // 3 failures + 1 success
    }

    // ---------- validate_upstream_response (anti-spoofing) ----------

    use crate::dns::wire::{builder, RecordType, ResponseCode};

    #[test]
    fn validate_accepts_matching_id_and_qname() {
        let query = builder::build_query("example.com", RecordType::A, 0xABCD);
        let resp = builder::build_response(
            "example.com",
            "93.184.216.34",
            0xABCD,
            300,
            ResponseCode::NoError,
        );
        assert!(validate_upstream_response(&query, &resp).is_ok());
    }

    #[test]
    fn validate_rejects_mismatched_id() {
        let query = builder::build_query("example.com", RecordType::A, 0xABCD);
        // Same QNAME but a different transaction ID — spoofed off-path response.
        let resp = builder::build_response(
            "example.com",
            "93.184.216.34",
            0x1234,
            300,
            ResponseCode::NoError,
        );
        assert!(matches!(
            validate_upstream_response(&query, &resp),
            Err(DnsError::SpoofingDetected)
        ));
    }

    #[test]
    fn validate_rejects_mismatched_qname() {
        let query = builder::build_query("good.com", RecordType::A, 0xABCD);
        // Echoed ID but the response's question is for a different name —
        // classic cache-poisoning vector.
        let resp =
            builder::build_response("evil.com", "6.6.6.6", 0xABCD, 300, ResponseCode::NoError);
        assert!(matches!(
            validate_upstream_response(&query, &resp),
            Err(DnsError::SpoofingDetected)
        ));
    }

    #[test]
    fn validate_rejects_truncated_response() {
        let query = builder::build_query("example.com", RecordType::A, 0xABCD);
        // Shorter than the DNS header — clearly bogus.
        let truncated = vec![0xAB, 0xCD, 0x81, 0x80];
        assert!(matches!(
            validate_upstream_response(&query, &truncated),
            Err(DnsError::SpoofingDetected)
        ));
    }

    #[tokio::test]
    async fn test_all_upstreams_fail() {
        let resolver = MockDnsResolver::new(10, vec![1, 2, 3, 4]);
        let upstreams: Vec<SocketAddr> =
            vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()];

        let result = handle_dns_query_with_resolver(
            &resolver,
            &[0, 1],
            &upstreams,
            Duration::from_secs(1),
            0,
            false,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DnsError::UpstreamFailed));
    }
}
