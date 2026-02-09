//! DNS resolver trait with generics for zero-cost abstraction.

use crate::config::DnsSecurityConfig;
use crate::error::DnsError;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

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
        let upstreams: Vec<SocketAddr> = vec![
            "8.8.8.8:53".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
        ];

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

    #[tokio::test]
    async fn test_all_upstreams_fail() {
        let resolver = MockDnsResolver::new(10, vec![1, 2, 3, 4]);
        let upstreams: Vec<SocketAddr> = vec![
            "8.8.8.8:53".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
        ];

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
