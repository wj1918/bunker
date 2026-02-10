//! DNS server implementation with caching, rate limiting, and failover.

use crate::config::{DnsCacheConfig, DnsFailoverConfig, DnsSecurityConfig, LoggingConfig};
use crate::dns::cache::DnsCache;
use crate::dns::resolver::{DnsResolver, UdpDnsResolver};
use crate::dns::validation::{create_dns_error_response, validate_dns_query};
use crate::dns::wire::{DnsQuery, DnsResponse, ResponseCode};
use crate::security::{is_source_ip_allowed, DnsRateLimiter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Run the DNS server with caching and failover support
pub async fn run_dns_server(
    listen_addr: SocketAddr,
    upstreams: Vec<String>,
    security: DnsSecurityConfig,
    cache_config: DnsCacheConfig,
    failover_config: DnsFailoverConfig,
    logging: LoggingConfig,
    allowed_source_ips: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let enable_logging = logging.log_requests;
    let has_ip_allowlist = !allowed_source_ips.is_empty();
    let socket = Arc::new(UdpSocket::bind(listen_addr).await?);

    // Parse all upstream addresses
    let mut upstream_addrs = Vec::new();
    for upstream in &upstreams {
        let addr: SocketAddr = upstream.parse()?;
        upstream_addrs.push(addr);
    }
    let upstream_addrs = Arc::new(upstream_addrs);

    let rate_limiter = Arc::new(Mutex::new(DnsRateLimiter::new(security.clone())));
    let cache = Arc::new(Mutex::new(DnsCache::new(cache_config.clone())));
    let failover_config = Arc::new(failover_config);
    let security = Arc::new(security);

    // Create the resolver with generics (zero-cost abstraction)
    let resolver = Arc::new(UdpDnsResolver::new((*security).clone()));

    if enable_logging {
        info!(
            listen = %listen_addr,
            upstreams = ?*upstream_addrs,
            rate_limit = security.rate_limit_enabled,
            block_any = security.block_any_queries,
            block_zone_xfer = security.block_zone_transfers,
            cache_enabled = cache_config.enabled,
            cache_max_entries = cache_config.max_entries,
            "DNS server started"
        );
    }

    // Spawn cleanup task for rate limiter
    let rate_limiter_cleanup = Arc::clone(&rate_limiter);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            rate_limiter_cleanup.lock().await.cleanup();
        }
    });

    // Spawn cleanup task for DNS cache
    let cache_cleanup = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            cache_cleanup.lock().await.cleanup();
        }
    });

    loop {
        let mut buf = vec![0u8; 512];
        let (len, src) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);

        // Check source IP allowlist
        if has_ip_allowlist && !is_source_ip_allowed(&src.ip(), &allowed_source_ips) {
            // Silently drop - don't even send REFUSED to unauthorized IPs
            continue;
        }

        if enable_logging {
            debug!(bytes = len, client = %src, "DNS query received");
        }

        // Check rate limit
        {
            let mut limiter = rate_limiter.lock().await;
            if !limiter.is_allowed(src.ip()) {
                if enable_logging {
                    warn!(
                        client = %src.ip(),
                        max_qps = security.max_qps,
                        "DNS rate limit exceeded"
                    );
                }
                // Send REFUSED response
                if let Some(response) = create_dns_error_response(&buf, ResponseCode::Refused) {
                    let _ = socket.send_to(&response, src).await;
                }
                continue;
            }
        }

        let socket_clone = Arc::clone(&socket);
        let upstreams_clone = Arc::clone(&upstream_addrs);
        let security_clone = Arc::clone(&security);
        let cache_clone = Arc::clone(&cache);
        let failover_clone = Arc::clone(&failover_config);
        let resolver_clone = Arc::clone(&resolver);

        tokio::spawn(async move {
            match handle_dns_query(
                &*resolver_clone,
                &buf,
                src,
                &upstreams_clone,
                &security_clone,
                cache_clone,
                &failover_clone,
                enable_logging,
            )
            .await
            {
                Ok(response) => {
                    if enable_logging {
                        debug!(bytes = response.len(), client = %src, "DNS sending response");
                    }
                    if let Err(e) = socket_clone.send_to(&response, src).await {
                        if enable_logging {
                            error!(client = %src, error = %e, "DNS failed to send response");
                        }
                    } else if enable_logging {
                        debug!(client = %src, "DNS response sent");
                    }
                }
                Err(e) => {
                    if enable_logging {
                        error!(client = %src, error = %e, "DNS query handling failed");
                    }
                    // Try to send error response
                    if let Some(response) = create_dns_error_response(&buf, ResponseCode::ServFail)
                    {
                        let _ = socket_clone.send_to(&response, src).await;
                    }
                }
            }
        });
    }
}

/// Handle a DNS query with caching, validation, and failover.
/// Made public for testing with mock resolvers.
#[allow(clippy::too_many_arguments)]
pub async fn handle_dns_query<R: DnsResolver>(
    resolver: &R,
    query_buf: &[u8],
    client: SocketAddr,
    upstreams: &[SocketAddr],
    security: &DnsSecurityConfig,
    cache: Arc<Mutex<DnsCache>>,
    failover: &DnsFailoverConfig,
    enable_logging: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Parse the query
    let query = match DnsQuery::parse(query_buf) {
        Ok(q) => q,
        Err(e) => {
            if enable_logging {
                warn!(
                    client = %client,
                    error = %e,
                    bytes = query_buf.len(),
                    "DNS failed to parse query"
                );
            }
            return Err(format!("Failed to parse query: {}", e).into());
        }
    };

    let id = query.id();
    let query_name = query.name().to_string();
    let query_type = query.query_type();

    if enable_logging {
        info!(
            id = id,
            client = %client,
            name = %query_name,
            qtype = %query_type,
            "DNS query"
        );
    }

    // Validate query (block ANY, zone transfers)
    if let Err(reason) = validate_dns_query(&query, security) {
        if enable_logging {
            warn!(
                id = id,
                client = %client,
                reason = %reason,
                "DNS query blocked"
            );
        }
        return create_dns_error_response(query_buf, ResponseCode::Refused)
            .ok_or_else(|| "Failed to create error response".into());
    }

    // Check cache first
    {
        let cache_guard = cache.lock().await;
        if let Some(cached_response) = cache_guard.get(&query_name, query_type, id) {
            if enable_logging {
                debug!(
                    name = %query_name,
                    qtype = %query_type,
                    client = %client,
                    "DNS cache hit"
                );
            }
            return Ok(cached_response);
        }
    }

    // Try upstreams with failover using generic resolver
    let timeout_duration = Duration::from_millis(failover.timeout_ms);

    if enable_logging {
        debug!(
            upstreams = upstreams.len(),
            retries = failover.max_retries,
            "DNS cache miss, trying upstreams"
        );
    }

    // Use the generic resolver for failover
    match try_upstreams_with_resolver(
        resolver,
        query_buf,
        upstreams,
        timeout_duration,
        failover.max_retries,
        enable_logging,
    )
    .await
    {
        Ok(response_buf) => {
            // Success! Cache the response
            if let Ok(response) = DnsResponse::parse(&response_buf) {
                let answer_count = response.answer_count();
                if enable_logging {
                    debug!(
                        id = response.id(),
                        answers = answer_count,
                        "DNS response received"
                    );
                }

                // Only cache successful responses with answers
                if response.response_code() == ResponseCode::NoError && answer_count > 0 {
                    let min_ttl = response.min_ttl();

                    let mut cache_guard = cache.lock().await;
                    cache_guard.put(
                        &query_name,
                        query_type,
                        response_buf.clone(),
                        min_ttl as u64,
                    );
                    if enable_logging {
                        debug!(
                            name = %query_name,
                            qtype = %query_type,
                            ttl = min_ttl,
                            "DNS cached"
                        );
                    }
                }
            }
            Ok(response_buf)
        }
        Err(_) => {
            // All upstreams failed - try serve stale if enabled
            if failover.serve_stale {
                let cache_guard = cache.lock().await;
                if let Some(stale_response) = cache_guard.get_stale(&query_name, query_type, id) {
                    if enable_logging {
                        warn!(
                            name = %query_name,
                            qtype = %query_type,
                            "DNS serving stale cache (upstreams failed)"
                        );
                    }
                    return Ok(stale_response);
                }
            }

            if enable_logging {
                error!(
                    upstreams = upstreams.len(),
                    attempts = 1 + failover.max_retries,
                    "DNS all upstreams failed"
                );
            }
            Err("All upstreams failed".into())
        }
    }
}

/// Try upstream servers with failover logic.
/// Made public for testing with mock resolvers.
pub async fn try_upstreams_with_resolver<R: DnsResolver>(
    resolver: &R,
    query_buf: &[u8],
    upstreams: &[SocketAddr],
    timeout: Duration,
    max_retries: u32,
    enable_logging: bool,
) -> Result<Vec<u8>, ()> {
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
                }
            }
        }
    }

    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{builder, RecordType};
    use crate::error::DnsError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Mock DNS resolver for testing
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

        fn always_succeed(response: Vec<u8>) -> Self {
            Self::new(0, response)
        }

        fn always_fail() -> Self {
            Self::new(usize::MAX, vec![])
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

    fn test_security_config() -> DnsSecurityConfig {
        DnsSecurityConfig {
            rate_limit_enabled: false,
            max_qps: 100,
            block_any_queries: true,
            block_zone_transfers: true,
            verify_upstream_source: true,
            max_tracked_ips: 50000,
            ipv6_subnet_rate_limit: true,
        }
    }

    fn test_cache_config() -> DnsCacheConfig {
        DnsCacheConfig {
            enabled: true,
            max_entries: 1000,
            min_ttl_seconds: 60,
            max_ttl_seconds: 86400,
        }
    }

    fn test_failover_config() -> DnsFailoverConfig {
        DnsFailoverConfig {
            timeout_ms: 1000,
            max_retries: 1,
            serve_stale: true,
        }
    }

    /// Build a valid DNS query message
    fn build_dns_query(domain: &str, query_type: RecordType, id: u16) -> Vec<u8> {
        builder::build_query(domain, query_type, id)
    }

    /// Build an ANY query (should be blocked)
    fn build_any_query(domain: &str, id: u16) -> Vec<u8> {
        builder::build_query(domain, RecordType::ANY, id)
    }

    /// Build an AXFR query (should be blocked)
    fn build_axfr_query(domain: &str, id: u16) -> Vec<u8> {
        builder::build_query(domain, RecordType::AXFR, id)
    }

    /// Build a mock DNS response with one A record
    fn build_dns_response(domain: &str, ip: &str, id: u16, ttl: u32) -> Vec<u8> {
        builder::build_response(domain, ip, id, ttl, ResponseCode::NoError)
    }

    // ==================== try_upstreams_with_resolver tests ====================

    #[tokio::test]
    async fn test_try_upstreams_success_first_upstream() {
        let response = vec![1, 2, 3, 4];
        let resolver = MockDnsResolver::always_succeed(response.clone());
        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];

        let result = try_upstreams_with_resolver(
            &resolver,
            &[0, 1],
            &upstreams,
            Duration::from_secs(1),
            0,
            false,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), response);
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test]
    async fn test_try_upstreams_failover_to_second() {
        let response = vec![1, 2, 3, 4];
        let resolver = MockDnsResolver::new(1, response.clone()); // Fail once
        let upstreams: Vec<SocketAddr> =
            vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()];

        let result = try_upstreams_with_resolver(
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
    async fn test_try_upstreams_with_retries() {
        let response = vec![1, 2, 3, 4];
        let resolver = MockDnsResolver::new(2, response.clone()); // Fail twice
        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];

        let result = try_upstreams_with_resolver(
            &resolver,
            &[0, 1],
            &upstreams,
            Duration::from_secs(1),
            2, // 3 total attempts
            false,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(resolver.calls(), 3); // 2 failures + 1 success
    }

    #[tokio::test]
    async fn test_try_upstreams_all_fail() {
        let resolver = MockDnsResolver::always_fail();
        let upstreams: Vec<SocketAddr> =
            vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()];

        let result = try_upstreams_with_resolver(
            &resolver,
            &[0, 1],
            &upstreams,
            Duration::from_secs(1),
            1, // 2 total attempts
            false,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(resolver.calls(), 4); // 2 upstreams * 2 attempts
    }

    // ==================== handle_dns_query tests ====================

    #[tokio::test]
    async fn test_handle_query_success() {
        let query_id = 0x1234;
        let query = build_dns_query("example.com", RecordType::A, query_id);
        let response = build_dns_response("example.com", "93.184.216.34", query_id, 300);
        let resolver = MockDnsResolver::always_succeed(response.clone());

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover, false,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test]
    async fn test_handle_query_cache_hit() {
        let query_id = 0x1234;
        let query = build_dns_query("cached.example.com", RecordType::A, query_id);
        let response = build_dns_response("cached.example.com", "1.2.3.4", query_id, 300);

        // Pre-populate cache
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        {
            let mut cache_guard = cache.lock().await;
            cache_guard.put("cached.example.com.", RecordType::A, response.clone(), 300);
        }

        let resolver = MockDnsResolver::always_fail(); // Should never be called
        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let security = test_security_config();
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver,
            &query,
            client,
            &upstreams,
            &security,
            Arc::clone(&cache),
            &failover,
            false,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(resolver.calls(), 0); // Cache hit, resolver not called
    }

    #[tokio::test]
    async fn test_handle_query_any_blocked() {
        let query_id = 0x1234;
        let query = build_any_query("example.com", query_id);
        let resolver = MockDnsResolver::always_fail(); // Should never be called

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config(); // block_any_queries = true
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover, false,
        )
        .await;

        // Should return REFUSED response
        assert!(result.is_ok());
        let response_bytes = result.unwrap();
        let response = DnsResponse::parse(&response_bytes).unwrap();
        assert_eq!(response.response_code(), ResponseCode::Refused);
        assert_eq!(resolver.calls(), 0); // Blocked before resolver called
    }

    #[tokio::test]
    async fn test_handle_query_axfr_blocked() {
        let query_id = 0x5678;
        let query = build_axfr_query("example.com", query_id);
        let resolver = MockDnsResolver::always_fail();

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config(); // block_zone_transfers = true
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover, false,
        )
        .await;

        assert!(result.is_ok());
        let response_bytes = result.unwrap();
        let response = DnsResponse::parse(&response_bytes).unwrap();
        assert_eq!(response.response_code(), ResponseCode::Refused);
        assert_eq!(resolver.calls(), 0);
    }

    #[tokio::test]
    async fn test_handle_query_serve_stale() {
        let query_id = 0x9ABC;
        let query = build_dns_query("stale.example.com", RecordType::A, query_id);
        let stale_response = build_dns_response("stale.example.com", "5.6.7.8", query_id, 1);

        // Pre-populate cache with "stale" entry
        let mut cache_config = test_cache_config();
        cache_config.min_ttl_seconds = 0; // Allow immediate expiration
        let cache = Arc::new(Mutex::new(DnsCache::new(cache_config)));
        {
            let mut cache_guard = cache.lock().await;
            // Store with TTL 0 so it becomes stale immediately
            cache_guard.put(
                "stale.example.com.",
                RecordType::A,
                stale_response.clone(),
                0,
            );
        }

        let resolver = MockDnsResolver::always_fail(); // All upstreams fail
        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let security = test_security_config();
        let mut failover = test_failover_config();
        failover.serve_stale = true;

        let result = handle_dns_query(
            &resolver,
            &query,
            client,
            &upstreams,
            &security,
            Arc::clone(&cache),
            &failover,
            false,
        )
        .await;

        // Should serve stale response when upstreams fail
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_query_all_upstreams_fail_no_stale() {
        let query_id = 0xDEAD;
        let query = build_dns_query("unknown.example.com", RecordType::A, query_id);
        let resolver = MockDnsResolver::always_fail();

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let mut failover = test_failover_config();
        failover.serve_stale = false; // Disable serve_stale

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover, false,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_query_malformed() {
        let malformed_query = vec![0x00, 0x01, 0x02]; // Invalid DNS packet
        let resolver = MockDnsResolver::always_fail();

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver,
            &malformed_query,
            client,
            &upstreams,
            &security,
            cache,
            &failover,
            false,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(resolver.calls(), 0); // Parse failed before resolver
    }

    #[tokio::test]
    async fn test_handle_query_caches_response() {
        let query_id = 0xBEEF;
        let query = build_dns_query("cacheme.example.com", RecordType::A, query_id);
        let response = build_dns_response("cacheme.example.com", "10.20.30.40", query_id, 600);
        let resolver = MockDnsResolver::always_succeed(response.clone());

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let failover = test_failover_config();

        // First query - should hit upstream
        let result1 = handle_dns_query(
            &resolver,
            &query,
            client,
            &upstreams,
            &security,
            Arc::clone(&cache),
            &failover,
            false,
        )
        .await;
        assert!(result1.is_ok());
        assert_eq!(resolver.calls(), 1);

        // Second query - should hit cache
        let result2 = handle_dns_query(
            &resolver,
            &query,
            client,
            &upstreams,
            &security,
            Arc::clone(&cache),
            &failover,
            false,
        )
        .await;
        assert!(result2.is_ok());
        assert_eq!(resolver.calls(), 1); // Still 1, cache hit
    }

    #[tokio::test]
    async fn test_handle_query_failover_success() {
        let query_id = 0xCAFE;
        let query = build_dns_query("failover.example.com", RecordType::A, query_id);
        let response = build_dns_response("failover.example.com", "11.22.33.44", query_id, 300);
        let resolver = MockDnsResolver::new(1, response.clone()); // First fails

        let upstreams: Vec<SocketAddr> =
            vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover, false,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(resolver.calls(), 2); // First upstream failed, second succeeded
    }

    #[tokio::test]
    async fn test_handle_query_empty_question_section() {
        // Build a query with no question section (QDCOUNT = 0)
        let mut query = Vec::new();
        query.extend_from_slice(&[0x11, 0x11]); // ID
        query.extend_from_slice(&[0x00, 0x00]); // Flags
        query.extend_from_slice(&[0x00, 0x00]); // QDCOUNT = 0
        query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        let resolver = MockDnsResolver::always_fail();
        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover, false,
        )
        .await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No question section"));
    }

    #[tokio::test]
    async fn test_handle_query_any_allowed_when_disabled() {
        let query_id = 0x2222;
        let query = build_any_query("example.com", query_id);
        let response = build_dns_response("example.com", "1.2.3.4", query_id, 300);
        let resolver = MockDnsResolver::always_succeed(response);

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let mut security = test_security_config();
        security.block_any_queries = false; // Allow ANY queries
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover, false,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(resolver.calls(), 1); // Query was forwarded
    }

    // ==================== Logging path tests ====================

    #[tokio::test]
    async fn test_handle_query_success_with_logging() {
        let query_id = 0xAAAA;
        let query = build_dns_query("logged.example.com", RecordType::A, query_id);
        let response = build_dns_response("logged.example.com", "1.2.3.4", query_id, 300);
        let resolver = MockDnsResolver::always_succeed(response);

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let failover = test_failover_config();

        // Test with logging ENABLED
        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover,
            true, // enable_logging = true
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_query_cache_hit_with_logging() {
        let query_id = 0xBBBB;
        let query = build_dns_query("cached-log.example.com", RecordType::A, query_id);
        let response = build_dns_response("cached-log.example.com", "5.6.7.8", query_id, 300);

        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        {
            let mut cache_guard = cache.lock().await;
            cache_guard.put("cached-log.example.com.", RecordType::A, response, 300);
        }

        let resolver = MockDnsResolver::always_fail();
        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let security = test_security_config();
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver,
            &query,
            client,
            &upstreams,
            &security,
            Arc::clone(&cache),
            &failover,
            true, // enable_logging
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(resolver.calls(), 0); // Cache hit
    }

    #[tokio::test]
    async fn test_handle_query_blocked_with_logging() {
        let query_id = 0xCCCC;
        let query = build_any_query("blocked-log.example.com", query_id);
        let resolver = MockDnsResolver::always_fail();

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover,
            true, // enable_logging
        )
        .await;

        assert!(result.is_ok()); // Returns REFUSED response
    }

    #[tokio::test]
    async fn test_handle_query_malformed_with_logging() {
        let malformed_query = vec![0xFF, 0xFE, 0xFD];
        let resolver = MockDnsResolver::always_fail();

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver,
            &malformed_query,
            client,
            &upstreams,
            &security,
            cache,
            &failover,
            true, // enable_logging
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_try_upstreams_with_logging() {
        let response = vec![1, 2, 3, 4];
        let resolver = MockDnsResolver::new(1, response.clone()); // Fail once
        let upstreams: Vec<SocketAddr> =
            vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()];

        let result = try_upstreams_with_resolver(
            &resolver,
            &[0, 1],
            &upstreams,
            Duration::from_secs(1),
            0,
            true, // enable_logging
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_try_upstreams_all_fail_with_logging() {
        let resolver = MockDnsResolver::always_fail();
        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];

        let result = try_upstreams_with_resolver(
            &resolver,
            &[0, 1],
            &upstreams,
            Duration::from_secs(1),
            1,
            true, // enable_logging
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_query_upstream_fail_serve_stale_with_logging() {
        let query_id = 0xDDDD;
        let query = build_dns_query("stale-log.example.com", RecordType::A, query_id);
        let stale_response = build_dns_response("stale-log.example.com", "9.9.9.9", query_id, 1);

        let mut cache_config = test_cache_config();
        cache_config.min_ttl_seconds = 0;
        let cache = Arc::new(Mutex::new(DnsCache::new(cache_config)));
        {
            let mut cache_guard = cache.lock().await;
            cache_guard.put("stale-log.example.com.", RecordType::A, stale_response, 0);
        }

        let resolver = MockDnsResolver::always_fail();
        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let security = test_security_config();
        let mut failover = test_failover_config();
        failover.serve_stale = true;

        let result = handle_dns_query(
            &resolver,
            &query,
            client,
            &upstreams,
            &security,
            Arc::clone(&cache),
            &failover,
            true, // enable_logging
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_query_upstream_fail_no_stale_with_logging() {
        let query_id = 0xEEEE;
        let query = build_dns_query("nostale-log.example.com", RecordType::A, query_id);
        let resolver = MockDnsResolver::always_fail();

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config();
        let mut failover = test_failover_config();
        failover.serve_stale = false;

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover,
            true, // enable_logging
        )
        .await;

        assert!(result.is_err());
    }

    // ==================== IXFR blocked test ====================

    #[tokio::test]
    async fn test_handle_query_ixfr_blocked() {
        let query_id = 0xFFFF;
        let query = build_dns_query("example.com", RecordType::IXFR, query_id);
        let resolver = MockDnsResolver::always_fail();

        let upstreams: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let cache = Arc::new(Mutex::new(DnsCache::new(test_cache_config())));
        let security = test_security_config(); // block_zone_transfers = true
        let failover = test_failover_config();

        let result = handle_dns_query(
            &resolver, &query, client, &upstreams, &security, cache, &failover, false,
        )
        .await;

        assert!(result.is_ok());
        let response_bytes = result.unwrap();
        let response = DnsResponse::parse(&response_bytes).unwrap();
        assert_eq!(response.response_code(), ResponseCode::Refused);
    }
}
