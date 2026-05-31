//! Proxy-facing hostname-to-IPs resolver.
//!
//! `DnsClient` is the single API the proxy uses to resolve a hostname into a
//! `Vec<IpAddr>`. Two backends:
//!
//! - **Upstream** — forwards A + AAAA queries to the configured upstreams via
//!   `handle_dns_query_with_resolver`, sharing the same cache the DNS server
//!   uses (Mode 1). Picks up the operator-configured failover, anti-spoofing,
//!   serve-stale, and TTL bounds.
//! - **Os** — wraps `crate::dns::os_resolve(host, cache)`, which calls
//!   `getaddrinfo` on a tokio worker. Used in Mode 2 (shares cache with the
//!   DNS server's `OsResolverHandler`) and Mode 3 (own cache, no DNS server).
//!
//! Both variants check the bunker cache first and store results in the same
//! wire-byte format, so an entry put by one is consumable by the other (and
//! by the DNS server's own per-query cache check at the server-loop level).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::config::{DnsFailoverConfig, DnsSecurityConfig};
use crate::dns::cache::DnsCache;
use crate::dns::resolver::{handle_dns_query_with_resolver, UdpDnsResolver};
use crate::dns::wire::{builder, extract_ips, RecordType};
use crate::error::DnsError;

/// Proxy-side DNS resolver. Two backends; same `resolve(host)` API.
pub enum DnsClient {
    /// Forwards via configured upstreams. Used when DNS is enabled with at
    /// least one upstream configured (`bunker_dns_active = true`).
    Upstream {
        cache: Arc<Mutex<DnsCache>>,
        upstreams: Arc<Vec<SocketAddr>>,
        failover: Arc<DnsFailoverConfig>,
        #[allow(dead_code)] // reserved for future per-resolve security checks
        security: Arc<DnsSecurityConfig>,
        resolver: UdpDnsResolver,
        enable_logging: bool,
    },
    /// Uses the OS resolver via `os_resolve`. The cache is optional — Mode 2
    /// passes the same `Arc` the DNS server holds, Mode 3 passes its own,
    /// and `dns.cache.enabled: false` passes `None` (pure passthrough to
    /// `lookup_host`).
    Os { cache: Option<Arc<Mutex<DnsCache>>> },
}

impl DnsClient {
    /// Construct an Upstream-backed client. The `Arc<Mutex<DnsCache>>` should
    /// be the same instance passed to the DNS server's `UpstreamForwardHandler`
    /// so the two consumers share cache entries.
    pub fn new_upstream(
        cache: Arc<Mutex<DnsCache>>,
        upstreams: Arc<Vec<SocketAddr>>,
        failover: Arc<DnsFailoverConfig>,
        security: Arc<DnsSecurityConfig>,
        enable_logging: bool,
    ) -> Self {
        let resolver = UdpDnsResolver::new((*security).clone());
        DnsClient::Upstream {
            cache,
            upstreams,
            failover,
            security,
            resolver,
            enable_logging,
        }
    }

    /// Construct an Os-backed client. `cache` is the shared cache (Mode 2)
    /// or a proxy-only cache (Mode 3), or `None` when caching is disabled.
    pub fn new_os(cache: Option<Arc<Mutex<DnsCache>>>) -> Self {
        DnsClient::Os { cache }
    }

    /// Resolve `host` to a list of IPs. Literal IPs (v4 or v6) short-circuit
    /// without touching the cache or any resolver. Results from both backends
    /// are sorted v4-first for stability across cache hit/miss paths.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        // Literal-IP shortcut — same behavior in every mode, no resolver call.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        match self {
            DnsClient::Upstream {
                cache,
                upstreams,
                failover,
                resolver,
                enable_logging,
                ..
            } => {
                resolve_via_upstream(host, cache, upstreams, failover, resolver, *enable_logging)
                    .await
            }
            DnsClient::Os { cache } => crate::dns::os_resolve(host, cache.as_ref())
                .await
                .map_err(|e| DnsError::ParseError(e.to_string())),
        }
    }
}

/// Upstream-backed resolution: A + AAAA in parallel, cache check first, fall
/// back to `handle_dns_query_with_resolver` (which handles failover, retries,
/// serve-stale, and anti-spoofing).
async fn resolve_via_upstream(
    host: &str,
    cache: &Arc<Mutex<DnsCache>>,
    upstreams: &Arc<Vec<SocketAddr>>,
    failover: &Arc<DnsFailoverConfig>,
    resolver: &UdpDnsResolver,
    enable_logging: bool,
) -> Result<Vec<IpAddr>, DnsError> {
    // Use a fixed synthetic ID for the wire queries — the cache rewrites
    // IDs on lookup and we're not feeding anyone, so this value doesn't
    // need to be random.
    const SYNTH_ID: u16 = 0;
    let a_query = builder::build_query(host, RecordType::A, SYNTH_ID);
    let aaaa_query = builder::build_query(host, RecordType::AAAA, SYNTH_ID);

    // Run A and AAAA in parallel. Each task: cache check first, then if miss
    // forward to upstreams (with the existing failover/serve-stale machinery).
    let timeout = Duration::from_millis(failover.timeout_ms);
    let max_retries = failover.max_retries;

    let a_fut = fetch_via_upstream_with_cache(
        &a_query,
        host,
        RecordType::A,
        cache,
        upstreams,
        resolver,
        timeout,
        max_retries,
        enable_logging,
    );
    let aaaa_fut = fetch_via_upstream_with_cache(
        &aaaa_query,
        host,
        RecordType::AAAA,
        cache,
        upstreams,
        resolver,
        timeout,
        max_retries,
        enable_logging,
    );

    let (a_result, aaaa_result) = tokio::join!(a_fut, aaaa_fut);

    // Extract whatever IPs we got — partial success (just A or just AAAA) is
    // still useful; the proxy can connect to whichever family succeeded.
    let mut ips = Vec::new();
    if let Ok(bytes) = a_result {
        ips.extend(extract_ips(&bytes, RecordType::A));
    }
    if let Ok(bytes) = aaaa_result {
        ips.extend(extract_ips(&bytes, RecordType::AAAA));
    }
    if ips.is_empty() {
        return Err(DnsError::UpstreamFailed);
    }

    // Stable sort v4-first so callers see a deterministic order regardless
    // of which family came back first.
    ips.sort_by_key(|ip| if ip.is_ipv4() { 0 } else { 1 });
    Ok(ips)
}

#[allow(clippy::too_many_arguments)] // grouping these into a struct just to satisfy clippy would hurt readability
async fn fetch_via_upstream_with_cache(
    query: &[u8],
    host: &str,
    qtype: RecordType,
    cache: &Arc<Mutex<DnsCache>>,
    upstreams: &Arc<Vec<SocketAddr>>,
    resolver: &UdpDnsResolver,
    timeout: Duration,
    max_retries: u32,
    enable_logging: bool,
) -> Result<Vec<u8>, DnsError> {
    // Cache hit fast path.
    {
        let cache_guard = cache.lock().await;
        if let Some(bytes) = cache_guard.get(host, qtype, 0) {
            return Ok(bytes);
        }
    }

    // Forward via upstreams (failover + retries + serve-stale + anti-spoofing
    // already inside this function).
    let response = handle_dns_query_with_resolver(
        resolver,
        query,
        upstreams,
        timeout,
        max_retries,
        enable_logging,
    )
    .await?;

    // Cache the wire response. Use min_ttl from the response itself (parsed
    // by DnsCache::put consumers — for now we pass 0 and let the cache's
    // min_ttl_seconds clamp apply, matching how the DNS server stores
    // entries via its own cache path).
    {
        let mut cache_guard = cache.lock().await;
        cache_guard.put(host, qtype, response.clone(), 0);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsCacheConfig;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn new_cache() -> Arc<Mutex<DnsCache>> {
        Arc::new(Mutex::new(DnsCache::new(DnsCacheConfig {
            enabled: true,
            max_entries: 100,
            min_ttl_seconds: 60,
            max_ttl_seconds: 3600,
        })))
    }

    #[tokio::test]
    async fn os_variant_literal_ipv4_short_circuits() {
        let client = DnsClient::new_os(None);
        let ips = client.resolve("127.0.0.1").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    }

    #[tokio::test]
    async fn os_variant_literal_ipv6_short_circuits() {
        let client = DnsClient::new_os(None);
        let ips = client.resolve("::1").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    }

    #[tokio::test]
    async fn os_variant_resolves_localhost() {
        let client = DnsClient::new_os(None);
        let ips = client.resolve("localhost").await.unwrap();
        assert!(!ips.is_empty());
    }

    #[tokio::test]
    async fn os_variant_with_cache_hit_returns_same() {
        let cache = new_cache();
        let client = DnsClient::new_os(Some(cache));
        let first = client.resolve("localhost").await.unwrap();
        let second = client.resolve("localhost").await.unwrap();
        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    #[tokio::test]
    async fn os_variant_no_cache_works() {
        // dns.cache.enabled: false → os variant with cache: None should still
        // resolve (just no caching).
        let client = DnsClient::new_os(None);
        let ips = client.resolve("localhost").await.unwrap();
        assert!(!ips.is_empty());
    }

    #[tokio::test]
    async fn upstream_variant_literal_ip_short_circuits() {
        // Upstream variant should also honor the literal-IP shortcut without
        // touching the network or the cache.
        let cache = new_cache();
        let upstreams = Arc::new(vec!["127.0.0.1:53".parse().unwrap()]);
        let failover = Arc::new(DnsFailoverConfig::default());
        let security = Arc::new(DnsSecurityConfig::default());
        let client = DnsClient::new_upstream(cache, upstreams, failover, security, false);
        let ips = client.resolve("203.0.113.1").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]);
    }

    #[tokio::test]
    async fn upstream_variant_returns_cached_a_record() {
        // Pre-populate the cache with a synthetic A response, then call
        // resolve() — should hit the cache without any network I/O.
        let cache = new_cache();
        {
            let synth_query = builder::build_query("example.test", RecordType::A, 0);
            let synth_response = builder::build_response_with_ips(
                &synth_query,
                &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
                RecordType::A,
                60,
            );
            cache
                .lock()
                .await
                .put("example.test", RecordType::A, synth_response, 0);
        }

        // Upstreams point to an unreachable address — if cache works, this
        // doesn't matter; if cache misses, we'd time out (test would hang).
        // failover.timeout_ms=200 keeps the timeout short either way.
        let upstreams = Arc::new(vec!["127.0.0.1:1".parse().unwrap()]);
        let failover = Arc::new(DnsFailoverConfig {
            timeout_ms: 200,
            max_retries: 0,
            serve_stale: false,
        });
        let security = Arc::new(DnsSecurityConfig::default());

        let client = DnsClient::new_upstream(cache, upstreams, failover, security, false);
        let ips = client.resolve("example.test").await.unwrap();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }
}
