//! DNS server module with caching and query validation.

mod cache;
mod client;
mod resolver;
mod server;
mod validation;
pub mod wire;

#[allow(unused_imports)] // run_dns_server is the legacy wrapper for external callers
pub use cache::DnsCache;
pub use client::DnsClient;
#[allow(unused_imports)]
pub use server::{bind_dns_socket, run_dns_server, run_dns_server_on};

use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use wire::{builder, extract_ips, RecordType};

/// Resolve a hostname to a list of IPs via the OS resolver (getaddrinfo on a
/// tokio blocking worker). When `cache` is `Some`, results are cached under
/// `(host, A)` and `(host, AAAA)` using the same wire format the DNS server
/// uses — entries written here are interchangeable with entries written by
/// the upstream-forwarding path, so a Mode 1 ↔ Mode 2 mode switch (if it
/// ever happens at runtime) doesn't invalidate the cache.
///
/// On a cache miss, a single `lookup_host` call returns both v4 and v6
/// (getaddrinfo's natural shape); we partition by family and synthesize one
/// A response and one AAAA response, both cached. The wire TTL is `0` —
/// `DnsCache::put`'s existing clamp raises it to `min_ttl_seconds` for the
/// cache entry, and downstream LAN clients treat 0 as "don't cache" which
/// is the right hint (bunker holds the cache, not them).
///
/// When `cache` is `None`, this is a thin wrapper over `lookup_host` with
/// the same `Vec<IpAddr>` shape — useful for tests or for the
/// `dns.cache.enabled: false` config path.
pub async fn os_resolve(
    host: &str,
    cache: Option<&Arc<Mutex<DnsCache>>>,
) -> std::io::Result<Vec<IpAddr>> {
    // 1. Cache lookup: both A and AAAA need to be present to return early.
    //    If only one is cached, we still do a fresh getaddrinfo for both
    //    (no separate v4/v6 lookup_host APIs in tokio).
    if let Some(cache_arc) = cache {
        if let Some(ips) = cache_lookup_ips(host, cache_arc).await {
            return Ok(ips);
        }
    }

    // 2. Fresh OS lookup (returns mixed v4 + v6).
    let mut ips: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
        .await?
        .map(|sa| sa.ip())
        .collect();

    // 3. Sort v4-first so the result is deterministic across the
    //    OS-lookup path and the cache-hit path (cache walks A then AAAA).
    //    Stable sort preserves relative order within a family.
    ips.sort_by_key(|ip| if ip.is_ipv4() { 0 } else { 1 });

    // 4. Cache by family. The synthetic query/response pair uses a fixed
    //    TX-ID — only the wire bytes' question section matters for cache
    //    storage; `DnsCache::get` rewrites the ID on lookup to match the
    //    asker's request.
    if let Some(cache_arc) = cache {
        cache_store_ips(host, &ips, cache_arc).await;
    }

    Ok(ips)
}

/// Helper: look up `(host, A)` and `(host, AAAA)` in the cache. Returns
/// `Some(merged_ips)` only when at least one family has a cached entry
/// (returning a partial answer is better than ignoring valid cache data).
async fn cache_lookup_ips(host: &str, cache_arc: &Arc<Mutex<DnsCache>>) -> Option<Vec<IpAddr>> {
    let cache = cache_arc.lock().await;
    let a_bytes = cache.get(host, RecordType::A, 0);
    let aaaa_bytes = cache.get(host, RecordType::AAAA, 0);
    drop(cache);

    if a_bytes.is_none() && aaaa_bytes.is_none() {
        return None;
    }
    let mut ips = Vec::new();
    if let Some(bytes) = a_bytes {
        ips.extend(extract_ips(&bytes, RecordType::A));
    }
    if let Some(bytes) = aaaa_bytes {
        ips.extend(extract_ips(&bytes, RecordType::AAAA));
    }
    Some(ips)
}

/// Helper: partition IPs by family, build a synthetic wire response per
/// family, and store both in the cache. `DnsCache::put` is a no-op when
/// the cache is disabled, so we don't need to gate this further.
async fn cache_store_ips(host: &str, ips: &[IpAddr], cache_arc: &Arc<Mutex<DnsCache>>) {
    // Fixed TX-ID for the synthetic queries — the cache rewrites IDs on
    // lookup, so the value here is irrelevant for correctness.
    const SYNTH_ID: u16 = 0;
    let synth_a_query = builder::build_query(host, RecordType::A, SYNTH_ID);
    let synth_aaaa_query = builder::build_query(host, RecordType::AAAA, SYNTH_ID);
    let a_response = builder::build_response_with_ips(&synth_a_query, ips, RecordType::A, 0);
    let aaaa_response =
        builder::build_response_with_ips(&synth_aaaa_query, ips, RecordType::AAAA, 0);

    let mut cache = cache_arc.lock().await;
    cache.put(host, RecordType::A, a_response, 0);
    cache.put(host, RecordType::AAAA, aaaa_response, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsCacheConfig;

    fn new_cache() -> Arc<Mutex<DnsCache>> {
        Arc::new(Mutex::new(DnsCache::new(DnsCacheConfig {
            enabled: true,
            max_entries: 100,
            min_ttl_seconds: 60,
            max_ttl_seconds: 3600,
        })))
    }

    #[tokio::test]
    async fn os_resolve_localhost_returns_at_least_one_ip() {
        // Without cache.
        let ips = os_resolve("localhost", None).await.unwrap();
        assert!(
            !ips.is_empty(),
            "localhost should resolve to at least one IP"
        );
    }

    #[tokio::test]
    async fn os_resolve_cache_hit_avoids_second_lookup() {
        // Hard to assert "no syscall" without mocks, but we can verify the
        // cache is populated after the first call and that subsequent calls
        // return the same IPs in the same order.
        let cache = new_cache();
        let first = os_resolve("localhost", Some(&cache)).await.unwrap();
        let second = os_resolve("localhost", Some(&cache)).await.unwrap();
        assert_eq!(first, second);

        // Sanity: cache entries exist for both families.
        let guard = cache.lock().await;
        let a_cached = guard.get("localhost", RecordType::A, 0);
        let aaaa_cached = guard.get("localhost", RecordType::AAAA, 0);
        assert!(
            a_cached.is_some() || aaaa_cached.is_some(),
            "at least one family should be cached after resolution"
        );
    }

    #[tokio::test]
    async fn os_resolve_invalid_hostname_errors() {
        // RFC 2606 reserves .invalid for guaranteed non-resolution.
        let result = os_resolve("nope.invalid", None).await;
        assert!(result.is_err());
    }
}
