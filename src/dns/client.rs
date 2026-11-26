//! Proxy-facing hostname-to-IPs resolver.
//!
//! `DnsClient` is the single API the proxy uses to resolve a hostname into a
//! `Vec<IpAddr>`. Two backends:
//!
//! - **Upstream** — forwards A + AAAA queries to the configured upstreams via
//!   `handle_dns_query_with_resolver`, sharing the same cache the DNS server
//!   uses (Mode 1). Picks up the operator-configured failover, anti-spoofing,
//!   serve-stale, and TTL bounds. Only successful replies are cached, for the
//!   TTL the upstream gave.
//! - **Os** — wraps `crate::dns::os_resolve(host, cache)`, which calls
//!   `getaddrinfo` on a tokio worker. Used in Mode 2 (shares cache with the
//!   DNS server's `OsResolverHandler`) and Mode 3 (own cache, no DNS server).
//!
//! Both variants check the bunker cache first and store results in the same
//! wire-byte format, so an entry put by one is consumable by the other (and
//! by the DNS server's own per-query cache check at the server-loop level).

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Mutex;

use crate::config::{DnsFailoverConfig, DnsSecurityConfig};
use crate::dns::cache::DnsCache;
use crate::dns::resolver::{handle_dns_query_with_resolver, UdpDnsResolver};
use crate::dns::wire::{builder, extract_ips, DnsResponse, RecordType, ResponseCode};
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

/// The tokio runtime that resolution is sent to when the caller is not on one.
static RESOLVER_RUNTIME: OnceLock<tokio::runtime::Handle> = OnceLock::new();

/// Name the tokio runtime that hostname resolution may be handed to. Called
/// once at startup, from that runtime.
pub fn set_resolver_runtime(handle: tokio::runtime::Handle) {
    let _ = RESOLVER_RUNTIME.set(handle);
}

impl DnsClient {
    /// `resolve`, callable from any thread.
    ///
    /// Both backends of `resolve` need tokio: the OS resolver runs on tokio's
    /// blocking pool and the upstream forwarder uses tokio UDP sockets. The
    /// io_uring engine's workers run monoio instead, and calling `resolve`
    /// there panicked ("there is no reactor running"), killing the worker.
    /// From such a thread the lookup is run on the runtime registered with
    /// `set_resolver_runtime` and only the result is awaited here.
    #[cfg_attr(not(feature = "engine"), allow(dead_code))] // engine path only
    pub async fn resolve_anywhere(self: &Arc<Self>, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        resolve_on(RESOLVER_RUNTIME.get(), self, host).await
    }
}

#[cfg_attr(not(feature = "engine"), allow(dead_code))] // engine path only
async fn resolve_on(
    home: Option<&tokio::runtime::Handle>,
    client: &Arc<DnsClient>,
    host: &str,
) -> Result<Vec<IpAddr>, DnsError> {
    // Literal IPs need no resolver, and a tokio thread can resolve in place.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if tokio::runtime::Handle::try_current().is_ok() {
        return client.resolve(host).await;
    }
    // Not on tokio and nowhere to send the work: fail the lookup, don't panic.
    let home = home.ok_or(DnsError::UpstreamFailed)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let client = Arc::clone(client);
    let host = host.to_string();
    home.spawn(async move {
        let _ = tx.send(client.resolve(&host).await);
    });
    rx.await.unwrap_or(Err(DnsError::UpstreamFailed))
}

/// An unpredictable DNS transaction ID from the OS CSPRNG.
fn random_query_id() -> u16 {
    let mut bytes = [0u8; 2];
    if getrandom::getrandom(&mut bytes).is_ok() {
        return u16::from_ne_bytes(bytes);
    }
    // The OS RNG essentially never fails. If it does, fall back to std's
    // randomly keyed SipHash (seeded from the OS at thread start, re-keyed per
    // `RandomState`) rather than a predictable constant.
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish() as u16
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
    // Each query gets its own unpredictable transaction ID. The ID is half of
    // what an off-path attacker must guess to forge an upstream reply (the
    // other half is the source port) — `validate_upstream_response` checks it,
    // and that check is worthless against a fixed, known value. The cache
    // rewrites IDs on lookup, so nothing downstream depends on the value.
    let a_query = builder::build_query(host, RecordType::A, random_query_id());
    let aaaa_query = builder::build_query(host, RecordType::AAAA, random_query_id());

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
        failover.serve_stale,
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
        failover.serve_stale,
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
    serve_stale: bool,
    enable_logging: bool,
) -> Result<Vec<u8>, DnsError> {
    // Cache hit fast path.
    {
        let cache_guard = cache.lock().await;
        if let Some(bytes) = cache_guard.get(host, qtype, 0) {
            return Ok(bytes);
        }
    }

    // Forward via upstreams (failover, retries and anti-spoofing are inside
    // this function).
    let response = match handle_dns_query_with_resolver(
        resolver,
        query,
        upstreams,
        timeout,
        max_retries,
        enable_logging,
    )
    .await
    {
        Ok(response) => response,
        Err(e) => {
            // Every upstream failed: an expired answer beats no answer.
            if serve_stale {
                if let Some(stale) = cache.lock().await.get_stale(host, qtype, 0) {
                    return Ok(stale);
                }
            }
            return Err(e);
        }
    };

    if let Some(ttl) = cacheable_ttl(&response) {
        cache.lock().await.put(host, qtype, response.clone(), ttl);
    }

    Ok(response)
}

/// Whether an upstream reply may be cached, and for how long (before the
/// cache applies its own min/max bounds).
///
/// Only `NOERROR` replies are kept. A failure such as `SERVFAIL` is usually
/// transient, and caching it would turn one bad reply into errors for every
/// request to that host until the entry expires. A `NOERROR` reply with no
/// answers (the host has no record of this type, typically no AAAA) is kept
/// for the cache's minimum TTL so that an IPv4-only host does not cost an
/// extra upstream query on every request.
fn cacheable_ttl(response: &[u8]) -> Option<u64> {
    let parsed = DnsResponse::parse(response).ok()?;
    if parsed.response_code() != ResponseCode::NoError {
        return None;
    }
    if parsed.answer_count() == 0 {
        return Some(0);
    }
    Some(u64::from(parsed.min_ttl()))
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

    /// A fake upstream on loopback. Answers A queries with 192.0.2.1 and AAAA
    /// queries with an empty answer, and reports each transaction ID it sees.
    async fn spawn_fake_upstream() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<u16>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                let query = &buf[..len];
                let _ = tx.send(u16::from_be_bytes([query[0], query[1]]));
                // QTYPE is the 2 bytes before the trailing 2-byte QCLASS.
                let qtype = u16::from_be_bytes([query[len - 4], query[len - 3]]);
                let response = if qtype == 1 {
                    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
                    builder::build_response_with_ips(query, &[ip], RecordType::A, 60)
                } else {
                    builder::build_response_with_ips(query, &[], RecordType::AAAA, 60)
                };
                let _ = socket.send_to(&response, from).await;
            }
        });
        (addr, rx)
    }

    /// Regression: every query the proxy sent upstream carried transaction ID
    /// 0, so a forged reply only had to guess the source port.
    #[tokio::test]
    async fn upstream_queries_use_unpredictable_transaction_ids() {
        let (upstream, mut seen) = spawn_fake_upstream().await;
        let client = DnsClient::new_upstream(
            new_cache(),
            Arc::new(vec![upstream]),
            Arc::new(DnsFailoverConfig::default()),
            Arc::new(DnsSecurityConfig::default()),
            false,
        );

        const HOSTS: usize = 8;
        for i in 0..HOSTS {
            let ips = client.resolve(&format!("host{i}.test")).await.unwrap();
            assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
        }

        let mut ids = Vec::new();
        while let Ok(id) = seen.try_recv() {
            ids.push(id);
        }
        assert_eq!(ids.len(), HOSTS * 2, "one A and one AAAA query per host");
        let distinct: std::collections::HashSet<u16> = ids.iter().copied().collect();
        // 16 random 16-bit IDs: even one collision is a ~0.2% event, so
        // demanding at least 12 distinct values can't flake in practice,
        // while a constant (or A/AAAA-shared constant) ID fails outright.
        assert!(
            distinct.len() >= 12,
            "transaction IDs look predictable: {ids:?}"
        );
    }

    /// A fake upstream that counts queries. The first `failures` A queries
    /// get SERVFAIL; later ones get 192.0.2.1 with `ttl`. AAAA queries get an
    /// empty NOERROR answer.
    async fn spawn_counting_upstream(
        failures: usize,
        ttl: u32,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&queries);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let mut a_seen = 0usize;
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                let query = &buf[..len];
                counter.fetch_add(1, Ordering::SeqCst);
                let qtype = u16::from_be_bytes([query[len - 4], query[len - 3]]);
                let response = if qtype == 1 {
                    a_seen += 1;
                    if a_seen <= failures {
                        crate::dns::wire::create_error_response(query, ResponseCode::ServFail)
                            .unwrap()
                    } else {
                        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
                        builder::build_response_with_ips(query, &[ip], RecordType::A, ttl)
                    }
                } else {
                    builder::build_response_with_ips(query, &[], RecordType::AAAA, ttl)
                };
                let _ = socket.send_to(&response, from).await;
            }
        });
        (addr, queries)
    }

    fn upstream_client(
        cache: Arc<Mutex<DnsCache>>,
        upstream: SocketAddr,
        serve_stale: bool,
    ) -> DnsClient {
        DnsClient::new_upstream(
            cache,
            Arc::new(vec![upstream]),
            Arc::new(DnsFailoverConfig {
                timeout_ms: 500,
                max_retries: 0,
                serve_stale,
            }),
            Arc::new(DnsSecurityConfig::default()),
            false,
        )
    }

    /// Regression: a SERVFAIL was cached like an answer, so one transient
    /// upstream failure broke the host until the entry expired.
    #[tokio::test]
    async fn upstream_failure_reply_is_not_cached() {
        let (upstream, _queries) = spawn_counting_upstream(1, 300).await;
        let cache = new_cache();
        let client = upstream_client(Arc::clone(&cache), upstream, false);

        assert!(client.resolve("flaky.test").await.is_err());
        assert_eq!(
            cache.lock().await.stored_ttl("flaky.test", RecordType::A),
            None,
            "SERVFAIL must not be cached"
        );
        let ips = client.resolve("flaky.test").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
    }

    /// Regression: answers were stored with TTL 0, so every record lived for
    /// exactly the cache minimum whatever the upstream said.
    #[tokio::test]
    async fn upstream_answer_is_cached_for_its_own_ttl() {
        let (upstream, queries) = spawn_counting_upstream(0, 600).await;
        let cache = new_cache();
        let client = upstream_client(Arc::clone(&cache), upstream, false);

        client.resolve("ttl.test").await.unwrap();
        {
            let guard = cache.lock().await;
            assert_eq!(guard.stored_ttl("ttl.test", RecordType::A), Some(600));
            // No AAAA record: remembered for the cache minimum.
            assert_eq!(guard.stored_ttl("ttl.test", RecordType::AAAA), Some(60));
            // The DNS server asks for the fully qualified name and must find
            // the entry the proxy stored.
            assert!(guard.get("ttl.test.", RecordType::A, 7).is_some());
        }

        // Both families now come from the cache.
        let before = queries.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(before, 2);
        client.resolve("ttl.test").await.unwrap();
        assert_eq!(queries.load(std::sync::atomic::Ordering::SeqCst), before);
    }

    #[test]
    fn only_successful_replies_are_cacheable() {
        let query = builder::build_query("example.test", RecordType::A, 1);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let answer = builder::build_response_with_ips(&query, &[ip], RecordType::A, 1234);
        let empty = builder::build_response_with_ips(&query, &[], RecordType::A, 1234);
        assert_eq!(cacheable_ttl(&answer), Some(1234));
        assert_eq!(cacheable_ttl(&empty), Some(0));
        for rcode in [
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::NxDomain,
        ] {
            let reply = crate::dns::wire::create_error_response(&query, rcode).unwrap();
            assert_eq!(cacheable_ttl(&reply), None, "{rcode:?}");
        }
        assert_eq!(cacheable_ttl(&[0u8; 3]), None);
    }

    /// With `serve_stale` on, an expired entry is used when no upstream
    /// answers; with it off the lookup fails.
    #[tokio::test]
    async fn expired_entry_is_served_only_when_serve_stale_is_on() {
        // Nothing listens here, so every upstream query fails.
        let dead = {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.local_addr().unwrap()
        };
        for serve_stale in [true, false] {
            let cache = Arc::new(Mutex::new(DnsCache::new(DnsCacheConfig {
                enabled: true,
                max_entries: 100,
                min_ttl_seconds: 0,
                max_ttl_seconds: 3600,
            })));
            let query = builder::build_query("stale.test", RecordType::A, 0);
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
            let response = builder::build_response_with_ips(&query, &[ip], RecordType::A, 0);
            cache
                .lock()
                .await
                .put("stale.test", RecordType::A, response, 0);

            let client = upstream_client(cache, dead, serve_stale);
            let result = client.resolve("stale.test").await;
            if serve_stale {
                assert_eq!(result.unwrap(), vec![ip]);
            } else {
                assert!(result.is_err());
            }
        }
    }

    /// Drive a future on the current thread with no async runtime at all,
    /// the situation of an io_uring engine worker.
    fn block_on_plain_thread<F: std::future::Future>(fut: F) -> F::Output {
        struct ThreadWaker(std::thread::Thread);
        impl std::task::Wake for ThreadWaker {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Arc::new(ThreadWaker(std::thread::current())).into();
        let mut cx = std::task::Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(out) => return out,
                std::task::Poll::Pending => std::thread::park(),
            }
        }
    }

    /// Regression: resolving a hostname from a thread without a tokio runtime
    /// (every io_uring worker) panicked and took the worker down.
    #[test]
    fn resolves_hostnames_from_a_thread_without_tokio() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        let outcome = std::thread::spawn(move || {
            assert!(tokio::runtime::Handle::try_current().is_err());
            let client = Arc::new(DnsClient::new_os(None));
            let resolved = block_on_plain_thread(resolve_on(Some(&handle), &client, "localhost"));
            let literal = block_on_plain_thread(resolve_on(None, &client, "192.0.2.7"));
            // With nowhere to run the lookup it fails; it must not panic.
            let stranded = block_on_plain_thread(resolve_on(None, &client, "localhost"));
            (resolved, literal, stranded)
        })
        .join()
        .expect("resolving off-runtime must not panic");
        let (resolved, literal, stranded) = outcome;
        assert!(resolved.unwrap().iter().all(|ip| ip.is_loopback()));
        assert_eq!(
            literal.unwrap(),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
        assert!(stranded.is_err());
    }

    #[test]
    fn random_query_ids_vary() {
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| random_query_id()).collect();
        assert!(
            ids.len() > 32,
            "only {} distinct IDs in 64 draws",
            ids.len()
        );
    }
}
