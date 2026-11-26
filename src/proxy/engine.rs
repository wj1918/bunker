//! Runtime-agnostic proxy engine: a common I/O interface (`ProxyIo`) plus the
//! generic relay core written once against it. The two async runtimes bunker
//! cares about — tokio (portable, incl. Windows) and monoio (Linux/io_uring) —
//! unify only under a **thread-per-core, `!Send`** model: monoio is inherently
//! that, and tokio matches it with a `current_thread` runtime + `LocalSet`. So
//! the trait's futures need not be `Send`, the proxy core is written exactly
//! once, and each runtime supplies a backend (a `ProxyIo` impl + a runner).
//!
//! This module owns the portable pieces: the trait, the relay loop, the tokio
//! backend, and a portable thread-per-core runner. The monoio backend lives in
//! the Linux-only example (it can't compile on Windows).
#![allow(dead_code)] // spike engine; not yet wired into the shipped binary

use crate::config::{RateLimitConfig, SecurityConfig};
use crate::proxy::forward::{
    parse_connect_target, rewrite_forward_with_metadata, ForwardError, Target,
};
use crate::proxy::framing::{
    scan_message_with_metadata, scan_response, MessageError, MessageMetadata, MessageScan,
    ResponseScan,
};
use crate::security::{
    is_blocked_target, is_source_ip_allowed, resolved_addrs_blocked, RateLimiter,
};
use bytes::{Bytes, BytesMut};
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::debug;

/// Runtime + security knobs for the forward engine, wired from the YAML config.
/// Bundled so the runner/core signatures stay small.
pub struct EngineConfig {
    pub security: Arc<SecurityConfig>,
    /// Hostname-to-IPs resolver. Built once by main; shared across all
    /// engine workers. Variant chosen at startup based on `dns.enabled` +
    /// `upstreams`: `Upstream` (Mode 1) shares cache with the DNS server,
    /// `Os` (Modes 2 & 3) wraps `os_resolve` with an optional cache.
    pub dns_client: Arc<crate::dns::DnsClient>,
    pub rate_limit: RateLimitConfig,
    /// Idle-pool caps + TTLs (from proxy.connection_pool).
    pub pool_max_per_host: usize,
    pub pool_max_total: usize,
    pub pool_idle_timeout: Duration,
    pub pool_max_lifetime: Duration,
    /// Upstream connect timeout; zero = no timeout.
    pub connect_timeout: Duration,
    /// Time to receive a complete request head; zero = no limit (slowloris).
    pub header_read_timeout: Duration,
    /// Max request body (Content-Length) in bytes; 0 = unlimited.
    pub max_request_body_bytes: u64,
    /// Max requests per client connection; 0 = unlimited.
    pub max_requests_per_conn: u32,
    /// Max concurrent client connections across all workers; 0 = unlimited.
    pub max_connections: usize,
    /// Emit per-request INFO logs for HTTP forwards and CONNECT tunnels.
    /// Mirrors `logging.log_requests` in the hyper path.
    pub log_requests: bool,
}

/// A bidirectional byte stream the proxy relays over. Methods are `async fn`
/// (AFIT) and may return `!Send` futures — fine because the engine runs
/// thread-per-core. Both reads and writes are expressed in terms of a caller
/// accumulator so the same shape fits tokio (borrowed buffers) and monoio
/// (owned/completion buffers) without leaking either model into the core.
// The engine is thread-per-core, so trait-method futures need not be `Send`;
// the async_fn_in_trait lint's Send caveat doesn't apply here.
#[allow(async_fn_in_trait)]
pub trait ProxyIo {
    /// Read some bytes and append them to `acc`. Returns the count (0 = EOF).
    /// Uses `BytesMut` (not `Vec<u8>`) so the engine can extract messages as
    /// reference-counted `Bytes` slices via `acc.split_to(n).freeze()` — the
    /// foundation of the body-copy elimination in `relay_once` /
    /// `rewrite_forward`.
    async fn read_append(&mut self, acc: &mut BytesMut) -> std::io::Result<usize>;
    /// Write all of `data`.
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()>;
    /// Write `head` then `body` in as few syscalls as possible. The default
    /// impl falls back to two sequential `write_all` calls; tokio's backend
    /// overrides with `writev(2)` so head+body usually go out in one syscall
    /// (the whole point of vectored I/O — saves the per-segment cost when
    /// proxying a rewritten head + an unmodified body slice).
    async fn write_all_vectored(&mut self, head: &[u8], body: &[u8]) -> std::io::Result<()> {
        self.write_all(head).await?;
        if !body.is_empty() {
            self.write_all(body).await?;
        }
        Ok(())
    }
    /// Like `read_append`, but fails with a TimedOut error if no read completes
    /// within `dur` (used to bound the header read — slowloris defense). The
    /// default ignores the timeout; runtime backends override it with their
    /// timer. `dur` is only ever a positive remaining-budget.
    async fn read_append_timeout(
        &mut self,
        acc: &mut BytesMut,
        _dur: Duration,
    ) -> std::io::Result<usize> {
        self.read_append(acc).await
    }
}

/// Why reading one message stopped without yielding it.
#[derive(Debug)]
pub enum RelayErr {
    /// EOF, I/O error, malformed/smuggling head, or header-read timeout — in all
    /// cases the caller just drops the connection (no response, or already sent).
    Closed,
    /// A request whose declared Content-Length exceeds the limit (-> 413).
    TooLarge,
}

/// Read exactly one complete HTTP/1 message from `src` into `acc`, returning its
/// bytes and leaving any trailing (pipelined) bytes in `acc`. Runtime-agnostic.
///
/// `head_timeout` (when Some) bounds the *total* time to receive a complete head
/// (CRLFCRLF) — slowloris defense; it does NOT bound body transfer. `max_body`
/// (>0) rejects an oversized declared Content-Length up front (-> TooLarge).
pub async fn relay_once<C: ProxyIo>(
    src: &mut C,
    acc: &mut BytesMut,
    is_request: bool,
    head_timeout: Option<Duration>,
    max_body: u64,
) -> Result<Bytes, RelayErr> {
    // Backward-compat wrapper: tests and the response path call this; only
    // proxy_forward needs the metadata variant.
    relay_once_with_metadata(src, acc, is_request, head_timeout, max_body)
        .await
        .map(|(b, _)| b)
}

/// Like `relay_once`, but also returns the routing metadata extracted in the
/// same httparse pass `scan_message_with_metadata` performs internally. Used by
/// the engine's request loop so `rewrite_forward` can skip a second parse.
pub async fn relay_once_with_metadata<C: ProxyIo>(
    src: &mut C,
    acc: &mut BytesMut,
    is_request: bool,
    head_timeout: Option<Duration>,
    max_body: u64,
) -> Result<(Bytes, Option<MessageMetadata>), RelayErr> {
    let start = std::time::Instant::now();
    let mut head_done = false;
    loop {
        let (scan, meta) = scan_message_with_metadata(acc, is_request, max_body);
        match scan {
            MessageScan::Complete { total, .. } => {
                // Zero-copy: split_to + freeze hands the caller a Bytes view
                // that shares the underlying allocation. No memcpy, no drain.
                // The remaining tail (pipelined bytes, if any) stays in `acc`.
                return Ok((acc.split_to(total).freeze(), meta));
            }
            MessageScan::Error(MessageError::BodyTooLarge) => return Err(RelayErr::TooLarge),
            MessageScan::Error(_) => return Err(RelayErr::Closed),
            MessageScan::Incomplete => {
                // Latch once the head is fully received; after that, body reads
                // are untimed (a large upload mustn't trip the header timeout).
                if !head_done && acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    head_done = true;
                }
                let n = match head_timeout {
                    Some(t) if !head_done => {
                        let elapsed = start.elapsed();
                        if elapsed >= t {
                            return Err(RelayErr::Closed); // slowloris: head too slow
                        }
                        match src.read_append_timeout(acc, t - elapsed).await {
                            Ok(n) => n,
                            Err(_) => return Err(RelayErr::Closed),
                        }
                    }
                    _ => match src.read_append(acc).await {
                        Ok(n) => n,
                        Err(_) => return Err(RelayErr::Closed),
                    },
                };
                if n == 0 {
                    return Err(RelayErr::Closed); // EOF
                }
            }
        }
    }
}

/// Opens upstream connections for the forward proxy, and pumps CONNECT tunnels.
/// Backend-specific (tokio vs monoio bidirectional copy), so the forward core is
/// generic over it.
///
/// Hostname resolution is NOT on this trait — it's delegated to `DnsClient`
/// (threaded through `EngineConfig`). That keeps the per-backend impl focused
/// on TCP I/O and lets bunker's resolver chain (Mode 1 upstream forwarder,
/// Mode 2/3 OS-resolver wrapper, all with shared cache) apply uniformly
/// regardless of which backend runtime is in use.
#[allow(async_fn_in_trait)]
pub trait Connect {
    type Conn: ProxyIo;
    /// Connect to an already-resolved, already-validated address (no second
    /// resolution — avoids a rebinding TOCTOU between validation and connect).
    async fn connect(&self, addr: SocketAddr) -> std::io::Result<Self::Conn>;
    /// Pump bytes both ways between an established client and upstream until
    /// either side closes (the CONNECT tunnel). Consumes both connections.
    async fn tunnel(client: Self::Conn, upstream: Self::Conn);
}

/// Outcome of resolving + validating a target before connecting.
enum AcquireErr {
    /// Blocked by SSRF (resolved to a private/internal IP — rebinding).
    Blocked,
    /// DNS failure or connect failure.
    Failed,
}

/// Resolve a target to a single connectable address, applying DNS-rebinding
/// validation to ALL resolved IPs. Literal-IP targets skip the resolver (and
/// were already vetted by `is_blocked_target` upstream); hostnames go through
/// the shared `DnsClient` (Mode 1 upstream forwarder or Mode 2/3 OS-resolver
/// wrapper) and every returned IP is checked.
async fn resolve_target(
    host: &str,
    port: u16,
    security: &SecurityConfig,
    dns_client: &Arc<crate::dns::DnsClient>,
) -> Result<SocketAddr, AcquireErr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        // Defense in depth: run the literal IP through the same SSRF gate as
        // resolved hostnames. Callers do gate via `is_blocked_target` first,
        // but that invariant is implicit — if a future caller wires into
        // resolve_target directly, this keeps literal-IP SSRF (including the
        // ::ffff:x.x.x.x mapped form) from slipping through.
        let addr = SocketAddr::new(ip, port);
        if resolved_addrs_blocked(&[addr], security).is_some() {
            return Err(AcquireErr::Blocked);
        }
        return Ok(addr);
    }
    let ips = dns_client
        .resolve(host)
        .await
        .map_err(|_| AcquireErr::Failed)?;
    if ips.is_empty() {
        return Err(AcquireErr::Failed);
    }
    let addrs: Vec<SocketAddr> = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    if resolved_addrs_blocked(&addrs, security).is_some() {
        return Err(AcquireErr::Blocked);
    }
    Ok(addrs[0])
}

/// Resolve + validate + connect a fresh upstream for a target. The returned
/// `Instant` is the connection's creation time (for pool lifetime tracking).
async fn connect_fresh<K: Connect>(
    connector: &K,
    target: &Target,
    security: &SecurityConfig,
    dns_client: &Arc<crate::dns::DnsClient>,
) -> Result<(K::Conn, std::time::Instant), AcquireErr> {
    let addr = resolve_target(&target.host, target.port, security, dns_client).await?;
    let conn = connector
        .connect(addr)
        .await
        .map_err(|_| AcquireErr::Failed)?;
    Ok((conn, std::time::Instant::now()))
}

// Minimal fixed error responses (the proxy never builds arbitrary responses).
const RESP_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESP_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESP_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const CONNECT_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const RESP_429: &[u8] =
    b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESP_413: &[u8] =
    b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Per-worker idle-connection pool keyed by (host, port). Lock-free: the engine
/// is thread-per-core, so a worker's tasks never run truly concurrently — an
/// `Rc<RefCell<_>>` is sufficient (no Mutex like the tokio/work-stealing pool).
/// Holds only *idle* connections; in-use ones are checked out by their task.
/// Bounded per-host and in total; over-cap check-ins are dropped (closed).
struct Pooled<C> {
    conn: C,
    created_at: std::time::Instant,
    idle_since: std::time::Instant,
}

pub struct ConnPool<C> {
    idle: HashMap<(String, u16), Vec<Pooled<C>>>,
    max_per_host: usize,
    max_total: usize,
    total: usize,
    /// Max time a connection may sit idle in the pool; zero = unlimited.
    idle_timeout: Duration,
    /// Max total age of a connection since creation; zero = unlimited.
    max_lifetime: Duration,
}

impl<C> ConnPool<C> {
    pub fn new(
        max_per_host: usize,
        max_total: usize,
        idle_timeout: Duration,
        max_lifetime: Duration,
    ) -> Self {
        ConnPool {
            idle: HashMap::new(),
            max_per_host,
            max_total,
            total: 0,
            idle_timeout,
            max_lifetime,
        }
    }

    /// Take a live idle connection for the target, returning it with its
    /// original `created_at` (so lifetime keeps counting). Expired entries are
    /// dropped (closed) while searching.
    fn checkout(&mut self, host: &str, port: u16) -> Option<(C, std::time::Instant)> {
        let now = std::time::Instant::now();
        let (idle_to, life) = (self.idle_timeout, self.max_lifetime);
        let mut removed = 0usize;
        let mut found = None;
        if let Some(bucket) = self.idle.get_mut(&(host.to_string(), port)) {
            while let Some(p) = bucket.pop() {
                removed += 1;
                let expired = (!idle_to.is_zero() && now.duration_since(p.idle_since) > idle_to)
                    || (!life.is_zero() && now.duration_since(p.created_at) > life);
                if !expired {
                    found = Some((p.conn, p.created_at));
                    break;
                }
                // else: expired — dropped (closed)
            }
        }
        self.total -= removed;
        found
    }

    /// Return a (healthy) connection to the pool with its `created_at`, honoring
    /// the caps. Resets the idle clock.
    fn checkin(&mut self, host: String, port: u16, conn: C, created_at: std::time::Instant) {
        if self.total >= self.max_total {
            return; // global cap: drop (close)
        }
        // Don't pool a connection already past its lifetime.
        if !self.max_lifetime.is_zero()
            && std::time::Instant::now().duration_since(created_at) > self.max_lifetime
        {
            return;
        }
        let bucket = self.idle.entry((host, port)).or_default();
        if bucket.len() < self.max_per_host {
            bucket.push(Pooled {
                conn,
                created_at,
                idle_since: std::time::Instant::now(),
            });
            self.total += 1;
        }
        // else per-host cap: drop (close)
    }

    /// Drop (close) every idle connection that is past its idle timeout or
    /// lifetime, and forget hosts left with none. `checkout` only expires
    /// entries for the host being asked for, so without this a connection to
    /// a host that is never visited again would stay open and keep counting
    /// against `max_total`. Returns how many were closed.
    fn sweep(&mut self, now: std::time::Instant) -> usize {
        let (idle_to, life) = (self.idle_timeout, self.max_lifetime);
        let mut removed = 0usize;
        self.idle.retain(|_, bucket| {
            let before = bucket.len();
            bucket.retain(|p| {
                let expired = (!idle_to.is_zero() && now.duration_since(p.idle_since) > idle_to)
                    || (!life.is_zero() && now.duration_since(p.created_at) > life);
                !expired
            });
            removed += before - bucket.len();
            !bucket.is_empty()
        });
        self.total -= removed;
        removed
    }
}

/// How often a worker sweeps its pool: half the shortest configured expiry,
/// kept between 1 and 30 seconds. `None` when connections never expire.
fn pool_sweep_interval(idle_timeout: Duration, max_lifetime: Duration) -> Option<Duration> {
    let shortest = [idle_timeout, max_lifetime]
        .into_iter()
        .filter(|d| !d.is_zero())
        .min()?;
    Some((shortest / 2).clamp(Duration::from_secs(1), Duration::from_secs(30)))
}

/// One worker's share of the configured pool-wide connection cap. Each worker
/// owns its own pool, so handing every worker the full cap would let the
/// process hold `workers` times the configured total.
fn per_worker_pool_cap(max_total: usize, workers: usize) -> usize {
    (max_total / workers.max(1)).max(1)
}

/// Shared per-worker pool handle.
pub type SharedPool<C> = Rc<RefCell<ConnPool<C>>>;

/// Build a fresh per-worker pool handle with the configured caps + TTLs.
fn new_pool<C>(
    max_per_host: usize,
    max_total: usize,
    idle_timeout: Duration,
    max_lifetime: Duration,
) -> SharedPool<C> {
    Rc::new(RefCell::new(ConnPool::new(
        max_per_host,
        max_total,
        idle_timeout,
        max_lifetime,
    )))
}

/// Outcome of admission control. `Reject(_)` carries the response bytes the
/// caller should write to the socket before closing it — distinguishing
/// rate-limit (429 + Retry-After) and capacity (503 + Retry-After) so the
/// client knows what to do. Allowlist rejections are silent on purpose:
/// unauthorized sources get no protocol-level signal back.
pub enum AdmitDecision {
    /// Accept the connection. `conns` has already been incremented; the caller
    /// must hold a `ConnGuard` to release it on task end.
    Allowed,
    /// Reject without sending anything (allowlist).
    SilentDrop,
    /// Reject and send these bytes to the socket before closing.
    Reject(&'static [u8]),
}

/// Admission control for a new client connection, shared by both runners:
/// source-IP allowlist, global connection cap, per-IP rate limit (checked once
/// per connection — for the per-request semantics gap see CODE_ANALYSIS_2 #5).
fn admit(
    cfg: &EngineConfig,
    limiter: &Mutex<RateLimiter>,
    conns: &AtomicUsize,
    peer: IpAddr,
) -> AdmitDecision {
    let allow = &cfg.security.allowed_source_ips;
    if !allow.is_empty() && !is_source_ip_allowed(&peer, allow) {
        return AdmitDecision::SilentDrop;
    }
    // Reserve a connection slot atomically. Previously a Relaxed load + later
    // fetch_add allowed N concurrent admits (across N worker threads) to all
    // pass the cap check before any incremented the counter — letting the
    // live count briefly reach `max + worker_count - 1`. The CAS loop below
    // makes the cap a strict ceiling and uses AcqRel ordering so the count
    // is observed consistently on weakly-ordered architectures.
    if cfg.max_connections > 0 {
        let mut cur = conns.load(Ordering::Acquire);
        loop {
            if cur >= cfg.max_connections {
                return AdmitDecision::Reject(crate::helpers::ACCEPT_CAPACITY_RESP);
            }
            match conns.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,                  // slot reserved
                Err(observed) => cur = observed, // someone else moved it; retry
            }
        }
    } else {
        // Unlimited: still need to track the count (ConnGuard decrements on
        // task end, and we may use it for observability), but no cap check.
        conns.fetch_add(1, Ordering::AcqRel);
    }
    // Rate-limit check AFTER the slot is reserved. If the limiter rejects we
    // must give the slot back so the cap stays accurate. (Order: cap before
    // limiter keeps capacity rejection cheaper than per-IP lookup.)
    if !limiter.lock().unwrap().is_allowed(peer) {
        conns.fetch_sub(1, Ordering::AcqRel);
        return AdmitDecision::Reject(crate::helpers::ACCEPT_RATELIMIT_RESP);
    }
    AdmitDecision::Allowed
}

/// Releases a reserved connection slot when the connection task ends.
struct ConnGuard(Arc<AtomicUsize>);
impl ConnGuard {
    fn new(conns: Arc<AtomicUsize>) -> Self {
        ConnGuard(conns)
    }
}
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Forward-proxy hot loop, written once for every runtime. Per request: frame it,
/// rewrite absolute-form -> origin-form (hop-by-hop stripped, XFF added), run the
/// SSRF checks (blocklist/ports/literal-IP via `is_blocked_target`, plus
/// DNS-rebinding on resolved IPs), then connect/reuse the upstream (per-host
/// pool) and relay. CONNECT requests are tunneled. Enforces the per-connection
/// request cap; the connect timeout lives in the connector.
pub async fn proxy_forward<K: Connect>(
    mut client: K::Conn,
    connector: K,
    cfg: Arc<EngineConfig>,
    client_ip: IpAddr,
    pool: SharedPool<K::Conn>,
) {
    let security = &cfg.security;
    let dns_client = &cfg.dns_client;
    let mut req_acc: BytesMut = BytesMut::with_capacity(512);
    // Fast 1-slot reuse for consecutive same-target requests on this client
    // connection — avoids touching the shared pool in the common case. Carries
    // the connection's created_at for pool lifetime accounting.
    let mut current: Option<(Target, K::Conn, std::time::Instant)> = None;
    let mut served: u32 = 0;
    // Header-read (slowloris) timeout + request body-size limit from config.
    let head_timeout = (!cfg.header_read_timeout.is_zero()).then_some(cfg.header_read_timeout);
    let max_body = cfg.max_request_body_bytes;

    loop {
        // Parse-once: pull metadata out of the framing pass and hand it to
        // rewrite_forward_with_metadata, which then skips its own httparse call.
        let (req, meta) =
            match relay_once_with_metadata(&mut client, &mut req_acc, true, head_timeout, max_body)
                .await
            {
                Ok(x) => x,
                Err(RelayErr::TooLarge) => {
                    let _ = client.write_all(RESP_413).await;
                    break;
                }
                Err(RelayErr::Closed) => break, // EOF / bad head / slowloris timeout
            };
        // Per-connection request cap.
        served += 1;
        if cfg.max_requests_per_conn > 0 && served > cfg.max_requests_per_conn {
            let _ = client.write_all(RESP_429).await;
            break;
        }
        let (target, head, body) =
            match rewrite_forward_with_metadata(&req, client_ip, meta.as_ref()) {
                Ok(x) => x,
                Err(ForwardError::IsConnect) => {
                    // CONNECT tunnel: validate target, connect, 200, then pump bytes.
                    let Some(target) = parse_connect_target(&req) else {
                        let _ = client.write_all(RESP_400).await;
                        break;
                    };
                    if is_blocked_target(&target.host, Some(target.port), security).is_some() {
                        let _ = client.write_all(RESP_403).await;
                        break;
                    }
                    if cfg.log_requests {
                        // Per-request at DEBUG (was INFO) — see proxy/connect.rs.
                        debug!(
                            client = %client_ip,
                            target = %format_args!("{}:{}", target.host, target.port),
                            "CONNECT tunnel"
                        );
                    }
                    // Release any pooled HTTP upstream we were holding.
                    if let Some((t, c, ca)) = current.take() {
                        pool.borrow_mut().checkin(t.host, t.port, c, ca);
                    }
                    // Resolve + validate (rebinding) + connect to the tunnel target.
                    let mut upstream =
                        match connect_fresh(&connector, &target, security, dns_client).await {
                            Ok((c, _)) => c, // tunnel conn isn't pooled; created_at unused
                            Err(AcquireErr::Blocked) => {
                                let _ = client.write_all(RESP_403).await;
                                break;
                            }
                            Err(AcquireErr::Failed) => {
                                let _ = client.write_all(RESP_502).await;
                                break;
                            }
                        };
                    if client.write_all(CONNECT_OK).await.is_err() {
                        break;
                    }
                    // Forward any bytes the client pipelined after the CONNECT head
                    // (e.g. an eager TLS ClientHello) before starting the pump.
                    if !req_acc.is_empty() && upstream.write_all(&req_acc).await.is_err() {
                        break;
                    }
                    K::tunnel(client, upstream).await; // consumes both; runs to close
                    return;
                }
                Err(_) => {
                    let _ = client.write_all(RESP_400).await;
                    break;
                }
            };
        // SSRF: blocklist / port allowlist / literal private-IP.
        if is_blocked_target(&target.host, Some(target.port), security).is_some() {
            let _ = client.write_all(RESP_403).await;
            break;
        }
        if cfg.log_requests {
            // Per-request at DEBUG (was INFO) — see proxy/connect.rs.
            debug!(
                client = %client_ip,
                host = %target.host,
                port = target.port,
                "HTTP forward"
            );
        }

        // What the response framing and the retry policy need to know about
        // the request. `head` is the rewritten head, so it starts with the method.
        let method = head.split(|&b| b == b' ').next().unwrap_or(&[]);
        let head_request = method == b"HEAD";
        let idempotent = is_idempotent_method(method);
        // 1xx interim responses are forwarded, except to HTTP/1.0 clients,
        // which don't know them (RFC 7231 §6.2).
        let forward_interim = meta.as_ref().is_none_or(|m| m.version != 0);

        // Acquire an upstream for this target: fast 1-slot, else pool, else
        // resolve+validate+connect. `reused` => might be a stale keep-alive.
        //
        // Non-idempotent requests (POST, PATCH, ...) always get a fresh
        // connection: if a reused keep-alive turned out to be dead we could
        // not tell whether the origin had already acted on the request, so we
        // could neither retry it safely nor avoid a spurious 502.
        let acquired = match current.take() {
            Some((t, c, ca)) if idempotent && t == target => Ok((c, ca, true)),
            held => {
                if let Some((t, c, ca)) = held {
                    pool.borrow_mut().checkin(t.host, t.port, c, ca); // park it
                }
                if idempotent {
                    acquire(&connector, &pool, &target, security, dns_client).await
                } else {
                    connect_fresh(&connector, &target, security, dns_client)
                        .await
                        .map(|(c, created_at)| (c, created_at, false))
                }
            }
        };
        let (mut conn, mut created_at, reused) = match acquired {
            Ok(triple) => triple,
            Err(AcquireErr::Blocked) => {
                let _ = client.write_all(RESP_403).await; // rebinding
                break;
            }
            Err(AcquireErr::Failed) => {
                let _ = client.write_all(RESP_502).await;
                break;
            }
        };

        // Round-trip. Retry once on a fresh connection only when it is safe:
        // the connection was a reused keep-alive, the request is idempotent,
        // and the upstream closed without sending a single response byte (the
        // signature of a stale idle connection). Anything else — a reset
        // mid-response, an unparseable response — is a 502, never a replay.
        let resp = match try_roundtrip(&mut conn, &head, &body, head_request, forward_interim).await
        {
            Ok(r) => r,
            Err(failed) if reused && idempotent && !failed.response_started => {
                let retried = match connect_fresh(&connector, &target, security, dns_client).await {
                    Ok((mut fresh, fresh_ca)) => {
                        match try_roundtrip(&mut fresh, &head, &body, head_request, forward_interim)
                            .await
                        {
                            Ok(r) => {
                                conn = fresh;
                                created_at = fresh_ca;
                                Some(r)
                            }
                            Err(_) => None,
                        }
                    }
                    Err(_) => None,
                };
                match retried {
                    Some(r) => r,
                    None => {
                        let _ = client.write_all(RESP_502).await;
                        break;
                    }
                }
            }
            Err(_) => {
                let _ = client.write_all(RESP_502).await;
                break;
            }
        };

        // Keep the upstream for the next request (fast path) only if it can
        // carry one; otherwise it is dropped (closed) here.
        if resp.reusable {
            current = Some((target, conn, created_at));
        }
        if client.write_all(&resp.bytes).await.is_err() {
            break;
        }
        // A close-delimited body has no length the client could use to find
        // its end; closing the client connection is what terminates it.
        if resp.close_client {
            break;
        }
    }

    // Return the live upstream (if any) to the pool for cross-connection reuse.
    if let Some((t, c, ca)) = current {
        pool.borrow_mut().checkin(t.host, t.port, c, ca);
    }
}

/// Get a connection for `target`: pooled if available (reused=true), else
/// resolve+validate+connect a fresh one (reused=false). Returns the connection,
/// its creation time (for lifetime tracking), and whether it was reused.
async fn acquire<K: Connect>(
    connector: &K,
    pool: &SharedPool<K::Conn>,
    target: &Target,
    security: &SecurityConfig,
    dns_client: &Arc<crate::dns::DnsClient>,
) -> Result<(K::Conn, std::time::Instant, bool), AcquireErr> {
    if let Some((c, created_at)) = pool.borrow_mut().checkout(&target.host, target.port) {
        return Ok((c, created_at, true));
    }
    connect_fresh(connector, target, security, dns_client)
        .await
        .map(|(c, created_at)| (c, created_at, false))
}

/// Methods a proxy may automatically retry (RFC 7231 §4.2.2). HTTP methods are
/// case-sensitive, so this is an exact match.
fn is_idempotent_method(method: &[u8]) -> bool {
    matches!(
        method,
        b"GET" | b"HEAD" | b"PUT" | b"DELETE" | b"OPTIONS" | b"TRACE"
    )
}

/// A complete upstream response, plus what it implies for both connections.
struct UpstreamResponse {
    /// Bytes to relay to the client: any forwarded 1xx interim responses
    /// followed by the final response.
    bytes: Bytes,
    /// The upstream connection can carry another request.
    reusable: bool,
    /// The body was delimited by upstream close, so the client connection must
    /// be closed after `bytes` to mark the end of the body.
    close_client: bool,
}

/// A round-trip that produced no usable response.
struct RoundtripFailed {
    /// Whether any response byte arrived before the failure. `false` is the
    /// only case in which the request may be replayed on another connection.
    response_started: bool,
}

/// Upper bound on 1xx interim responses per request, so an upstream can't keep
/// a worker reading them forever.
const MAX_INTERIM_RESPONSES: usize = 16;

/// One request->response round-trip on `conn`. Takes head and body separately
/// so the upstream write goes out as one `writev(2)` call (no head+body
/// concatenation copy) — `write_all_vectored` handles the fallback if vectored
/// I/O isn't available on the backend.
///
/// The response is framed with the response rules of RFC 7230 §3.3.3 (see
/// `scan_response`): `head_request` suppresses the body, 1xx interim responses
/// are skipped over (and relayed when `forward_interim`), and a response with
/// no declared length is read until the upstream closes.
async fn try_roundtrip<C: ProxyIo>(
    conn: &mut C,
    head: &Bytes,
    body: &Bytes,
    head_request: bool,
    forward_interim: bool,
) -> Result<UpstreamResponse, RoundtripFailed> {
    if conn.write_all_vectored(head, body).await.is_err() {
        return Err(RoundtripFailed {
            response_started: false,
        });
    }
    // No head timeout / body limit on upstream responses (we trust the origin;
    // bunker's hyper path likewise doesn't size-limit responses).
    let mut acc: BytesMut = BytesMut::with_capacity(512);
    let mut interim: Option<BytesMut> = None; // forwarded 1xx bytes, if any
    let mut interim_count = 0usize;
    // Prepend any forwarded interim responses to the final response bytes.
    let assemble = |interim: Option<BytesMut>, rest: BytesMut| match interim {
        Some(mut pre) => {
            pre.extend_from_slice(&rest);
            pre.freeze()
        }
        None => rest.freeze(), // common case: zero-copy
    };
    loop {
        match scan_response(&acc, head_request) {
            ResponseScan::Complete {
                total,
                interim: true,
                ..
            } => {
                interim_count += 1;
                if interim_count > MAX_INTERIM_RESPONSES {
                    return Err(RoundtripFailed {
                        response_started: true,
                    });
                }
                let msg = acc.split_to(total);
                if forward_interim {
                    interim
                        .get_or_insert_with(BytesMut::new)
                        .extend_from_slice(&msg);
                }
                // The final response follows; rescan what's already buffered.
            }
            ResponseScan::Complete {
                total, keep_alive, ..
            } => {
                let msg = acc.split_to(total);
                // Bytes after the response mean the upstream is out of step
                // with us; such a connection must not carry another request.
                let reusable = keep_alive && acc.is_empty();
                return Ok(UpstreamResponse {
                    bytes: assemble(interim, msg),
                    reusable,
                    close_client: false,
                });
            }
            ResponseScan::UntilClose { .. } => {
                loop {
                    match conn.read_append(&mut acc).await {
                        Ok(0) => break, // upstream closed: end of body
                        Ok(_) => {}
                        Err(_) => {
                            return Err(RoundtripFailed {
                                response_started: true,
                            })
                        }
                    }
                }
                return Ok(UpstreamResponse {
                    bytes: assemble(interim, acc),
                    reusable: false,
                    close_client: true,
                });
            }
            ResponseScan::Error(_) => {
                return Err(RoundtripFailed {
                    response_started: true,
                })
            }
            ResponseScan::Incomplete => match conn.read_append(&mut acc).await {
                Ok(n) if n > 0 => {}
                // EOF or I/O error before a full response.
                _ => {
                    return Err(RoundtripFailed {
                        response_started: interim_count > 0 || !acc.is_empty(),
                    })
                }
            },
        }
    }
}

/// Relay one client connection against one upstream connection for their shared
/// lifetime (HTTP/1 keep-alive): request -> upstream, response -> client, repeat
/// until either closes or a message is rejected. This is the entire proxy hot
/// loop, written once for every runtime.
pub async fn proxy_pair<C: ProxyIo>(mut client: C, mut upstream: C) {
    let mut req_acc: BytesMut = BytesMut::with_capacity(512);
    let mut resp_acc: BytesMut = BytesMut::with_capacity(512);
    loop {
        let Ok(req) = relay_once(&mut client, &mut req_acc, true, None, 0).await else {
            return;
        };
        if upstream.write_all(&req).await.is_err() {
            return;
        }
        let Ok(resp) = relay_once(&mut upstream, &mut resp_acc, false, None, 0).await else {
            return;
        };
        if client.write_all(&resp).await.is_err() {
            return;
        }
    }
}

// ===================== tokio backend (portable) =====================

mod tokio_backend {
    use super::{proxy_forward, proxy_pair, ConnGuard, Connect, EngineConfig, ProxyIo};
    use crate::security::RateLimiter;
    use bytes::BytesMut;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// `ProxyIo` over a tokio TcpStream.
    pub struct TokioConn(pub tokio::net::TcpStream);

    impl ProxyIo for TokioConn {
        async fn read_append(&mut self, acc: &mut BytesMut) -> std::io::Result<usize> {
            // read_buf appends into the BytesMut's spare capacity (BytesMut: BufMut).
            self.0.read_buf(acc).await
        }
        async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.0.write_all(data).await
        }
        /// Vectored write: one `writev(2)` syscall for head + body when both
        /// fit, falling back to `write_all` for any leftover bytes on a
        /// partial write. The common case (TCP loopback, kernel buffer space
        /// available) is a single syscall — the actual zero-copy win when
        /// proxying a rewritten head followed by an unmodified body slice.
        async fn write_all_vectored(&mut self, head: &[u8], body: &[u8]) -> std::io::Result<()> {
            if head.is_empty() {
                return self.0.write_all(body).await;
            }
            if body.is_empty() {
                return self.0.write_all(head).await;
            }
            let bufs = [std::io::IoSlice::new(head), std::io::IoSlice::new(body)];
            let total = head.len() + body.len();
            let n = self.0.write_vectored(&bufs).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "write_vectored returned 0",
                ));
            }
            if n == total {
                return Ok(());
            }
            // Partial write — uncommon on loopback, but handle it. Finish with
            // sequential write_all; cheaper than reconstructing IoSlices.
            if n < head.len() {
                self.0.write_all(&head[n..]).await?;
                self.0.write_all(body).await
            } else {
                self.0.write_all(&body[n - head.len()..]).await
            }
        }
        async fn read_append_timeout(
            &mut self,
            acc: &mut BytesMut,
            dur: std::time::Duration,
        ) -> std::io::Result<usize> {
            tokio::time::timeout(dur, self.0.read_buf(acc))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "header read timeout")
                })?
        }
    }

    /// Opens upstream connections via tokio. Hostname resolution is delegated
    /// to the shared `DnsClient` in `EngineConfig` — this connector only deals
    /// with already-resolved addresses.
    pub struct TokioConnector {
        pub connect_timeout: std::time::Duration,
    }
    impl Connect for TokioConnector {
        type Conn = TokioConn;
        async fn connect(&self, addr: SocketAddr) -> std::io::Result<TokioConn> {
            let connect = tokio::net::TcpStream::connect(addr);
            let stream = if self.connect_timeout.is_zero() {
                connect.await?
            } else {
                tokio::time::timeout(self.connect_timeout, connect)
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")
                    })??
            };
            let _ = stream.set_nodelay(true);
            Ok(TokioConn(stream))
        }
        async fn tunnel(mut client: TokioConn, mut upstream: TokioConn) {
            // tokio's built-in bidirectional copy (32 KiB buffers each way).
            let _ = tokio::io::copy_bidirectional(&mut client.0, &mut upstream.0).await;
        }
    }

    /// Forward-proxy runner (tokio): acceptor/thread-per-core distribution, each
    /// connection served by `proxy_forward`. On accept it enforces the source-IP
    /// allowlist, the global connection cap (shared atomic), and per-IP rate
    /// limiting (shared, checked once per connection). Per-worker pool + a
    /// timeout-configured connector come from `cfg`.
    pub fn run_forward(
        listen: SocketAddr,
        cfg: Arc<EngineConfig>,
        threads: usize,
    ) -> std::io::Result<()> {
        let listener = reuseaddr_listener(listen)?;
        // Shared across workers: per-IP rate limiter + global connection count.
        let limiter = Arc::new(Mutex::new(RateLimiter::new(cfg.rate_limit.clone())));
        let conns = Arc::new(AtomicUsize::new(0));
        let mut senders = Vec::with_capacity(threads);
        let mut workers = Vec::with_capacity(threads);
        for _ in 0..threads {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<std::net::TcpStream>();
            senders.push(tx);
            let cfg = Arc::clone(&cfg);
            let limiter = Arc::clone(&limiter);
            let conns = Arc::clone(&conns);
            workers.push(std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("current_thread runtime");
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    let pool = super::new_pool::<TokioConn>(
                        cfg.pool_max_per_host,
                        super::per_worker_pool_cap(cfg.pool_max_total, threads),
                        cfg.pool_idle_timeout,
                        cfg.pool_max_lifetime,
                    );
                    if let Some(every) =
                        super::pool_sweep_interval(cfg.pool_idle_timeout, cfg.pool_max_lifetime)
                    {
                        let pool = pool.clone();
                        tokio::task::spawn_local(async move {
                            loop {
                                tokio::time::sleep(every).await;
                                pool.borrow_mut().sweep(std::time::Instant::now());
                            }
                        });
                    }
                    while let Some(std_stream) = rx.recv().await {
                        let _ = std_stream.set_nonblocking(true);
                        let peer = std_stream
                            .peer_addr()
                            .map(|a| a.ip())
                            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        // Convert before admit so we can write the rejection
                        // response back to the client on the Reject branch.
                        let mut client = match tokio::net::TcpStream::from_std(std_stream) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        match super::admit(&cfg, &limiter, &conns, peer) {
                            super::AdmitDecision::Allowed => {}
                            super::AdmitDecision::SilentDrop => continue,
                            super::AdmitDecision::Reject(bytes) => {
                                let _ = client.write_all(bytes).await;
                                continue;
                            }
                        }
                        let guard = ConnGuard::new(Arc::clone(&conns)); // dec on task end
                        let _ = client.set_nodelay(true);
                        let cfg = Arc::clone(&cfg);
                        let pool = pool.clone();
                        let connector = TokioConnector {
                            connect_timeout: cfg.connect_timeout,
                        };
                        tokio::task::spawn_local(async move {
                            let _g = guard;
                            proxy_forward(TokioConn(client), connector, cfg, peer, pool).await;
                        });
                    }
                });
            }));
        }
        accept_loop(listener, &senders, threads);
        for w in workers {
            let _ = w.join();
        }
        Ok(())
    }

    /// Portable thread-per-core runner: one blocking acceptor distributes
    /// accepted sockets round-robin to N `current_thread` + `LocalSet` workers.
    /// No SO_REUSEPORT, so it works on Windows as well as Linux; each connection
    /// is pinned to one worker thread (shared-nothing, no work-stealing).
    pub fn run(listen: SocketAddr, upstream: SocketAddr, threads: usize) -> std::io::Result<()> {
        let listener = reuseaddr_listener(listen)?;
        let mut senders = Vec::with_capacity(threads);
        let mut workers = Vec::with_capacity(threads);

        for _ in 0..threads {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<std::net::TcpStream>();
            senders.push(tx);
            workers.push(std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("current_thread runtime");
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    while let Some(std_stream) = rx.recv().await {
                        let _ = std_stream.set_nonblocking(true);
                        let client = match tokio::net::TcpStream::from_std(std_stream) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let _ = client.set_nodelay(true);
                        tokio::task::spawn_local(async move {
                            if let Ok(up) = tokio::net::TcpStream::connect(upstream).await {
                                let _ = up.set_nodelay(true);
                                proxy_pair(TokioConn(client), TokioConn(up)).await;
                            }
                        });
                    }
                });
            }));
        }
        accept_loop(listener, &senders, threads);
        for w in workers {
            let _ = w.join();
        }
        Ok(())
    }

    /// SO_REUSEADDR listener (single shared, acceptor model — no REUSEPORT) so a
    /// restart doesn't fail while the old listener is in TIME_WAIT.
    fn reuseaddr_listener(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        sock.set_reuse_address(true)?;
        sock.bind(&addr.into())?;
        sock.listen(1024)?;
        Ok(sock.into())
    }

    /// Blocking accept loop on the calling thread; round-robins sockets to workers.
    fn accept_loop(
        listener: std::net::TcpListener,
        senders: &[tokio::sync::mpsc::UnboundedSender<std::net::TcpStream>],
        threads: usize,
    ) {
        let mut i = 0usize;
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            if senders[i % threads].send(stream).is_err() {
                break;
            }
            i += 1;
        }
    }
}

#[allow(unused_imports)] // used by examples (separate crates), not the lib/bin
pub use tokio_backend::{
    run as run_tokio, run_forward as run_tokio_forward, TokioConn, TokioConnector,
};

// ===================== monoio backend (Linux / io_uring) =====================

#[cfg(all(feature = "engine-uring", target_os = "linux"))]
mod monoio_backend {
    use super::{proxy_forward, proxy_pair, ConnGuard, Connect, EngineConfig, ProxyIo};
    use crate::security::RateLimiter;
    use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
    use monoio::net::{TcpListener, TcpStream};
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    /// `ProxyIo` over a monoio io_uring TcpStream. Bridges monoio's owned-buffer
    /// completion model to the accumulator interface, reusing read/write buffers
    /// so the hot path doesn't allocate per operation.
    pub struct MonoConn {
        stream: TcpStream,
        rbuf: Vec<u8>,
        wbuf: Vec<u8>,
    }

    impl MonoConn {
        fn new(stream: TcpStream) -> Self {
            MonoConn {
                stream,
                rbuf: vec![0u8; 16 * 1024],
                wbuf: Vec::with_capacity(16 * 1024),
            }
        }
    }

    impl ProxyIo for MonoConn {
        async fn read_append(&mut self, acc: &mut bytes::BytesMut) -> std::io::Result<usize> {
            // monoio uses owned-buffer completion IO, so we read into the
            // recycled rbuf and append the result into the caller's BytesMut.
            // The append is a single memcpy of the just-read bytes — the
            // zero-copy win is on the OTHER side (relay_once's split_to+freeze
            // on the BytesMut, which doesn't copy at all).
            let buf = std::mem::take(&mut self.rbuf);
            let (res, buf) = self.stream.read(buf).await;
            match res {
                Ok(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    self.rbuf = buf;
                    Ok(n)
                }
                Err(e) => {
                    self.rbuf = buf;
                    Err(e)
                }
            }
        }
        async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
            let mut buf = std::mem::take(&mut self.wbuf);
            buf.clear();
            buf.extend_from_slice(data);
            let (res, buf) = self.stream.write_all(buf).await;
            self.wbuf = buf;
            res.map(|_| ())
        }
        // Note: monoio backend uses the default `write_all_vectored` (two
        // sequential write_all calls). monoio's TcpStream doesn't expose a
        // simple writev for arbitrary borrowed slices — using its
        // owned-buffer API for two-slot vectored writes would require an
        // extra buffer concatenation, defeating the purpose. The tokio
        // backend gets the writev win; monoio gets correctness.
        async fn read_append_timeout(
            &mut self,
            acc: &mut bytes::BytesMut,
            dur: std::time::Duration,
        ) -> std::io::Result<usize> {
            // monoio::time::timeout works on the io_uring runtime (timer enabled).
            match monoio::time::timeout(dur, self.read_append(acc)).await {
                Ok(r) => r,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "header read timeout",
                )),
            }
        }
    }

    /// Thread-per-core io_uring runner: each worker has its own monoio runtime
    /// and its own SO_REUSEPORT listener; the kernel load-balances connections.
    pub fn run(listen: SocketAddr, upstream: SocketAddr, threads: usize) -> std::io::Result<()> {
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            handles.push(std::thread::spawn(move || worker(listen, upstream)));
        }
        for h in handles {
            let _ = h.join();
        }
        Ok(())
    }

    fn worker(listen: SocketAddr, upstream: SocketAddr) {
        let std_listener = reuseport_listener(listen);
        let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .expect("monoio runtime");
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).expect("from_std");
            loop {
                match listener.accept().await {
                    Ok((client, _)) => {
                        monoio::spawn(handle(client, upstream));
                    }
                    Err(_) => continue,
                }
            }
        });
    }

    async fn handle(client: TcpStream, upstream: SocketAddr) {
        let _ = client.set_nodelay(true);
        let up = match TcpStream::connect(upstream).await {
            Ok(s) => s,
            Err(_) => return,
        };
        let _ = up.set_nodelay(true);
        proxy_pair(MonoConn::new(client), MonoConn::new(up)).await;
    }

    fn reuseport_listener(addr: SocketAddr) -> std::net::TcpListener {
        let sock =
            Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP)).unwrap();
        sock.set_reuse_address(true).unwrap();
        sock.set_reuse_port(true).unwrap();
        sock.set_nonblocking(true).unwrap();
        sock.bind(&addr.into()).unwrap();
        sock.listen(1024).unwrap();
        sock.into()
    }

    /// Opens upstream connections via monoio. Hostname resolution is now
    /// delegated to the shared `DnsClient` in `EngineConfig` — both the
    /// Upstream variant (forwards via the configured DNS upstreams) and the
    /// Os variant (wraps `os_resolve`, with optional caching) are fully async
    /// and cross-runtime-safe (the DNS work runs on the tokio main runtime,
    /// not on the monoio per-core worker, via the spawned DNS server task).
    /// This connector only deals with already-resolved addresses.
    pub struct MonoConnector {
        pub connect_timeout: std::time::Duration,
    }
    impl Connect for MonoConnector {
        type Conn = MonoConn;
        async fn connect(&self, addr: SocketAddr) -> std::io::Result<MonoConn> {
            let connect = TcpStream::connect_addr(addr);
            let stream = if self.connect_timeout.is_zero() {
                connect.await?
            } else {
                monoio::time::timeout(self.connect_timeout, connect)
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")
                    })??
            };
            let _ = stream.set_nodelay(true);
            Ok(MonoConn::new(stream))
        }
        async fn tunnel(client: MonoConn, upstream: MonoConn) {
            // monoio has no copy_bidirectional: split each stream and run both
            // unidirectional copies concurrently on this thread via join!.
            use monoio::io::Splitable;
            let (mut cr, mut cw) = client.stream.into_split();
            let (mut ur, mut uw) = upstream.stream.into_split();
            let _ = monoio::join!(
                monoio::io::copy(&mut cr, &mut uw), // client -> upstream
                monoio::io::copy(&mut ur, &mut cw), // upstream -> client
            );
        }
    }

    /// Forward-proxy runner (io_uring): per-core monoio runtime + SO_REUSEPORT.
    /// Admission control (source-IP allowlist, global connection cap, per-IP rate
    /// limit) is shared across workers; the per-worker pool + timeout-configured
    /// connector come from `cfg`.
    pub fn run_forward(
        listen: SocketAddr,
        cfg: Arc<EngineConfig>,
        threads: usize,
    ) -> std::io::Result<()> {
        let limiter = Arc::new(Mutex::new(RateLimiter::new(cfg.rate_limit.clone())));
        let conns = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let cfg = Arc::clone(&cfg);
            let limiter = Arc::clone(&limiter);
            let conns = Arc::clone(&conns);
            handles.push(std::thread::spawn(move || {
                worker_forward(listen, cfg, limiter, conns, threads)
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        Ok(())
    }

    fn worker_forward(
        listen: SocketAddr,
        cfg: Arc<EngineConfig>,
        limiter: Arc<Mutex<RateLimiter>>,
        conns: Arc<AtomicUsize>,
        threads: usize,
    ) {
        let std_listener = reuseport_listener(listen);
        let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .expect("monoio runtime");
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).expect("from_std");
            let pool = super::new_pool::<MonoConn>(
                cfg.pool_max_per_host,
                super::per_worker_pool_cap(cfg.pool_max_total, threads),
                cfg.pool_idle_timeout,
                cfg.pool_max_lifetime,
            );
            if let Some(every) =
                super::pool_sweep_interval(cfg.pool_idle_timeout, cfg.pool_max_lifetime)
            {
                let pool = pool.clone();
                monoio::spawn(async move {
                    loop {
                        monoio::time::sleep(every).await;
                        pool.borrow_mut().sweep(std::time::Instant::now());
                    }
                });
            }
            loop {
                match listener.accept().await {
                    Ok((mut client, peer)) => {
                        let peer_ip = peer.ip();
                        match super::admit(&cfg, &limiter, &conns, peer_ip) {
                            super::AdmitDecision::Allowed => {}
                            super::AdmitDecision::SilentDrop => continue,
                            super::AdmitDecision::Reject(bytes) => {
                                // monoio's write_all takes ownership; the
                                // to_vec() copy is only paid on reject paths.
                                let (_res, _buf) = client.write_all(bytes.to_vec()).await;
                                continue;
                            }
                        }
                        let guard = ConnGuard::new(Arc::clone(&conns));
                        let _ = client.set_nodelay(true);
                        let cfg = Arc::clone(&cfg);
                        let pool = pool.clone();
                        let connector = MonoConnector {
                            connect_timeout: cfg.connect_timeout,
                        };
                        monoio::spawn(async move {
                            let _g = guard;
                            proxy_forward(MonoConn::new(client), connector, cfg, peer_ip, pool)
                                .await;
                        });
                    }
                    Err(_) => continue,
                }
            }
        });
    }
}

#[cfg(all(feature = "engine-uring", target_os = "linux"))]
#[allow(unused_imports)]
pub use monoio_backend::{
    run as run_monoio, run_forward as run_monoio_forward, MonoConn, MonoConnector,
};

// ===================== platform-selecting entry point =====================

/// Which runtime backend to drive the shared proxy engine with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Best for the platform: io_uring (monoio) on Linux, tokio elsewhere.
    Auto,
    /// Portable thread-per-core tokio (works everywhere, incl. Windows).
    Tokio,
    /// io_uring (monoio) — Linux only.
    Uring,
}

impl Backend {
    pub fn parse(s: &str) -> Option<Backend> {
        match s {
            "auto" => Some(Backend::Auto),
            "tokio" => Some(Backend::Tokio),
            "uring" => Some(Backend::Uring),
            _ => None,
        }
    }
}

/// Run the proxy with the chosen backend, selecting per platform. `Auto` uses
/// io_uring on Linux and tokio everywhere else; `Uring` is rejected off Linux.
/// The same `ProxyIo` core runs underneath regardless.
pub fn run(
    listen: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    threads: usize,
    backend: Backend,
) -> std::io::Result<()> {
    // Auto picks io_uring only when that backend was actually compiled in
    // (engine-uring + Linux); otherwise the portable tokio backend.
    let resolved = match backend {
        Backend::Auto => {
            if cfg!(all(feature = "engine-uring", target_os = "linux")) {
                Backend::Uring
            } else {
                Backend::Tokio
            }
        }
        b => b,
    };
    match resolved {
        Backend::Tokio => run_tokio(listen, upstream, threads),
        Backend::Uring => {
            #[cfg(all(feature = "engine-uring", target_os = "linux"))]
            {
                run_monoio(listen, upstream, threads)
            }
            #[cfg(not(all(feature = "engine-uring", target_os = "linux")))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "io_uring backend not built (enable feature `engine-uring` on Linux)",
                ))
            }
        }
        Backend::Auto => unreachable!("resolved above"),
    }
}

/// Run the FORWARD proxy (per-request routing + SSRF) with the chosen backend,
/// selecting per platform exactly like `run`. No fixed upstream — each request's
/// target is parsed and routed. `security` drives the source-IP allowlist and
/// the SSRF blocklist.
pub fn run_forward(
    listen: std::net::SocketAddr,
    cfg: Arc<EngineConfig>,
    threads: usize,
    backend: Backend,
) -> std::io::Result<()> {
    let resolved = match backend {
        Backend::Auto => {
            if cfg!(all(feature = "engine-uring", target_os = "linux")) {
                Backend::Uring
            } else {
                Backend::Tokio
            }
        }
        b => b,
    };
    match resolved {
        Backend::Tokio => run_tokio_forward(listen, cfg, threads),
        Backend::Uring => {
            #[cfg(all(feature = "engine-uring", target_os = "linux"))]
            {
                run_monoio_forward(listen, cfg, threads)
            }
            #[cfg(not(all(feature = "engine-uring", target_os = "linux")))]
            {
                let _ = cfg;
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "io_uring backend not built (enable feature `engine-uring` on Linux)",
                ))
            }
        }
        Backend::Auto => unreachable!("resolved above"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory ProxyIo: replays scripted read chunks, captures writes.
    struct MockConn {
        reads: std::collections::VecDeque<Vec<u8>>,
        written: Vec<u8>,
    }
    impl MockConn {
        fn new(chunks: Vec<&[u8]>) -> Self {
            MockConn {
                reads: chunks.into_iter().map(|c| c.to_vec()).collect(),
                written: Vec::new(),
            }
        }
    }
    impl ProxyIo for MockConn {
        async fn read_append(&mut self, acc: &mut bytes::BytesMut) -> std::io::Result<usize> {
            match self.reads.pop_front() {
                Some(chunk) => {
                    acc.extend_from_slice(&chunk);
                    Ok(chunk.len())
                }
                None => Ok(0), // EOF
            }
        }
        async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.written.extend_from_slice(data);
            Ok(())
        }
    }

    // A tiny single-threaded executor so we can drive the async core in tests
    // without pulling in a runtime.
    fn block_on<F: std::future::Future>(mut fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VT)
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VT)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = unsafe { std::pin::Pin::new_unchecked(&mut fut) };
        loop {
            // MockConn never returns Pending, so a single poll suffices; loop for safety.
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn relay_one_request_reassembled_across_chunks() {
        // Head split across two reads, then the body.
        let mut conn = MockConn::new(vec![
            b"POST / HTTP/1.1\r\nHost: x\r\n",
            b"Content-Length: 5\r\n\r\nhel",
            b"lo",
        ]);
        let mut acc = bytes::BytesMut::new();
        let msg = block_on(relay_once(&mut conn, &mut acc, true, None, 0)).expect("complete");
        assert_eq!(
            &msg[..],
            &b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"[..]
        );
        assert!(acc.is_empty());
    }

    #[test]
    fn relay_leaves_pipelined_remainder() {
        let mut conn = MockConn::new(vec![
            b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n",
        ]);
        let mut acc = bytes::BytesMut::new();
        let first = block_on(relay_once(&mut conn, &mut acc, true, None, 0)).expect("first");
        assert_eq!(&first[..], &b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"[..]);
        // The second request stays buffered for the next call.
        let second = block_on(relay_once(&mut conn, &mut acc, true, None, 0)).expect("second");
        assert_eq!(&second[..], &b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n"[..]);
    }

    #[test]
    fn relay_rejects_smuggling() {
        let mut conn = MockConn::new(vec![
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ]);
        let mut acc = bytes::BytesMut::new();
        assert!(block_on(relay_once(&mut conn, &mut acc, true, None, 0)).is_err());
    }

    #[test]
    fn relay_eof_returns_none() {
        let mut conn = MockConn::new(vec![]); // immediate EOF
        let mut acc = bytes::BytesMut::new();
        assert!(block_on(relay_once(&mut conn, &mut acc, true, None, 0)).is_err());
    }

    #[test]
    fn proxy_pair_relays_request_and_response() {
        // client sends one GET; upstream replies once; then both EOF.
        let client = MockConn::new(vec![b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"]);
        let upstream = MockConn::new(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"]);
        // We need to inspect writes afterward; run and check via a wrapper.
        let mut client = client;
        let mut upstream = upstream;
        block_on(async {
            // inline the loop once to capture written buffers
            let mut req_acc = bytes::BytesMut::new();
            let req = relay_once(&mut client, &mut req_acc, true, None, 0)
                .await
                .unwrap();
            upstream.write_all(&req).await.unwrap();
            let mut resp_acc = bytes::BytesMut::new();
            let resp = relay_once(&mut upstream, &mut resp_acc, false, None, 0)
                .await
                .unwrap();
            client.write_all(&resp).await.unwrap();
        });
        assert_eq!(&upstream.written, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(
            &client.written,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        );
    }

    /// Stub Connect that panics on any use — proves resolve_target's literal-IP
    /// branch never touches DNS or TCP (no .connect()).
    struct PanicConnect;
    impl Connect for PanicConnect {
        type Conn = MockConn;
        async fn connect(&self, _: SocketAddr) -> std::io::Result<MockConn> {
            unreachable!("connect must not be called from resolve_target")
        }
        async fn tunnel(_: MockConn, _: MockConn) {
            unreachable!()
        }
    }

    /// DnsClient::Os with `cache: None` — a literal-IP target never reaches
    /// the resolver, so the cache doesn't matter; this is the minimal client
    /// we can construct for tests that exercise the literal-IP shortcut.
    fn panic_client() -> Arc<crate::dns::DnsClient> {
        Arc::new(crate::dns::DnsClient::new_os(None))
    }

    /// Verifies the defense-in-depth check: resolve_target rejects private
    /// literal IPs on its own (no upstream is_blocked_target needed) when
    /// block_private_ips is on, including the IPv4-mapped IPv6 form.
    #[test]
    fn resolve_target_blocks_literal_private_ip_defense_in_depth() {
        let mut sec = SecurityConfig::default();
        sec.block_private_ips = true;
        let dns = panic_client();

        // Native IPv4 private.
        assert!(matches!(
            block_on(resolve_target("127.0.0.1", 80, &sec, &dns)),
            Err(AcquireErr::Blocked)
        ));

        // IPv4-mapped IPv6 private (the bypass class — the one we just fixed
        // in is_private_ip; this test proves the protection also applies at
        // resolve_target's literal-IP short-circuit).
        assert!(matches!(
            block_on(resolve_target("::ffff:127.0.0.1", 80, &sec, &dns)),
            Err(AcquireErr::Blocked)
        ));

        // Public IP must pass through (literal-IP shortcut: doesn't call DnsClient).
        assert!(block_on(resolve_target("8.8.8.8", 80, &sec, &dns)).is_ok());

        // When block_private_ips is OFF, private literal IPs are allowed (sanity).
        let mut off = SecurityConfig::default();
        off.block_private_ips = false;
        assert!(block_on(resolve_target("127.0.0.1", 80, &off, &dns)).is_ok());
    }

    // ---- proxy_forward end-to-end over scripted connections ----

    /// A `MockConn` behind a shared handle, so a test can keep inspecting what
    /// was written after `proxy_forward` has taken ownership of the connection.
    #[derive(Clone)]
    struct SharedConn(Rc<std::cell::RefCell<MockConn>>);
    impl SharedConn {
        fn new(chunks: Vec<&[u8]>) -> Self {
            SharedConn(Rc::new(std::cell::RefCell::new(MockConn::new(chunks))))
        }
        fn written(&self) -> String {
            String::from_utf8_lossy(&self.0.borrow().written).into_owned()
        }
    }
    impl ProxyIo for SharedConn {
        async fn read_append(&mut self, acc: &mut bytes::BytesMut) -> std::io::Result<usize> {
            match self.0.borrow_mut().reads.pop_front() {
                Some(chunk) => {
                    acc.extend_from_slice(&chunk);
                    Ok(chunk.len())
                }
                None => Ok(0), // EOF
            }
        }
        async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.0.borrow_mut().written.extend_from_slice(data);
            Ok(())
        }
    }

    /// Hands out pre-scripted upstream connections in order. A connect beyond
    /// the script fails (-> 502), so `connects()` tells how many were opened.
    #[derive(Clone)]
    struct ScriptConnect {
        upstreams: Rc<std::cell::RefCell<std::collections::VecDeque<SharedConn>>>,
        connects: Rc<std::cell::Cell<usize>>,
    }
    impl ScriptConnect {
        fn new(upstreams: &[SharedConn]) -> Self {
            ScriptConnect {
                upstreams: Rc::new(std::cell::RefCell::new(upstreams.iter().cloned().collect())),
                connects: Rc::new(std::cell::Cell::new(0)),
            }
        }
        fn connects(&self) -> usize {
            self.connects.get()
        }
    }
    impl Connect for ScriptConnect {
        type Conn = SharedConn;
        async fn connect(&self, _: SocketAddr) -> std::io::Result<SharedConn> {
            self.connects.set(self.connects.get() + 1);
            self.upstreams
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| std::io::Error::other("no scripted upstream left"))
        }
        async fn tunnel(_: SharedConn, _: SharedConn) {
            unreachable!("no CONNECT in these tests")
        }
    }

    fn forward_test_config() -> Arc<EngineConfig> {
        Arc::new(EngineConfig {
            security: Arc::new(SecurityConfig::default()),
            dns_client: panic_client(), // targets are literal IPs: never resolved
            rate_limit: RateLimitConfig::default(),
            pool_max_per_host: 4,
            pool_max_total: 16,
            pool_idle_timeout: Duration::ZERO,
            pool_max_lifetime: Duration::ZERO,
            connect_timeout: Duration::ZERO,
            header_read_timeout: Duration::ZERO,
            max_request_body_bytes: 0,
            max_requests_per_conn: 0,
            max_connections: 0,
            log_requests: false,
        })
    }

    /// Run `proxy_forward` for one client connection sending `requests` (one
    /// read each), against the scripted `upstreams`. Returns what the client
    /// received and the connector (for its connect count).
    fn run_forward_test(requests: Vec<&[u8]>, upstreams: &[SharedConn]) -> (String, ScriptConnect) {
        let client = SharedConn::new(requests);
        let connector = ScriptConnect::new(upstreams);
        let pool = new_pool(4, 16, Duration::ZERO, Duration::ZERO);
        block_on(proxy_forward(
            client.clone(),
            connector.clone(),
            forward_test_config(),
            "10.0.0.7".parse().unwrap(),
            pool,
        ));
        (client.written(), connector)
    }

    const GET: &[u8] = b"GET http://93.184.216.34/a HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n";
    const OK_2: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";

    /// Regression: a chunked upload reached the origin without its
    /// Transfer-Encoding header, so the chunk bytes parsed as a second request.
    #[test]
    fn forward_chunked_upload_keeps_its_framing() {
        let upstream = SharedConn::new(vec![OK_2]);
        let (client, _) = run_forward_test(
            vec![
                b"POST http://93.184.216.34/up HTTP/1.1\r\nHost: 93.184.216.34\r\n\
                   Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            ],
            &[upstream.clone()],
        );
        let sent = upstream.written();
        assert!(sent.starts_with("POST /up HTTP/1.1\r\n"), "{sent}");
        assert!(sent.contains("Transfer-Encoding: chunked\r\n"), "{sent}");
        assert!(sent.ends_with("\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), "{sent}");
        assert_eq!(client.as_bytes(), OK_2);
    }

    /// Regression: a HEAD response advertising a Content-Length made the proxy
    /// wait for a body that never comes. It must complete at the head, and the
    /// upstream connection must stay usable for the next request.
    #[test]
    fn forward_head_response_has_no_body() {
        let head_resp: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 1256\r\n\r\n";
        let upstream = SharedConn::new(vec![head_resp, OK_2]);
        let (client, connector) = run_forward_test(
            vec![
                b"HEAD http://93.184.216.34/a HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n",
                GET,
            ],
            &[upstream],
        );
        let expected = [head_resp, OK_2].concat();
        assert_eq!(client.as_bytes(), &expected[..]);
        assert_eq!(connector.connects(), 1, "upstream should be reused");
    }

    /// Regression: `100 Continue` was returned as the whole response and the
    /// real one stayed queued on the upstream, to be served to the next request.
    #[test]
    fn forward_interim_response_is_followed_by_the_final_one() {
        let upstream = SharedConn::new(vec![
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst",
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond",
        ]);
        let (client, connector) = run_forward_test(
            vec![
                b"PUT http://93.184.216.34/a HTTP/1.1\r\nHost: 93.184.216.34\r\n\
                  Expect: 100-continue\r\nContent-Length: 1\r\n\r\nx",
                GET,
            ],
            &[upstream],
        );
        assert_eq!(
            client,
            "HTTP/1.1 100 Continue\r\n\r\n\
             HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst\
             HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond"
        );
        assert_eq!(connector.connects(), 1);
    }

    /// An HTTP/1.0 client doesn't know 1xx responses: drop them, keep the final.
    #[test]
    fn forward_interim_response_is_not_sent_to_http10_clients() {
        let upstream = SharedConn::new(vec![b"HTTP/1.1 100 Continue\r\n\r\n", OK_2]);
        let (client, _) = run_forward_test(
            vec![b"GET http://93.184.216.34/a HTTP/1.0\r\nHost: 93.184.216.34\r\n\r\n"],
            &[upstream],
        );
        assert_eq!(client.as_bytes(), OK_2);
    }

    /// Regression: a response with no Content-Length / chunked encoding reached
    /// the client as headers only. The body runs to upstream close; afterwards
    /// the client connection is closed and the upstream is not reused.
    #[test]
    fn forward_close_delimited_response_delivers_the_body() {
        let upstream = SharedConn::new(vec![
            b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html>",
            b"body</html>",
        ]);
        let spare = SharedConn::new(vec![OK_2]);
        let (client, connector) = run_forward_test(vec![GET, GET], &[upstream, spare.clone()]);
        assert_eq!(
            client,
            "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html>body</html>"
        );
        // The second pipelined request is not served: the connection closed.
        assert_eq!(connector.connects(), 1);
        assert_eq!(spare.written(), "");
    }

    /// An upstream that announces `Connection: close` must not be reused.
    #[test]
    fn forward_does_not_reuse_upstream_after_connection_close() {
        let first = SharedConn::new(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
        ]);
        let second = SharedConn::new(vec![OK_2]);
        let (_, connector) = run_forward_test(vec![GET, GET], &[first.clone(), second.clone()]);
        assert_eq!(connector.connects(), 2);
        assert_eq!(first.written().matches("GET /a").count(), 1);
        assert_eq!(second.written().matches("GET /a").count(), 1);
    }

    /// A stale keep-alive (closed with no response byte) is the one case where
    /// an idempotent request is replayed on a fresh connection.
    #[test]
    fn forward_retries_idempotent_request_on_stale_connection() {
        let stale = SharedConn::new(vec![OK_2]); // answers once, then EOF
        let fresh = SharedConn::new(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nnew"]);
        let (client, connector) = run_forward_test(vec![GET, GET], &[stale, fresh.clone()]);
        assert!(client.ends_with("\r\n\r\nnew"), "{client}");
        assert!(!client.contains("502"), "{client}");
        assert_eq!(connector.connects(), 2);
        assert_eq!(fresh.written().matches("GET /a").count(), 1);
    }

    /// Regression: once response bytes have arrived the origin has acted on the
    /// request, so a failure is a 502 — never a replay.
    #[test]
    fn forward_does_not_retry_after_a_partial_response() {
        let upstream = SharedConn::new(vec![
            OK_2,
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", // then EOF
        ]);
        let spare = SharedConn::new(vec![OK_2]);
        let (client, connector) = run_forward_test(vec![GET, GET], &[upstream, spare.clone()]);
        assert!(
            client.ends_with(std::str::from_utf8(RESP_502).unwrap()),
            "{client}"
        );
        assert_eq!(connector.connects(), 1, "must not reconnect to replay");
        assert_eq!(spare.written(), "");
    }

    /// Regression: a POST on a reused connection that failed was sent again,
    /// so the origin could execute it twice. A POST now always travels on a
    /// fresh connection and is never replayed.
    #[test]
    fn pool_sweep_closes_expired_connections_for_hosts_never_revisited() {
        let start = std::time::Instant::now();
        let mut pool: ConnPool<u8> = ConnPool::new(4, 2, Duration::from_secs(10), Duration::ZERO);
        pool.checkin("a.test".into(), 80, 1, start);
        pool.checkin("b.test".into(), 80, 2, start);
        // At the total cap: nothing more can be pooled.
        pool.checkin("c.test".into(), 80, 3, start);
        assert_eq!(pool.total, 2);

        // Within the idle timeout nothing is closed.
        assert_eq!(pool.sweep(start + Duration::from_secs(5)), 0);
        assert_eq!(pool.total, 2);

        // Past it, both go, the host entries with them, and the cap is free
        // again even though neither host was asked for.
        assert_eq!(pool.sweep(start + Duration::from_secs(60)), 2);
        assert_eq!(pool.total, 0);
        assert!(pool.idle.is_empty());
        pool.checkin("c.test".into(), 80, 3, std::time::Instant::now());
        assert_eq!(pool.total, 1);
    }

    #[test]
    fn pool_sweep_honours_max_lifetime_and_keeps_live_connections() {
        let start = std::time::Instant::now();
        let mut pool: ConnPool<u8> = ConnPool::new(4, 8, Duration::ZERO, Duration::from_secs(30));
        // Created long enough ago to expire at the sweep below; the second is
        // younger and must survive.
        pool.checkin("a.test".into(), 80, 1, start);
        pool.checkin("a.test".into(), 80, 2, start + Duration::from_secs(20));
        assert_eq!(pool.total, 2);

        assert_eq!(pool.sweep(start + Duration::from_secs(40)), 1);
        assert_eq!(pool.total, 1);
        assert_eq!(pool.checkout("a.test", 80).map(|(c, _)| c), Some(2));
    }

    #[test]
    fn pool_sweep_interval_follows_the_shortest_expiry() {
        let secs = Duration::from_secs;
        assert_eq!(pool_sweep_interval(Duration::ZERO, Duration::ZERO), None);
        assert_eq!(pool_sweep_interval(secs(60), secs(300)), Some(secs(30)));
        assert_eq!(
            pool_sweep_interval(secs(20), Duration::ZERO),
            Some(secs(10))
        );
        assert_eq!(pool_sweep_interval(Duration::ZERO, secs(1)), Some(secs(1)));
        assert_eq!(pool_sweep_interval(secs(3600), secs(7200)), Some(secs(30)));
    }

    #[test]
    fn pool_cap_is_split_between_workers() {
        assert_eq!(per_worker_pool_cap(1000, 8), 125);
        assert_eq!(per_worker_pool_cap(1000, 1), 1000);
        assert_eq!(per_worker_pool_cap(4, 8), 1);
        assert_eq!(per_worker_pool_cap(1000, 0), 1000);
    }

    #[test]
    fn forward_never_replays_a_post() {
        const POST: &[u8] = b"POST http://93.184.216.34/charge HTTP/1.1\r\n\
            Host: 93.184.216.34\r\nContent-Length: 1\r\n\r\nx";
        let kept = SharedConn::new(vec![OK_2]); // serves the GET, stays open
        let dies = SharedConn::new(vec![]); // accepts the POST, then EOF
        let spare = SharedConn::new(vec![OK_2]);
        let (client, connector) = run_forward_test(
            vec![GET, POST],
            &[kept.clone(), dies.clone(), spare.clone()],
        );

        // The POST did not ride the kept-alive connection...
        assert!(!kept.written().contains("POST"), "{}", kept.written());
        // ...it went out exactly once, on its own connection...
        assert_eq!(dies.written().matches("POST /charge").count(), 1);
        // ...and its failure was reported, not retried.
        assert!(
            client.ends_with(std::str::from_utf8(RESP_502).unwrap()),
            "{client}"
        );
        assert_eq!(connector.connects(), 2);
        assert_eq!(spare.written(), "");
    }

    #[test]
    fn idempotent_methods_are_matched_exactly() {
        for m in ["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"] {
            assert!(is_idempotent_method(m.as_bytes()), "{m}");
        }
        for m in ["POST", "PATCH", "CONNECT", "get", ""] {
            assert!(!is_idempotent_method(m.as_bytes()), "{m}");
        }
    }

    /// PanicConnect retained for symmetry / future tests that may need a
    /// connector that must never be touched. Silence the unused-struct warning.
    #[allow(dead_code)]
    fn _ensure_panic_connect_lives(_pc: PanicConnect) {}
}
