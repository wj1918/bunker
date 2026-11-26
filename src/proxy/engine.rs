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
    request_body_framing, scan_message_with_metadata, scan_response_head, BodyFraming,
    ChunkProgress, ChunkedTracker, MessageError, MessageMetadata, MessageScan, ResponseBody,
    ResponseHead,
};
use crate::security::{
    is_blocked_target, is_source_ip_allowed, resolved_addrs_blocked, RateLimiter,
};
use bytes::{Buf, Bytes, BytesMut};
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, warn};

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
    /// Longest wait for the upstream to send more of a response (head or
    /// body); zero = no limit. An idle limit, not a total: a slow but steady
    /// download is never cut off.
    pub upstream_read_timeout: Duration,
    /// Longest wait for the client to send more of a request body or accept
    /// more of a response; zero = no limit. Idle limit, like the one above.
    pub client_idle_timeout: Duration,
    /// TCP keep-alive for client and upstream sockets. This is what notices a
    /// peer that vanished without closing on an idle CONNECT tunnel.
    pub tcp_keepalive: crate::config::TcpKeepaliveConfig,
    /// Add `X-Forwarded-For: <client address>` to forwarded requests.
    pub forwarded_for: bool,
    /// Max request body in bytes; 0 = unlimited.
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
    /// Run `fut`, giving up after `dur`; `None` means it timed out. This is
    /// the runtime's timer, exposed so the runtime-agnostic core can bound any
    /// operation (writes in particular). The default never times out.
    async fn timeout<F: std::future::Future>(_dur: Duration, fut: F) -> Option<F::Output> {
        Some(fut.await)
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

/// Largest message head (request or response) accepted. A peer that never
/// finishes its head would otherwise be buffered without bound.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Why reading one message stopped without yielding it.
#[derive(Debug)]
pub enum RelayErr {
    /// EOF, I/O error, malformed/smuggling head, or header-read timeout — in all
    /// cases the caller just drops the connection (no response, or already sent).
    Closed,
    /// A request whose declared Content-Length exceeds the limit (-> 413).
    TooLarge,
    /// A head or body framing the proxy refuses to interpret (-> 400). These
    /// are the shapes request smuggling is made of, so they are logged.
    Malformed,
}

/// Read exactly one complete HTTP/1 message from `src` into `acc`, returning its
/// bytes and leaving any trailing (pipelined) bytes in `acc`. Runtime-agnostic.
///
/// `head_timeout` (when Some) bounds the *total* time to receive a complete head
/// (CRLFCRLF) — slowloris defense; it does NOT bound body transfer (the metadata
/// variant takes a separate idle limit for that). `max_body`
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
    relay_once_with_metadata(src, acc, is_request, head_timeout, None, max_body)
        .await
        .map(|(b, _)| b)
}

/// What is still missing of a request whose head has arrived, tracked so that
/// each read costs work in proportion to the bytes it brought.
///
/// Without it the whole message was scanned from the first byte after every
/// read — the head re-parsed, every chunk walked again — so an upload sent in
/// small pieces cost CPU in proportion to the square of its size.
enum BodyWait {
    /// Complete once the buffer holds this many bytes.
    Length { total: usize },
    /// Chunked: `scanned` bytes are already accounted for by `tracker`.
    Chunked {
        tracker: ChunkedTracker,
        scanned: usize,
    },
}

impl BodyWait {
    fn for_request_head(head: &[u8]) -> Option<Self> {
        match request_body_framing(head)? {
            BodyFraming::None => None,
            BodyFraming::ContentLength(n) => Some(BodyWait::Length {
                total: head.len().checked_add(usize::try_from(n).ok()?)?,
            }),
            BodyFraming::Chunked => Some(BodyWait::Chunked {
                tracker: ChunkedTracker::new(),
                scanned: head.len(),
            }),
        }
    }

    /// False while the body is certainly still incomplete. True means "scan
    /// the message now": it is complete, or malformed (the scan says which).
    fn worth_scanning(&mut self, acc: &[u8]) -> bool {
        match self {
            BodyWait::Length { total } => acc.len() >= *total,
            BodyWait::Chunked { tracker, scanned } => match tracker.advance(&acc[*scanned..]) {
                ChunkProgress::More(n) => {
                    *scanned += n;
                    false
                }
                ChunkProgress::Done(_) | ChunkProgress::Malformed => true,
            },
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Full-message scans performed by `relay_once_with_metadata` on this thread.
    static FULL_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Like `relay_once`, but also returns the routing metadata extracted in the
/// same httparse pass `scan_message_with_metadata` performs internally. Used by
/// the engine's request loop so `rewrite_forward` can skip a second parse.
pub async fn relay_once_with_metadata<C: ProxyIo>(
    src: &mut C,
    acc: &mut BytesMut,
    is_request: bool,
    head_timeout: Option<Duration>,
    body_idle_timeout: Option<Duration>,
    max_body: u64,
) -> Result<(Bytes, Option<MessageMetadata>), RelayErr> {
    let start = std::time::Instant::now();
    let mut head_done = false;
    let mut head_len = 0usize;
    let mut body_wait: Option<BodyWait> = None;
    loop {
        // Once the head is in and we know how the body is framed, skip the
        // scan until enough has arrived for the message to be complete.
        let (scan, meta) = if body_wait.as_mut().is_some_and(|w| !w.worth_scanning(acc)) {
            (MessageScan::Incomplete, None)
        } else {
            #[cfg(test)]
            FULL_SCANS.with(|n| n.set(n.get() + 1));
            scan_message_with_metadata(acc, is_request, max_body)
        };
        match scan {
            MessageScan::Complete { total, .. } => {
                // Zero-copy: split_to + freeze hands the caller a Bytes view
                // that shares the underlying allocation. No memcpy, no drain.
                // The remaining tail (pipelined bytes, if any) stays in `acc`.
                return Ok((acc.split_to(total).freeze(), meta));
            }
            MessageScan::Error(MessageError::BodyTooLarge) => return Err(RelayErr::TooLarge),
            MessageScan::Error(_) => return Err(RelayErr::Malformed),
            MessageScan::Incomplete => {
                // Latch once the head is fully received; after that, body reads
                // are untimed (a large upload mustn't trip the header timeout).
                if !head_done {
                    if let Some(i) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                        head_done = true;
                        head_len = i + 4;
                        if is_request {
                            body_wait = BodyWait::for_request_head(&acc[..head_len]);
                        }
                    } else if acc.len() > MAX_HEAD_BYTES {
                        return Err(RelayErr::Closed); // head never ends
                    }
                }
                // A chunked body declares no length up front, so the limit has
                // to be applied while it is still arriving. Without this an
                // endless chunked upload would be buffered until memory ran out.
                if head_done && max_body > 0 && (acc.len() - head_len) as u64 > max_body {
                    return Err(RelayErr::TooLarge);
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
                    // Body: no limit on the total (a large upload takes as
                    // long as it takes), only on each wait for more of it.
                    _ if head_done && body_idle_timeout.is_some() => {
                        let t = body_idle_timeout.unwrap_or_default();
                        match src.read_append_timeout(acc, t).await {
                            Ok(n) => n,
                            Err(_) => return Err(RelayErr::Closed), // stalled upload
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
    /// DNS failure or connect failure (which one, for the log).
    Failed(&'static str),
}

/// At most this many resolved addresses are tried for one connection, so a
/// host with many dead addresses cannot multiply the connect timeout without
/// bound.
const MAX_CONNECT_ATTEMPTS: usize = 3;

/// Resolve a target to its connectable addresses, applying DNS-rebinding
/// validation to ALL resolved IPs (one private address blocks the lot). Literal-IP targets skip the resolver (and
/// were already vetted by `is_blocked_target` upstream); hostnames go through
/// the shared `DnsClient` (Mode 1 upstream forwarder or Mode 2/3 OS-resolver
/// wrapper) and every returned IP is checked.
async fn resolve_target(
    host: &str,
    port: u16,
    security: &SecurityConfig,
    dns_client: &Arc<crate::dns::DnsClient>,
) -> Result<Vec<SocketAddr>, AcquireErr> {
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
        return Ok(vec![addr]);
    }
    // `resolve_anywhere`, not `resolve`: io_uring workers are not tokio threads.
    let ips = dns_client
        .resolve_anywhere(host)
        .await
        .map_err(|_| AcquireErr::Failed("DNS lookup failed"))?;
    if ips.is_empty() {
        return Err(AcquireErr::Failed("DNS lookup returned no addresses"));
    }
    let addrs: Vec<SocketAddr> = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    if resolved_addrs_blocked(&addrs, security).is_some() {
        return Err(AcquireErr::Blocked);
    }
    Ok(addrs)
}

/// Resolve + validate + connect a fresh upstream for a target. The returned
/// `Instant` is the connection's creation time (for pool lifetime tracking).
async fn connect_fresh<K: Connect>(
    connector: &K,
    target: &Target,
    security: &SecurityConfig,
    dns_client: &Arc<crate::dns::DnsClient>,
) -> Result<(K::Conn, std::time::Instant), AcquireErr> {
    // The addresses were validated as a set, and it is these addresses that
    // are connected to — no second resolution a rebinding answer could exploit.
    // If the first is unreachable the next is tried: a host that publishes
    // several addresses stays reachable when one of them is down.
    let addrs = resolve_target(&target.host, target.port, security, dns_client).await?;
    connect_first_reachable(connector, addrs).await
}

/// Connect to the first of `addrs` that accepts, trying at most
/// `MAX_CONNECT_ATTEMPTS` of them.
async fn connect_first_reachable<K: Connect>(
    connector: &K,
    addrs: Vec<SocketAddr>,
) -> Result<(K::Conn, std::time::Instant), AcquireErr> {
    for addr in addrs.into_iter().take(MAX_CONNECT_ATTEMPTS) {
        if let Ok(conn) = connector.connect(addr).await {
            return Ok((conn, std::time::Instant::now()));
        }
    }
    Err(AcquireErr::Failed("connect failed"))
}

// Minimal fixed error responses (the proxy never builds arbitrary responses).
const RESP_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESP_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESP_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESP_504: &[u8] =
    b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const CONNECT_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
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
        info!(client = %peer, "Connection dropped: source address not in allowed_source_ips");
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
                warn!(client = %peer, limit = cfg.max_connections, "Connection refused: max_connections reached");
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
        warn!(client = %peer, "Connection refused: rate limit exceeded");
        return AdmitDecision::Reject(crate::helpers::ACCEPT_RATELIMIT_RESP);
    }
    AdmitDecision::Allowed
}

/// Pause before the next accept after `consecutive` failed ones. Accept can
/// fail persistently — most often when the process is out of file
/// descriptors — and retrying at once turned that into a loop burning a whole
/// CPU core. Grows to half a second, which is short enough not to matter when
/// the condition clears.
fn accept_error_backoff(consecutive: u32) -> Duration {
    Duration::from_millis((u64::from(consecutive) * 10).min(500))
}

/// Report an accept failure: the first of a run, then every hundredth.
fn log_accept_error(error: &std::io::Error, consecutive: u32) {
    if consecutive == 1 || consecutive.is_multiple_of(100) {
        warn!(error = %error, consecutive, "Accepting a connection failed");
    }
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
    let read_timeout = (!cfg.upstream_read_timeout.is_zero()).then_some(cfg.upstream_read_timeout);
    let client_timeout = (!cfg.client_idle_timeout.is_zero()).then_some(cfg.client_idle_timeout);

    loop {
        // Parse-once: pull metadata out of the framing pass and hand it to
        // rewrite_forward_with_metadata, which then skips its own httparse call.
        let (req, meta) = match relay_once_with_metadata(
            &mut client,
            &mut req_acc,
            true,
            head_timeout,
            client_timeout,
            max_body,
        )
        .await
        {
            Ok(x) => x,
            Err(RelayErr::TooLarge) => {
                warn!(client = %client_ip, limit = max_body, "Request body over the size limit");
                let _ = client.write_all(RESP_413).await;
                break;
            }
            Err(RelayErr::Malformed) => {
                warn!(client = %client_ip, "Malformed request rejected (bad head or body framing)");
                let _ = client.write_all(RESP_400).await;
                break;
            }
            Err(RelayErr::Closed) => break, // EOF / slowloris timeout / stalled upload
        };
        // Per-connection request cap: the request that reaches it is still
        // served, and the connection is closed after its response. (Answering
        // the next request with an error instead would fail a request from a
        // client that did nothing wrong but reuse its connection.)
        served += 1;
        let last_request = cfg.max_requests_per_conn > 0 && served >= cfg.max_requests_per_conn;
        let forwarded_for = cfg.forwarded_for.then_some(client_ip);
        let (target, head, body) =
            match rewrite_forward_with_metadata(&req, forwarded_for, meta.as_ref()) {
                Ok(x) => x,
                Err(ForwardError::IsConnect) => {
                    // CONNECT tunnel: validate target, connect, 200, then pump bytes.
                    let Some(target) = parse_connect_target(&req) else {
                        warn!(client = %client_ip, "CONNECT without a valid host:port");
                        let _ = client.write_all(RESP_400).await;
                        break;
                    };
                    if let Some(reason) =
                        is_blocked_target(&target.host, Some(target.port), security)
                    {
                        log_blocked(client_ip, &target, reason);
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
                                log_blocked(client_ip, &target, REBINDING);
                                let _ = client.write_all(RESP_403).await;
                                break;
                            }
                            Err(AcquireErr::Failed(why)) => {
                                log_upstream_failure(client_ip, &target, why);
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
                Err(e) => {
                    let reason = match e {
                        ForwardError::HttpsNotTunnelled => {
                            "https:// URL in a plain request (HTTPS needs CONNECT)"
                        }
                        ForwardError::NoTarget => "no target host",
                        _ => "malformed request",
                    };
                    warn!(client = %client_ip, reason, "Request rejected");
                    let _ = client.write_all(RESP_400).await;
                    break;
                }
            };
        // SSRF: blocklist / port allowlist / literal private-IP.
        if let Some(reason) = is_blocked_target(&target.host, Some(target.port), security) {
            log_blocked(client_ip, &target, reason);
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
                log_blocked(client_ip, &target, REBINDING);
                let _ = client.write_all(RESP_403).await;
                break;
            }
            Err(AcquireErr::Failed(why)) => {
                log_upstream_failure(client_ip, &target, why);
                let _ = client.write_all(RESP_502).await;
                break;
            }
        };

        // Send the request and wait for the response head. Retry once on a
        // fresh connection only when it is safe: the connection was a reused
        // keep-alive, the request is idempotent, and the upstream closed
        // without sending a single response byte (the signature of a stale
        // idle connection). Anything else — a reset mid-head, an unparseable
        // response, a timeout — is an error response, never a replay.
        let started = match begin_roundtrip(
            &mut conn,
            &head,
            &body,
            head_request,
            forward_interim,
            read_timeout,
        )
        .await
        {
            Ok(r) => Ok(r),
            Err(failed) if reused && idempotent && failed.retryable => {
                match connect_fresh(&connector, &target, security, dns_client).await {
                    Ok((fresh, fresh_ca)) => {
                        conn = fresh;
                        created_at = fresh_ca;
                        begin_roundtrip(
                            &mut conn,
                            &head,
                            &body,
                            head_request,
                            forward_interim,
                            read_timeout,
                        )
                        .await
                    }
                    Err(_) => Err(failed),
                }
            }
            Err(failed) => Err(failed),
        };
        let started = match started {
            Ok(r) => r,
            Err(failed) => {
                let (status, why) = if failed.timed_out {
                    (RESP_504, "no response within the read timeout")
                } else {
                    (RESP_502, "no valid response")
                };
                log_upstream_failure(client_ip, &target, why);
                let _ = client.write_all(status).await;
                break;
            }
        };

        // Relay the response as it arrives. From here on the client has (or is
        // about to have) part of the response, so a failure can only be
        // signalled by closing its connection.
        let relayed = relay_response(
            &mut client,
            &mut conn,
            started,
            read_timeout,
            client_timeout,
            last_request,
        )
        .await;

        // Keep the upstream for the next request (fast path) only if it can
        // carry one; otherwise it is dropped (closed) here.
        if relayed.upstream_reusable {
            current = Some((target, conn, created_at));
        }
        if !relayed.client_open || last_request {
            break;
        }
    }

    // Return the live upstream (if any) to the pool for cross-connection reuse.
    if let Some((t, c, ca)) = current {
        pool.borrow_mut().checkin(t.host, t.port, c, ca);
    }
}

/// Reason logged when a hostname resolved to a private/internal address.
const REBINDING: &str = "resolved to a private/internal address";

/// A request the security policy refused. Always logged, whatever
/// `log_requests` says: refusals are the audit trail of an egress proxy.
fn log_blocked(client: IpAddr, target: &Target, reason: &str) {
    warn!(
        client = %client,
        target = %format_args!("{}:{}", target.host, target.port),
        reason,
        "Request blocked"
    );
}

/// A request that was allowed but could not be served by the upstream.
fn log_upstream_failure(client: IpAddr, target: &Target, reason: &str) {
    warn!(
        client = %client,
        target = %format_args!("{}:{}", target.host, target.port),
        reason,
        "Upstream request failed"
    );
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

/// The final response head has arrived; the body (if any) is still to be
/// relayed by `relay_response`.
struct ResponseStarted {
    /// Forwarded 1xx interim responses that preceded the final one, if any.
    interim: Option<BytesMut>,
    /// Everything read so far, starting with the final response's head.
    buf: BytesMut,
    /// Length of that head.
    head: usize,
    body: ResponseBody,
    keep_alive: bool,
}

/// A round-trip that produced no response head.
struct RoundtripFailed {
    /// The upstream closed (or the write failed) before a single response
    /// byte arrived — the only case in which the request may be replayed on
    /// another connection.
    retryable: bool,
    /// The upstream stayed silent past the read timeout (-> 504, not 502).
    timed_out: bool,
}

impl RoundtripFailed {
    const BAD_RESPONSE: Self = RoundtripFailed {
        retryable: false,
        timed_out: false,
    };
}

/// Upper bound on 1xx interim responses per request, so an upstream can't keep
/// a worker reading them forever.
const MAX_INTERIM_RESPONSES: usize = 16;

/// How much room to offer the upstream per read while relaying a body. This,
/// not the size of the response, is what bounds the proxy's memory use.
const RELAY_READ_BYTES: usize = 64 * 1024;

/// Write to the client, giving up if it accepts nothing for `limit`. Each call
/// carries at most about one read's worth of data, so this is an idle limit:
/// a client that keeps reading, however slowly, is not cut off for the size of
/// the response.
async fn write_client<C: ProxyIo>(
    client: &mut C,
    data: &[u8],
    limit: Option<Duration>,
) -> std::io::Result<()> {
    match limit {
        Some(t) => C::timeout(t, client.write_all(data))
            .await
            .unwrap_or_else(|| Err(std::io::ErrorKind::TimedOut.into())),
        None => client.write_all(data).await,
    }
}

/// One read from the upstream, bounded by the idle timeout when one is set.
async fn read_upstream<C: ProxyIo>(
    conn: &mut C,
    acc: &mut BytesMut,
    timeout: Option<Duration>,
) -> std::io::Result<usize> {
    match timeout {
        Some(t) => conn.read_append_timeout(acc, t).await,
        None => conn.read_append(acc).await,
    }
}

/// Send one request on `conn` and read until the final response head is in.
/// Takes head and body separately so the upstream write goes out as one
/// `writev(2)` call (no head+body concatenation copy) — `write_all_vectored`
/// handles the fallback if vectored I/O isn't available on the backend.
///
/// The head is framed with the response rules of RFC 7230 §3.3.3 (see
/// `scan_response_head`): `head_request` suppresses the body, and 1xx interim
/// responses are skipped over (and kept for relaying when `forward_interim`).
/// Nothing is written to the client here, so a failure can still be answered
/// with an error status or, when `retryable`, a second attempt.
async fn begin_roundtrip<C: ProxyIo>(
    conn: &mut C,
    head: &Bytes,
    body: &Bytes,
    head_request: bool,
    forward_interim: bool,
    read_timeout: Option<Duration>,
) -> Result<ResponseStarted, RoundtripFailed> {
    // An upstream that accepts the connection but stops taking the request is
    // as stuck as one that never answers, so the same limit covers the send.
    let sent = match read_timeout {
        Some(t) => C::timeout(t, conn.write_all_vectored(head, body)).await,
        None => Some(conn.write_all_vectored(head, body).await),
    };
    match sent {
        Some(Ok(())) => {}
        Some(Err(_)) => {
            return Err(RoundtripFailed {
                retryable: true,
                timed_out: false,
            })
        }
        None => {
            return Err(RoundtripFailed {
                retryable: false,
                timed_out: true,
            })
        }
    }
    let mut acc: BytesMut = BytesMut::with_capacity(4096);
    let mut interim: Option<BytesMut> = None; // forwarded 1xx bytes, if any
    let mut interim_count = 0usize;
    loop {
        match scan_response_head(&acc, head_request) {
            ResponseHead::Complete {
                head,
                interim: true,
                ..
            } => {
                interim_count += 1;
                if interim_count > MAX_INTERIM_RESPONSES {
                    return Err(RoundtripFailed::BAD_RESPONSE);
                }
                let msg = acc.split_to(head);
                if forward_interim {
                    interim
                        .get_or_insert_with(BytesMut::new)
                        .extend_from_slice(&msg);
                }
                // The final response follows; rescan what's already buffered.
            }
            ResponseHead::Complete {
                head,
                keep_alive,
                body,
                ..
            } => {
                return Ok(ResponseStarted {
                    interim,
                    buf: acc,
                    head,
                    body,
                    keep_alive,
                })
            }
            ResponseHead::Error(_) => return Err(RoundtripFailed::BAD_RESPONSE),
            ResponseHead::Incomplete => {
                if acc.len() > MAX_HEAD_BYTES {
                    return Err(RoundtripFailed::BAD_RESPONSE); // head never ends
                }
                let nothing_yet = interim_count == 0 && acc.is_empty();
                match read_upstream(conn, &mut acc, read_timeout).await {
                    Ok(n) if n > 0 => {}
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        return Err(RoundtripFailed {
                            retryable: false,
                            timed_out: true,
                        })
                    }
                    // EOF or I/O error before a full head.
                    _ => {
                        return Err(RoundtripFailed {
                            retryable: nothing_yet,
                            timed_out: false,
                        })
                    }
                }
            }
        }
    }
}

/// A copy of a response head that tells the client the connection will close:
/// any `Connection` header is replaced by `Connection: close`. `head` is a
/// complete, already-validated head ending in an empty line.
fn head_with_connection_close(head: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len() + 24);
    let lines = head.strip_suffix(b"\r\n\r\n").unwrap_or(head);
    for line in lines.split_inclusive(|&b| b == b'\n') {
        let name = line.split(|&b| b == b':').next().unwrap_or(&[]);
        if !name.eq_ignore_ascii_case(b"connection") {
            out.extend_from_slice(line);
        }
    }
    if !out.ends_with(b"\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

/// What relaying a response left behind.
struct Relayed {
    /// The upstream connection can carry another request.
    upstream_reusable: bool,
    /// The client connection can carry another request. False when the body
    /// was delimited by upstream close (closing is what marks its end), and
    /// when the response could not be delivered in full.
    client_open: bool,
}

impl Relayed {
    /// The response was cut short, or the client went away: neither
    /// connection is in a known state.
    const ABORTED: Self = Relayed {
        upstream_reusable: false,
        client_open: false,
    };
}

/// Relay a started response to the client, passing the body on as it arrives.
/// Each piece is written to the client before the next is read from the
/// upstream, so memory use stays at about one read however large the body is
/// (a download of any size, or a stream that never ends), and a slow client
/// slows the upstream down instead of filling the proxy. A client that stops
/// reading altogether is dropped after `client_timeout`.
async fn relay_response<C: ProxyIo>(
    client: &mut C,
    conn: &mut C,
    started: ResponseStarted,
    read_timeout: Option<Duration>,
    client_timeout: Option<Duration>,
    announce_close: bool,
) -> Relayed {
    let ResponseStarted {
        interim,
        mut buf,
        mut head,
        body,
        keep_alive,
    } = started;
    if let Some(pre) = interim {
        if write_client(client, &pre, client_timeout).await.is_err() {
            return Relayed::ABORTED;
        }
    }
    // The proxy is about to close the client connection (request cap): say so
    // in this response, so the client opens a new connection for its next
    // request instead of sending it into a closed one.
    if announce_close {
        let rewritten = head_with_connection_close(&buf[..head]);
        if write_client(client, &rewritten, client_timeout)
            .await
            .is_err()
        {
            return Relayed::ABORTED;
        }
        buf.advance(head);
        head = 0;
    }
    // Make room for the next read. `buf` is emptied after every write, so this
    // reuses one allocation rather than growing.
    fn make_room(buf: &mut BytesMut) {
        if buf.capacity() - buf.len() < RELAY_READ_BYTES / 4 {
            buf.reserve(RELAY_READ_BYTES);
        }
    }

    match body {
        ResponseBody::None => {
            if write_client(client, &buf[..head], client_timeout)
                .await
                .is_err()
            {
                return Relayed::ABORTED;
            }
            // Bytes after the response mean the upstream is out of step with
            // us; such a connection must not carry another request.
            Relayed {
                upstream_reusable: keep_alive && buf.len() == head,
                client_open: true,
            }
        }
        ResponseBody::Length(len) => {
            let mut remaining = len;
            let mut offset = head; // the head goes out with the first piece
            let mut surplus = false;
            loop {
                let available = (buf.len() - offset) as u64;
                let take = available.min(remaining) as usize;
                surplus |= available > remaining;
                if write_client(client, &buf[..offset + take], client_timeout)
                    .await
                    .is_err()
                {
                    return Relayed::ABORTED;
                }
                remaining -= take as u64;
                if remaining == 0 {
                    return Relayed {
                        upstream_reusable: keep_alive && !surplus,
                        client_open: true,
                    };
                }
                buf.clear();
                offset = 0;
                make_room(&mut buf);
                match read_upstream(conn, &mut buf, read_timeout).await {
                    Ok(n) if n > 0 => {}
                    // Closed, failed or stalled short of the declared length.
                    _ => return Relayed::ABORTED,
                }
            }
        }
        ResponseBody::Chunked => {
            let mut tracker = ChunkedTracker::new();
            let mut offset = head;
            loop {
                match tracker.advance(&buf[offset..]) {
                    ChunkProgress::Done(n) => {
                        if write_client(client, &buf[..offset + n], client_timeout)
                            .await
                            .is_err()
                        {
                            return Relayed::ABORTED;
                        }
                        return Relayed {
                            upstream_reusable: keep_alive && buf.len() == offset + n,
                            client_open: true,
                        };
                    }
                    ChunkProgress::More(n) => {
                        let ready = offset + n;
                        if ready > 0 {
                            if write_client(client, &buf[..ready], client_timeout)
                                .await
                                .is_err()
                            {
                                return Relayed::ABORTED;
                            }
                            // Keep only the unfinished line, if any.
                            buf.advance(ready);
                        }
                        offset = 0;
                    }
                    ChunkProgress::Malformed => return Relayed::ABORTED,
                }
                make_room(&mut buf);
                match read_upstream(conn, &mut buf, read_timeout).await {
                    Ok(n) if n > 0 => {}
                    _ => return Relayed::ABORTED,
                }
            }
        }
        ResponseBody::UntilClose => {
            loop {
                if !buf.is_empty() && write_client(client, &buf, client_timeout).await.is_err() {
                    return Relayed::ABORTED;
                }
                buf.clear();
                make_room(&mut buf);
                match read_upstream(conn, &mut buf, read_timeout).await {
                    Ok(0) => break, // upstream closed: end of body
                    Ok(_) => {}
                    Err(_) => return Relayed::ABORTED,
                }
            }
            // The client has no length to find the end by; closing its
            // connection is what terminates the body.
            Relayed {
                upstream_reusable: false,
                client_open: false,
            }
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
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))?
        }
        async fn timeout<F: std::future::Future>(
            dur: std::time::Duration,
            fut: F,
        ) -> Option<F::Output> {
            tokio::time::timeout(dur, fut).await.ok()
        }
    }

    /// Opens upstream connections via tokio. Hostname resolution is delegated
    /// to the shared `DnsClient` in `EngineConfig` — this connector only deals
    /// with already-resolved addresses.
    pub struct TokioConnector {
        pub connect_timeout: std::time::Duration,
        pub tcp_keepalive: crate::config::TcpKeepaliveConfig,
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
            let _ = crate::helpers::apply_tcp_keepalive(&stream, &self.tcp_keepalive);
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
                        let _ = crate::helpers::apply_tcp_keepalive(&client, &cfg.tcp_keepalive);
                        let cfg = Arc::clone(&cfg);
                        let pool = pool.clone();
                        let connector = TokioConnector {
                            connect_timeout: cfg.connect_timeout,
                            tcp_keepalive: cfg.tcp_keepalive.clone(),
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
        let mut failures = 0u32;
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => {
                    failures = 0;
                    s
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    super::log_accept_error(&e, failures);
                    std::thread::sleep(super::accept_error_backoff(failures));
                    continue;
                }
            };
            if senders[i % threads].send(stream).is_err() {
                break;
            }
            i += 1;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::TcpKeepaliveConfig;

        /// Regression: the engine ignored `proxy.tcp_keepalive`, so a peer
        /// that vanished without closing was never noticed and its CONNECT
        /// tunnel stayed open for good.
        #[tokio::test]
        async fn connector_applies_tcp_keepalive() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let keepalive = |enabled| TcpKeepaliveConfig {
                enabled,
                time_seconds: 77,
                ..TcpKeepaliveConfig::default()
            };

            let on = TokioConnector {
                connect_timeout: std::time::Duration::ZERO,
                tcp_keepalive: keepalive(true),
            };
            let conn = on.connect(addr).await.unwrap();
            let sock = socket2::SockRef::from(&conn.0);
            assert!(sock.keepalive().unwrap());
            // socket2 has no getter for the idle time on Windows, so there
            // only the on/off state can be read back.
            #[cfg(not(windows))]
            assert_eq!(
                sock.tcp_keepalive_time().unwrap(),
                std::time::Duration::from_secs(77)
            );

            let off = TokioConnector {
                connect_timeout: std::time::Duration::ZERO,
                tcp_keepalive: keepalive(false),
            };
            let conn = off.connect(addr).await.unwrap();
            assert!(!socket2::SockRef::from(&conn.0).keepalive().unwrap());
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
                    "read timeout",
                )),
            }
        }
        async fn timeout<F: std::future::Future>(
            dur: std::time::Duration,
            fut: F,
        ) -> Option<F::Output> {
            monoio::time::timeout(dur, fut).await.ok()
        }
    }

    /// Apply the configured TCP keep-alive to a monoio stream.
    fn apply_keepalive(stream: &TcpStream, config: &crate::config::TcpKeepaliveConfig) {
        use std::os::fd::{AsRawFd, BorrowedFd};
        // SAFETY: the descriptor belongs to `stream`, which outlives this
        // borrow; it is only used for the setsockopt calls below.
        let fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
        let _ = crate::helpers::apply_tcp_keepalive_to(socket2::SockRef::from(&fd), config);
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
        pub tcp_keepalive: crate::config::TcpKeepaliveConfig,
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
            apply_keepalive(&stream, &self.tcp_keepalive);
            Ok(MonoConn::new(stream))
        }
        async fn tunnel(client: MonoConn, upstream: MonoConn) {
            // monoio has no copy_bidirectional: split each stream and run both
            // unidirectional copies concurrently on this thread via join!.
            use monoio::io::Splitable;
            let (mut cr, mut cw) = client.stream.into_split();
            let (mut ur, mut uw) = upstream.stream.into_split();
            // When one direction reaches end-of-stream, pass that on by
            // shutting down the write side it was feeding. Without it a peer
            // that finishes sending and waits for the other to close (an
            // ordinary half-close) left the tunnel open for good, since the
            // other side never learned the stream had ended. tokio's
            // copy_bidirectional does the same.
            use monoio::io::AsyncWriteRent;
            let client_to_upstream = async {
                let _ = monoio::io::copy(&mut cr, &mut uw).await;
                let _ = uw.shutdown().await;
            };
            let upstream_to_client = async {
                let _ = monoio::io::copy(&mut ur, &mut cw).await;
                let _ = cw.shutdown().await;
            };
            monoio::join!(client_to_upstream, upstream_to_client);
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
            let mut failures = 0u32;
            loop {
                match listener.accept().await {
                    Ok((mut client, peer)) => {
                        failures = 0;
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
                        apply_keepalive(&client, &cfg.tcp_keepalive);
                        let cfg = Arc::clone(&cfg);
                        let pool = pool.clone();
                        let connector = MonoConnector {
                            connect_timeout: cfg.connect_timeout,
                            tcp_keepalive: cfg.tcp_keepalive.clone(),
                        };
                        monoio::spawn(async move {
                            let _g = guard;
                            proxy_forward(MonoConn::new(client), connector, cfg, peer_ip, pool)
                                .await;
                        });
                    }
                    Err(e) => {
                        failures = failures.saturating_add(1);
                        super::log_accept_error(&e, failures);
                        monoio::time::sleep(super::accept_error_backoff(failures)).await;
                        continue;
                    }
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
    struct SharedConn {
        conn: Rc<std::cell::RefCell<MockConn>>,
        opts: Rc<std::cell::RefCell<ConnOpts>>,
    }
    /// Optional misbehaviour for a `SharedConn`.
    #[derive(Default)]
    struct ConnOpts {
        /// Once the scripted reads run out, time out instead of reporting EOF
        /// (an upstream that has gone silent).
        stall_when_drained: bool,
        /// Fail writes once this many bytes have been accepted (a client that
        /// has gone away).
        fail_writes_after: Option<usize>,
        /// Once this many bytes have been accepted, writes never complete (a
        /// client that is connected but has stopped reading).
        stall_writes_after: Option<usize>,
        /// The limit passed with each read that asked for one.
        timed_reads: Vec<Duration>,
        /// Another connection to observe: at every read on this one, how many
        /// bytes the watched one had been sent so far is appended to `seen`.
        watch: Option<Rc<std::cell::RefCell<MockConn>>>,
        seen: Vec<usize>,
    }
    impl SharedConn {
        fn new(chunks: Vec<&[u8]>) -> Self {
            SharedConn {
                conn: Rc::new(std::cell::RefCell::new(MockConn::new(chunks))),
                opts: Rc::default(),
            }
        }
        fn written(&self) -> String {
            String::from_utf8_lossy(&self.conn.borrow().written).into_owned()
        }
        fn unread(&self) -> usize {
            self.conn.borrow().reads.len()
        }
        fn stalling(self) -> Self {
            self.opts.borrow_mut().stall_when_drained = true;
            self
        }
        fn failing_writes_after(self, bytes: usize) -> Self {
            self.opts.borrow_mut().fail_writes_after = Some(bytes);
            self
        }
        fn stalling_writes_after(self, bytes: usize) -> Self {
            self.opts.borrow_mut().stall_writes_after = Some(bytes);
            self
        }
        fn timed_reads(&self) -> Vec<Duration> {
            self.opts.borrow().timed_reads.clone()
        }
        fn watching(self, other: &SharedConn) -> Self {
            self.opts.borrow_mut().watch = Some(Rc::clone(&other.conn));
            self
        }
        fn seen(&self) -> Vec<usize> {
            self.opts.borrow().seen.clone()
        }
    }
    impl ProxyIo for SharedConn {
        async fn read_append(&mut self, acc: &mut bytes::BytesMut) -> std::io::Result<usize> {
            let mut opts = self.opts.borrow_mut();
            if let Some(watched) = opts.watch.clone() {
                opts.seen.push(watched.borrow().written.len());
            }
            match self.conn.borrow_mut().reads.pop_front() {
                Some(chunk) => {
                    acc.extend_from_slice(&chunk);
                    Ok(chunk.len())
                }
                None if opts.stall_when_drained => Err(std::io::ErrorKind::TimedOut.into()),
                None => Ok(0), // EOF
            }
        }
        async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
            let stall = self.opts.borrow().stall_writes_after;
            if stall.is_some_and(|limit| self.conn.borrow().written.len() >= limit) {
                return std::future::pending().await;
            }
            let mut conn = self.conn.borrow_mut();
            if let Some(limit) = self.opts.borrow().fail_writes_after {
                if conn.written.len() >= limit {
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
            }
            conn.written.extend_from_slice(data);
            Ok(())
        }
        async fn read_append_timeout(
            &mut self,
            acc: &mut bytes::BytesMut,
            dur: Duration,
        ) -> std::io::Result<usize> {
            self.opts.borrow_mut().timed_reads.push(dur);
            self.read_append(acc).await
        }
        /// These connections are never "slow": an operation either completes
        /// at once or never does. So one poll decides — pending means the
        /// limit would have expired.
        async fn timeout<F: std::future::Future>(_dur: Duration, fut: F) -> Option<F::Output> {
            let mut fut = std::pin::pin!(fut);
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(match fut.as_mut().poll(cx) {
                    std::task::Poll::Ready(out) => Some(out),
                    std::task::Poll::Pending => None,
                })
            })
            .await
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
        Arc::new(forward_test_engine_config())
    }

    /// `forward_test_config` with both idle timeouts switched on.
    fn forward_test_config_with_timeouts() -> Arc<EngineConfig> {
        Arc::new(EngineConfig {
            upstream_read_timeout: Duration::from_secs(7),
            client_idle_timeout: Duration::from_secs(9),
            ..forward_test_engine_config()
        })
    }

    fn forward_test_engine_config() -> EngineConfig {
        EngineConfig {
            security: Arc::new(SecurityConfig::default()),
            dns_client: panic_client(), // targets are literal IPs: never resolved
            rate_limit: RateLimitConfig::default(),
            pool_max_per_host: 4,
            pool_max_total: 16,
            pool_idle_timeout: Duration::ZERO,
            pool_max_lifetime: Duration::ZERO,
            connect_timeout: Duration::ZERO,
            header_read_timeout: Duration::ZERO,
            upstream_read_timeout: Duration::ZERO,
            client_idle_timeout: Duration::ZERO,
            tcp_keepalive: crate::config::TcpKeepaliveConfig::default(),
            forwarded_for: true,
            max_request_body_bytes: 0,
            max_requests_per_conn: 0,
            max_connections: 0,
            log_requests: false,
        }
    }

    /// Run `proxy_forward` for one client connection sending `requests` (one
    /// read each), against the scripted `upstreams`. Returns what the client
    /// received and the connector (for its connect count).
    fn run_forward_test(requests: Vec<&[u8]>, upstreams: &[SharedConn]) -> (String, ScriptConnect) {
        run_forward_with(SharedConn::new(requests), upstreams)
    }

    /// Like `run_forward_test`, for a client connection the test built itself.
    fn run_forward_with(client: SharedConn, upstreams: &[SharedConn]) -> (String, ScriptConnect) {
        run_forward_cfg(client, upstreams, forward_test_config())
    }

    fn run_forward_cfg(
        client: SharedConn,
        upstreams: &[SharedConn],
        cfg: Arc<EngineConfig>,
    ) -> (String, ScriptConnect) {
        let connector = ScriptConnect::new(upstreams);
        let pool = new_pool(4, 16, Duration::ZERO, Duration::ZERO);
        block_on(proxy_forward(
            client.clone(),
            connector.clone(),
            cfg,
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
            std::slice::from_ref(&upstream),
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
            b"HTTP/1.1 200 OK\r\nContent-Len", // then EOF
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

    /// A body cut short after its head went out can't become a 502 any more:
    /// the client gets what arrived and then a closed connection, which tells
    /// it the response is incomplete. The request is not replayed, and nothing
    /// else is served on either connection.
    #[test]
    fn forward_truncated_body_closes_the_client_connection() {
        let truncated: [&[u8]; 2] = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
        ];
        for response in truncated {
            let upstream = SharedConn::new(vec![OK_2, response]); // then EOF
            let spare = SharedConn::new(vec![OK_2, OK_2]);
            let (client, connector) =
                run_forward_test(vec![GET, GET, GET], &[upstream, spare.clone()]);
            let mut expected = OK_2.to_vec();
            expected.extend_from_slice(response);
            assert_eq!(client.as_bytes(), expected);
            assert_eq!(connector.connects(), 1, "must not reconnect to replay");
            assert_eq!(spare.written(), "");
        }
    }

    /// Regression: the whole response was read into memory before any of it
    /// was sent on, so a large download cost its size in RAM and an endless
    /// stream never reached the client at all. Each piece must be on its way
    /// to the client before the next one is read.
    #[test]
    fn forward_streams_the_body_as_it_arrives() {
        let cases: [Vec<&[u8]>; 3] = [
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n",
                b"one",
                b"two",
                b"six",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                b"3\r\none\r\n",
                b"3\r\ntwo\r\n",
                b"0\r\n\r\n",
            ],
            // An event stream: no length at all.
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
                b"data: 1\n\n",
                b"data: 2\n\n",
                b"data: 3\n\n",
            ],
        ];
        for pieces in cases {
            let client = SharedConn::new(vec![GET]);
            let upstream = SharedConn::new(pieces.clone()).watching(&client);
            let (received, _) = run_forward_with(client, std::slice::from_ref(&upstream));
            assert_eq!(received.as_bytes(), pieces.concat());

            // Before the upstream's read number n+1, the client had already
            // been sent everything from reads 1..=n. (The very first read
            // happens with nothing sent yet.)
            let seen = upstream.seen();
            let mut sent = 0usize;
            for (n, piece) in pieces.iter().enumerate() {
                assert_eq!(seen[n], sent, "before read {} of {pieces:?}", n + 1);
                sent += piece.len();
            }
        }
    }

    /// Framing that straddles read boundaries (a chunk-size line and a chunk's
    /// CRLF split across reads) is relayed byte for byte, and the upstream
    /// stays usable for the next request.
    #[test]
    fn forward_streamed_responses_keep_the_upstream_reusable() {
        let responses: [Vec<&[u8]>; 3] = [
            vec![
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1",
                b"0\r\n0123456789abcdef\r",
                b"\n3;x=y\r\nab",
                b"c\r\n0\r\nX-Trailer: t\r",
                b"\n\r\n",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nab",
                b"cd",
                b"ef",
            ],
            // Everything in one read, the common case for small responses.
            vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n"],
        ];
        for pieces in responses {
            let mut script = pieces.clone();
            script.push(OK_2);
            let upstream = SharedConn::new(script);
            let (client, connector) =
                run_forward_test(vec![GET, GET], std::slice::from_ref(&upstream));
            let mut expected = pieces.concat();
            expected.extend_from_slice(OK_2);
            assert_eq!(client.as_bytes(), expected);
            assert_eq!(connector.connects(), 1, "upstream should be reused");
            assert_eq!(upstream.written().matches("GET /a").count(), 2);
        }
    }

    /// Bytes beyond the end of a response mean the upstream is out of step;
    /// they are not sent to the client and the connection is not reused.
    #[test]
    fn forward_drops_surplus_bytes_and_the_connection_that_sent_them() {
        let responses: [&[u8]; 2] = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOKjunk",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\njunk",
        ];
        for response in responses {
            // The first upstream would answer a second request if asked.
            let first = SharedConn::new(vec![response, OK_2]);
            let second = SharedConn::new(vec![OK_2]);
            let (client, connector) = run_forward_test(vec![GET, GET], &[first.clone(), second]);
            assert!(!client.contains("junk"), "{client}");
            assert!(client.ends_with("OK"), "{client}");
            assert_eq!(connector.connects(), 2);
            assert_eq!(first.written().matches("GET /a").count(), 1);
        }
    }

    /// A malformed chunked body is not passed on past the bad framing.
    #[test]
    fn forward_stops_at_malformed_chunked_framing() {
        let upstream = SharedConn::new(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n",
            b"zz\r\nsmuggled",
        ]);
        let spare = SharedConn::new(vec![OK_2]);
        let (client, connector) = run_forward_test(vec![GET, GET], &[upstream, spare]);
        assert!(client.ends_with("2\r\nOK\r\n"), "{client}");
        assert_eq!(connector.connects(), 1);
    }

    /// When the client goes away mid-download the proxy stops pulling from the
    /// upstream instead of reading the rest of an (endless) body.
    #[test]
    fn forward_stops_reading_when_the_client_is_gone() {
        let mut script: Vec<&[u8]> = vec![b"HTTP/1.1 200 OK\r\n\r\n"];
        script.extend(std::iter::repeat_n(&b"0123456789"[..], 1000));
        let upstream = SharedConn::new(script);
        let client = SharedConn::new(vec![GET]).failing_writes_after(100);
        let (received, _) = run_forward_with(client, std::slice::from_ref(&upstream));
        assert!(received.len() < 200, "{}", received.len());
        assert!(upstream.unread() > 900, "{} reads left", upstream.unread());
    }

    /// An upstream that never answers gets a 504 once the read timeout fires,
    /// and the request is not replayed, even on a reused connection.
    #[test]
    fn forward_answers_504_when_the_upstream_is_silent() {
        let upstream = SharedConn::new(vec![OK_2]).stalling();
        let spare = SharedConn::new(vec![OK_2]);
        let (client, connector) = run_forward_test(vec![GET, GET], &[upstream, spare.clone()]);
        assert!(
            client.ends_with(std::str::from_utf8(RESP_504).unwrap()),
            "{client}"
        );
        assert_eq!(
            connector.connects(),
            1,
            "a timeout is not a stale connection"
        );
        assert_eq!(spare.written(), "");
    }

    /// An upstream that stalls mid-body: the client's connection is closed
    /// rather than left waiting forever.
    #[test]
    fn forward_closes_the_client_when_the_upstream_stalls_mid_body() {
        let upstream =
            SharedConn::new(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"]).stalling();
        let spare = SharedConn::new(vec![OK_2]);
        let (client, connector) = run_forward_test(vec![GET, GET], &[upstream, spare]);
        assert!(client.ends_with("\r\n\r\nabc"), "{client}");
        assert_eq!(connector.connects(), 1);
    }

    /// A client that stays connected but stops reading used to block the
    /// write to it forever, holding its connection and an upstream one. With
    /// the idle limit on, the transfer is abandoned instead.
    #[test]
    fn forward_gives_up_on_a_client_that_stops_reading() {
        let mut script: Vec<&[u8]> = vec![b"HTTP/1.1 200 OK\r\n\r\n"];
        script.extend(std::iter::repeat_n(&b"0123456789"[..], 1000));
        let upstream = SharedConn::new(script);
        let client = SharedConn::new(vec![GET, GET]).stalling_writes_after(100);
        let (received, connector) = run_forward_cfg(
            client.clone(),
            std::slice::from_ref(&upstream),
            forward_test_config_with_timeouts(),
        );
        assert!(received.len() < 200, "{}", received.len());
        assert!(upstream.unread() > 900, "{} reads left", upstream.unread());
        // The connection is dropped: the second request is never read.
        assert_eq!(client.unread(), 1);
        assert_eq!(connector.connects(), 1);
    }

    /// An upstream that connects but never takes the request is a timeout
    /// (504), and the request is not replayed elsewhere.
    #[test]
    fn forward_answers_504_when_the_upstream_stops_accepting_the_request() {
        let upstream = SharedConn::new(vec![OK_2]).stalling_writes_after(0);
        let spare = SharedConn::new(vec![OK_2]);
        let (client, connector) = run_forward_cfg(
            SharedConn::new(vec![GET]),
            &[upstream, spare.clone()],
            forward_test_config_with_timeouts(),
        );
        assert_eq!(client.as_bytes(), RESP_504);
        assert_eq!(connector.connects(), 1);
        assert_eq!(spare.written(), "");
    }

    /// With the timeouts on, ordinary traffic is unaffected.
    #[test]
    fn forward_with_idle_timeouts_serves_normally() {
        let upstream = SharedConn::new(vec![OK_2, OK_2]);
        let (client, connector) = run_forward_cfg(
            SharedConn::new(vec![GET, GET]),
            std::slice::from_ref(&upstream),
            forward_test_config_with_timeouts(),
        );
        assert_eq!(client.as_bytes(), [OK_2, OK_2].concat());
        assert_eq!(connector.connects(), 1);
        // Upstream reads carry the upstream limit, not the client one.
        assert!(upstream
            .timed_reads()
            .iter()
            .all(|d| *d == Duration::from_secs(7)));
        assert!(!upstream.timed_reads().is_empty());
    }

    /// Regression: once the head had arrived, a request body could trickle in
    /// (or stop) with no limit at all. Body reads now carry the idle limit;
    /// head reads keep the separate head deadline.
    #[test]
    fn stalled_upload_is_dropped_by_the_body_idle_limit() {
        let head: &[u8] = b"POST http://h/ HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\n";
        let idle = Duration::from_secs(9);
        let head_limit = Duration::from_secs(30);

        let mut conn = SharedConn::new(vec![&head[..20], &head[20..], b"abc"]).stalling();
        let mut acc = BytesMut::new();
        let result = block_on(relay_once_with_metadata(
            &mut conn,
            &mut acc,
            true,
            Some(head_limit),
            Some(idle),
            0,
        ));
        assert!(matches!(result, Err(RelayErr::Closed)), "{result:?}");
        let limits = conn.timed_reads();
        // Two reads for the head (bounded by what is left of its deadline),
        // then the body reads, each with the full idle limit.
        assert_eq!(limits.len(), 4, "{limits:?}");
        assert!(limits[..2].iter().all(|d| *d <= head_limit && *d > idle));
        assert_eq!(limits[2..], [idle, idle]);

        // Without the limit the body reads are untimed, as before.
        let mut conn = SharedConn::new(vec![head, b"abc", b"defghij"]);
        let mut acc = BytesMut::new();
        let result = block_on(relay_once_with_metadata(
            &mut conn, &mut acc, true, None, None, 0,
        ));
        assert!(result.is_ok());
        assert!(conn.timed_reads().is_empty());
    }

    /// Regression: with a cap of N requests per connection, request N+1 was
    /// answered with a 429. The cap now ends the connection after the Nth
    /// response; no request is failed for it.
    #[test]
    fn forward_request_cap_closes_after_the_last_response_without_an_error() {
        let upstream = SharedConn::new(vec![OK_2, OK_2, OK_2]);
        let client = SharedConn::new(vec![GET, GET, GET]);
        let cfg = Arc::new(EngineConfig {
            max_requests_per_conn: 2,
            ..forward_test_engine_config()
        });
        let (received, _) = run_forward_cfg(client.clone(), std::slice::from_ref(&upstream), cfg);
        // The last response says the connection is closing; the first doesn't.
        assert_eq!(
            received,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK\
             HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
        );
        assert!(!received.contains("429"), "{received}");
        // The third request was never read: the connection closed first.
        assert_eq!(client.unread(), 1);
        assert_eq!(upstream.written().matches("GET /a").count(), 2);
    }

    #[test]
    fn connection_close_replaces_any_existing_connection_header() {
        let close = |head: &[u8]| String::from_utf8(head_with_connection_close(head)).unwrap();
        assert_eq!(
            close(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            close(b"HTTP/1.1 200 OK\r\nconnection: keep-alive\r\nX: 1\r\nConnection: x\r\n\r\n"),
            "HTTP/1.1 200 OK\r\nX: 1\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            close(b"HTTP/1.1 204 No Content\r\n\r\n"),
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        );
    }

    /// The closing announcement must not disturb how the body is relayed.
    #[test]
    fn forward_last_request_announces_close_for_every_body_kind() {
        let bodies: [(&[u8], &str); 3] = [
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
            ),
            (
                b"HTTP/1.1 304 Not Modified\r\nConnection: keep-alive\r\n\r\n",
                "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n",
            ),
            (
                b"HTTP/1.0 200 OK\r\n\r\nuntil close",
                "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nuntil close",
            ),
        ];
        for (response, expected) in bodies {
            let cfg = Arc::new(EngineConfig {
                max_requests_per_conn: 1,
                ..forward_test_engine_config()
            });
            let upstream = SharedConn::new(vec![response]);
            let (received, _) = run_forward_cfg(
                SharedConn::new(vec![GET]),
                std::slice::from_ref(&upstream),
                cfg,
            );
            assert_eq!(received, expected);
        }
    }

    /// Regression: only the first resolved address was tried, so a host with
    /// one dead address was unreachable even though another was up.
    #[test]
    fn connect_fresh_falls_back_to_the_next_address() {
        // Fails the first `failures` connects, then hands out the script.
        struct Flaky {
            failures: std::cell::Cell<usize>,
            attempts: std::cell::Cell<usize>,
        }
        impl Connect for Flaky {
            type Conn = SharedConn;
            async fn connect(&self, _: SocketAddr) -> std::io::Result<SharedConn> {
                self.attempts.set(self.attempts.get() + 1);
                if self.failures.get() > 0 {
                    self.failures.set(self.failures.get() - 1);
                    return Err(std::io::ErrorKind::ConnectionRefused.into());
                }
                Ok(SharedConn::new(vec![]))
            }
            async fn tunnel(_: SharedConn, _: SharedConn) {}
        }
        let flaky = |failures| Flaky {
            failures: std::cell::Cell::new(failures),
            attempts: std::cell::Cell::new(0),
        };
        let addrs = |n: u8| -> Vec<SocketAddr> {
            (1..=n)
                .map(|i| SocketAddr::from(([93, 184, 216, i], 80)))
                .collect()
        };

        let c = flaky(1);
        assert!(block_on(connect_first_reachable(&c, addrs(2))).is_ok());
        assert_eq!(c.attempts.get(), 2);

        // Bounded: a long list of dead addresses is not walked to the end.
        let c = flaky(usize::MAX);
        assert!(block_on(connect_first_reachable(&c, addrs(10))).is_err());
        assert_eq!(c.attempts.get(), MAX_CONNECT_ATTEMPTS);
    }

    /// Regression: `GET https://...` on the proxy port went out in clear text.
    #[test]
    fn forward_refuses_https_urls_without_contacting_the_origin() {
        let upstream = SharedConn::new(vec![OK_2]);
        let (client, connector) = run_forward_test(
            vec![b"GET https://93.184.216.34/a HTTP/1.1\r\nCookie: s=secret\r\n\r\n"],
            std::slice::from_ref(&upstream),
        );
        assert_eq!(client.as_bytes(), RESP_400);
        assert_eq!(connector.connects(), 0);
        assert_eq!(upstream.written(), "");
    }

    /// A request with framing the proxy refuses (here, a bare LF hidden in a
    /// chunk extension) gets a 400 and never reaches the origin.
    #[test]
    fn forward_answers_400_to_malformed_framing() {
        let upstream = SharedConn::new(vec![OK_2]);
        let (client, connector) = run_forward_test(
            vec![
                b"POST http://93.184.216.34/x HTTP/1.1\r\nHost: h\r\n\
                   Transfer-Encoding: chunked\r\n\r\n5;a=b\nfoo\r\nhello\r\n0\r\n\r\n",
            ],
            std::slice::from_ref(&upstream),
        );
        assert_eq!(client.as_bytes(), RESP_400);
        assert_eq!(connector.connects(), 0);
    }

    /// A response head that never ends is cut off instead of buffered.
    #[test]
    fn forward_rejects_an_endless_response_head() {
        let mut script: Vec<&[u8]> = vec![b"HTTP/1.1 200 OK\r\n"];
        let filler = [b'a'; 1024];
        script.extend(std::iter::repeat_n(&filler[..], 1000));
        let upstream = SharedConn::new(script);
        let (client, _) = run_forward_test(vec![GET], std::slice::from_ref(&upstream));
        assert_eq!(client.as_bytes(), RESP_502);
        assert!(upstream.unread() > 900, "{} reads left", upstream.unread());
    }

    /// Regression: the body limit was only applied to a chunked upload once it
    /// was complete, so one that never completed was buffered without bound.
    #[test]
    fn chunked_upload_over_the_limit_is_rejected_while_still_arriving() {
        let mut script: Vec<&[u8]> =
            vec![b"POST http://h/ HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"];
        script.extend(std::iter::repeat_n(&b"8\r\n01234567\r\n"[..], 1000));
        let mut conn = MockConn::new(script);
        let mut acc = BytesMut::new();
        let result = block_on(relay_once(&mut conn, &mut acc, true, None, 100));
        assert!(matches!(result, Err(RelayErr::TooLarge)), "{result:?}");
        assert!(conn.reads.len() > 900, "{} reads left", conn.reads.len());

        // Within the limit it still goes through.
        let mut ok = MockConn::new(vec![
            b"POST http://h/ HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"8\r\n01234567\r\n",
            b"0\r\n\r\n",
        ]);
        let mut acc = BytesMut::new();
        assert!(block_on(relay_once(&mut ok, &mut acc, true, None, 100)).is_ok());
    }

    /// Regression: every read re-scanned the whole request, so an upload sent
    /// in small pieces cost work in proportion to the square of its size.
    /// However many reads it takes, the message is now scanned a fixed number
    /// of times.
    #[test]
    fn upload_arriving_in_many_reads_is_not_rescanned_each_time() {
        let scans_for = |script: Vec<&[u8]>| {
            FULL_SCANS.with(|n| n.set(0));
            let mut conn = MockConn::new(script);
            let mut acc = BytesMut::new();
            let msg = block_on(relay_once(&mut conn, &mut acc, true, None, 0)).unwrap();
            (FULL_SCANS.with(|n| n.get()), msg.len())
        };

        let head: &[u8] =
            b"POST http://h/ HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut chunked: Vec<&[u8]> = vec![head];
        // Chunks split across reads at awkward places.
        chunked.extend(
            std::iter::repeat_n(&b"8\r\n0123"[..], 2000).flat_map(|a| [a, &b"4567\r\n"[..]]),
        );
        chunked.push(b"0\r\n\r\n");
        let (scans, len) = scans_for(chunked);
        assert_eq!(len, head.len() + 2000 * 13 + 5);
        assert!(scans <= 3, "{scans} scans for a 4001-read chunked upload");

        let head: &[u8] = b"POST http://h/ HTTP/1.1\r\nHost: h\r\nContent-Length: 4000\r\n\r\n";
        let mut sized: Vec<&[u8]> = vec![head];
        sized.extend(std::iter::repeat_n(&b"ab"[..], 2000));
        let (scans, len) = scans_for(sized);
        assert_eq!(len, head.len() + 4000);
        assert!(scans <= 3, "{scans} scans for a 2001-read sized upload");

        // The head itself arriving in pieces still works.
        let pieces: Vec<&[u8]> = vec![
            b"POST http://h/ HTTP/1.1\r\nHost: h\r\nContent-Le",
            b"ngth: 3\r\n\r",
            b"\nab",
            b"c",
        ];
        let expected: usize = pieces.iter().map(|p| p.len()).sum();
        let (_, len) = scans_for(pieces);
        assert_eq!(len, expected);
    }

    /// A malformed chunked upload is still rejected when the shortcut is in use.
    #[test]
    fn malformed_chunked_upload_is_rejected_mid_stream() {
        let mut conn = MockConn::new(vec![
            b"POST http://h/ HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"3\r\nabc\r\n",
            b"zz\r\nabc\r\n",
            b"0\r\n\r\n",
        ]);
        let mut acc = BytesMut::new();
        let result = block_on(relay_once(&mut conn, &mut acc, true, None, 0));
        assert!(matches!(result, Err(RelayErr::Malformed)), "{result:?}");
        assert_eq!(
            conn.reads.len(),
            1,
            "rejected as soon as the bad chunk arrived"
        );
    }

    #[test]
    fn accept_error_backoff_grows_and_is_capped() {
        assert_eq!(accept_error_backoff(1), Duration::from_millis(10));
        assert_eq!(accept_error_backoff(20), Duration::from_millis(200));
        assert_eq!(accept_error_backoff(50), Duration::from_millis(500));
        assert_eq!(accept_error_backoff(u32::MAX), Duration::from_millis(500));
    }

    /// A request head that never ends is cut off instead of buffered.
    #[test]
    fn endless_request_head_is_rejected() {
        let mut script: Vec<&[u8]> = vec![b"GET http://h/ HTTP/1.1\r\n"];
        let filler = [b'a'; 1024];
        script.extend(std::iter::repeat_n(&filler[..], 1000));
        let mut conn = MockConn::new(script);
        let mut acc = BytesMut::new();
        let result = block_on(relay_once(&mut conn, &mut acc, true, None, 0));
        assert!(matches!(result, Err(RelayErr::Closed)), "{result:?}");
        assert!(conn.reads.len() > 900, "{} reads left", conn.reads.len());
    }

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

    /// Regression: a POST on a reused connection that failed was sent again,
    /// so the origin could execute it twice. A POST now always travels on a
    /// fresh connection and is never replayed.
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
