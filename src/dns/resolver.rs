//! DNS resolver trait with generics for zero-cost abstraction.

use crate::config::DnsSecurityConfig;
use crate::dns::wire::{is_truncated, DnsQuery};
use crate::error::DnsError;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
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

    /// Whether `upstream` recently failed to answer and should be tried last.
    fn is_down(&self, _upstream: SocketAddr) -> bool {
        false
    }

    /// Record whether `upstream` answered (`true`) or timed out / errored.
    fn report(&self, _upstream: SocketAddr, _answered: bool) {}
}

/// Largest payload a UDP datagram can carry (65535 minus IP and UDP headers
/// is smaller still; this bound is simply never exceeded).
pub(crate) const MAX_UDP_PAYLOAD: usize = 65535;

/// How long an upstream that failed to answer is tried last instead of first.
const DOWN_COOLDOWN: Duration = Duration::from_secs(30);

/// UDP-based DNS resolver implementation
pub struct UdpDnsResolver {
    security: DnsSecurityConfig,
    /// Fetch the full answer over TCP when the UDP one comes back truncated.
    tcp_fallback: bool,
    /// Upstreams that recently failed to answer, and when.
    down: std::sync::Mutex<std::collections::HashMap<SocketAddr, std::time::Instant>>,
}

impl UdpDnsResolver {
    pub fn new(security: DnsSecurityConfig) -> Self {
        Self {
            security,
            tcp_fallback: false,
            down: Default::default(),
        }
    }

    /// When an upstream's UDP answer is truncated (TC bit), ask it again over
    /// TCP and return the full answer.
    ///
    /// For callers that need the whole answer themselves: the proxy's own
    /// lookups, and queries that reached the DNS server over TCP. A query
    /// from a UDP client is better served by passing the truncated answer
    /// through — the client then retries over TCP, as the protocol intends.
    pub fn with_tcp_fallback(mut self) -> Self {
        self.tcp_fallback = true;
        self
    }
}

/// One DNS exchange over TCP (RFC 1035 §4.2.2: each message is preceded by its
/// length as two bytes), bounded by `timeout` in total.
async fn query_over_tcp(
    query: &[u8],
    upstream: SocketAddr,
    timeout: Duration,
) -> Result<Vec<u8>, DnsError> {
    let exchange = async {
        let length = u16::try_from(query.len())
            .map_err(|_| std::io::Error::other("query too long for DNS over TCP"))?;
        let mut stream = TcpStream::connect(upstream).await?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(query).await?;
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await?;
        let mut response = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(response)) => {
            validate_upstream_response(query, &response)?;
            Ok(response)
        }
        Ok(Err(e)) => Err(DnsError::ParseError(e.to_string())),
        Err(_) => Err(DnsError::Timeout),
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

        // Room for the largest possible UDP payload. Client queries are
        // forwarded verbatim, including an EDNS0 OPT record that tells the
        // upstream it may answer with up to 1232 / 4096 / ... bytes; a 512-byte
        // buffer silently cut such answers short on Linux (and was then cached
        // corrupted) and failed the read outright on Windows.
        let mut recv_buf = vec![0u8; MAX_UDP_PAYLOAD];
        let deadline = tokio::time::Instant::now() + timeout;
        let mut warned = false;

        // Wait for the upstream's answer until the deadline. A datagram that
        // is not that answer — wrong source, wrong transaction ID, wrong
        // question — is dropped and the wait continues. Giving up on the first
        // such datagram (as this used to) let anyone who could reach the
        // socket fail a lookup with a single junk packet, before the genuine
        // answer had a chance to arrive.
        loop {
            let received = tokio::time::timeout_at(deadline, socket.recv_from(&mut recv_buf)).await;
            let (len, from) = match received {
                Ok(Ok(datagram)) => datagram,
                Ok(Err(e)) => return Err(DnsError::ParseError(e.to_string())),
                Err(_) => return Err(DnsError::Timeout),
            };
            // Source check (anti-spoofing), then transaction-ID and
            // question-section echo. The latter run unconditionally — they
            // also cover an on-path attacker who spoofs the upstream's address.
            let problem = if self.security.verify_upstream_source && from != upstream {
                Some("unexpected source")
            } else if validate_upstream_response(query, &recv_buf[..len]).is_err() {
                Some("ID or question mismatch")
            } else {
                None
            };
            match problem {
                None => {
                    // Copy out just the datagram: the result is long-lived (it
                    // is cached), so it must not keep the 64 KiB allocation.
                    let answer = recv_buf[..len].to_vec();
                    if self.tcp_fallback && is_truncated(&answer) {
                        // Too big for UDP. If TCP fails too, the truncated
                        // answer is still the best we have.
                        if let Ok(full) = query_over_tcp(query, upstream, timeout).await {
                            return Ok(full);
                        }
                    }
                    return Ok(answer);
                }
                Some(problem) => {
                    // Once per query: a flood must not flood the log too.
                    if enable_logging && !warned {
                        warned = true;
                        warn!(
                            from = %from,
                            expected = %upstream,
                            problem,
                            "DNS datagram ignored (possible spoofing attempt)"
                        );
                    }
                }
            }
        }
    }

    fn is_down(&self, upstream: SocketAddr) -> bool {
        self.down
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&upstream)
            .is_some_and(|since| since.elapsed() < DOWN_COOLDOWN)
    }

    fn report(&self, upstream: SocketAddr, answered: bool) {
        let mut down = self
            .down
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if answered {
            down.remove(&upstream);
        } else {
            down.insert(upstream, std::time::Instant::now());
        }
    }
}

/// An answer that says this upstream could not or would not resolve the name,
/// as opposed to an answer about the name. Another upstream may do better.
fn is_upstream_refusal(response: &[u8]) -> bool {
    const SERVFAIL: u8 = 2;
    const NOTIMP: u8 = 4;
    const REFUSED: u8 = 5;
    response
        .get(3)
        .is_some_and(|flags| matches!(flags & 0x0f, SERVFAIL | NOTIMP | REFUSED))
}

/// Handle DNS query with failover support using a generic resolver.
///
/// Upstreams are tried in the configured order, except that one which
/// recently failed to answer goes to the back of the queue — otherwise every
/// lookup would wait out the full timeout on a dead first upstream. An
/// upstream that answers SERVFAIL / REFUSED / NOTIMP counts as failed for this
/// query and the next is asked; if none does better, that answer is returned
/// so the client still sees the real response code.
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
    let mut refusal: Option<Vec<u8>> = None;

    for attempt in 0..total_attempts {
        if attempt > 0 && enable_logging {
            debug!(attempt = attempt, max_retries = max_retries, "DNS retry");
        }

        // Healthy upstreams first, in configured order; then the rest.
        let (healthy, down): (Vec<SocketAddr>, Vec<SocketAddr>) =
            upstreams.iter().partition(|u| !resolver.is_down(**u));
        for (idx, upstream) in healthy.iter().chain(down.iter()).enumerate() {
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
                Ok(response) => {
                    resolver.report(*upstream, true);
                    if !is_upstream_refusal(&response) {
                        return Ok(response);
                    }
                    if enable_logging {
                        debug!(upstream = %upstream, "DNS upstream refused or failed the query");
                    }
                    refusal = Some(response);
                }
                Err(e) => {
                    resolver.report(*upstream, false);
                    if enable_logging {
                        warn!(upstream = %upstream, error = %e, "DNS upstream failed");
                    }
                    // Continue to next upstream
                }
            }
        }
        // Every upstream was asked. If one of them answered (with a refusal),
        // asking the same servers again will not change it.
        if refusal.is_some() {
            break;
        }
    }

    refusal.ok_or(DnsError::UpstreamFailed)
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

    /// Regression: upstream answers were read into a 512-byte buffer, so a
    /// larger answer (normal once the client advertises EDNS0) came back cut
    /// short on Linux and failed the read on Windows.
    #[tokio::test]
    async fn udp_resolver_returns_answers_larger_than_512_bytes() {
        use crate::dns::wire::{builder, RecordType};
        use std::net::{IpAddr, Ipv4Addr};

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let query = builder::build_query("big.test", RecordType::A, 0x4242);
        // 100 A records: well over 512 bytes, under a typical 1232-byte limit.
        let ips: Vec<IpAddr> = (0..100)
            .map(|i| IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)))
            .collect();
        let big = builder::build_response_with_ips(&query, &ips, RecordType::A, 60);
        assert!(big.len() > 512, "test answer is only {} bytes", big.len());

        let expected = big.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, from) = upstream.recv_from(&mut buf).await.unwrap();
            upstream.send_to(&big, from).await.unwrap();
        });

        let resolver = UdpDnsResolver::new(DnsSecurityConfig::default());
        let got = resolver
            .resolve(&query, upstream_addr, Duration::from_secs(3), false)
            .await
            .expect("large answer should be accepted");
        assert_eq!(got.len(), expected.len());
        assert_eq!(got, expected);
        // The cached copy must not pin the 64 KiB receive buffer.
        assert!(got.capacity() < 4096, "capacity {}", got.capacity());
    }

    // ---------- stray datagrams, failover, upstream health ----------

    fn udp_resolver() -> UdpDnsResolver {
        UdpDnsResolver::new(DnsSecurityConfig::default())
    }

    /// Regression: the first datagram that was not the upstream's answer
    /// failed the lookup. Now it is ignored and the real answer is used.
    #[tokio::test]
    async fn stray_datagrams_do_not_fail_the_lookup() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = builder::build_query("example.com", RecordType::A, 0xBEEF);
        let answer = builder::build_response(
            "example.com",
            "93.184.216.34",
            0xBEEF,
            300,
            ResponseCode::NoError,
        );
        let wrong_id =
            builder::build_response("example.com", "6.6.6.6", 0x0001, 300, ResponseCode::NoError);
        let wrong_name = builder::build_response(
            "evil.example",
            "6.6.6.6",
            0xBEEF,
            300,
            ResponseCode::NoError,
        );

        let expected = answer.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, resolver_addr) = upstream.recv_from(&mut buf).await.unwrap();
            // From an unrelated address, with a perfectly valid-looking answer.
            stranger.send_to(&wrong_name, resolver_addr).await.unwrap();
            stranger.send_to(&answer, resolver_addr).await.unwrap();
            // From the upstream's own address, but not answering our query.
            upstream.send_to(&wrong_id, resolver_addr).await.unwrap();
            upstream.send_to(&wrong_name, resolver_addr).await.unwrap();
            upstream.send_to(&[0u8; 3], resolver_addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            upstream.send_to(&answer, resolver_addr).await.unwrap();
        });

        let got = udp_resolver()
            .resolve(&query, upstream_addr, Duration::from_secs(3), false)
            .await;
        assert_eq!(got.unwrap(), expected);
    }

    /// Junk alone never satisfies the query: it still times out.
    #[tokio::test]
    async fn only_stray_datagrams_end_in_a_timeout() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let query = builder::build_query("example.com", RecordType::A, 0xBEEF);
        let wrong_id =
            builder::build_response("example.com", "6.6.6.6", 0x0001, 300, ResponseCode::NoError);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, resolver_addr) = upstream.recv_from(&mut buf).await.unwrap();
            for _ in 0..5 {
                upstream.send_to(&wrong_id, resolver_addr).await.unwrap();
            }
        });
        let got = udp_resolver()
            .resolve(&query, upstream_addr, Duration::from_millis(300), false)
            .await;
        assert!(matches!(got, Err(DnsError::Timeout)), "{got:?}");
    }

    /// Per-upstream scripted answers, recording the order upstreams are asked
    /// in and keeping the health marks the failover logic reports.
    #[derive(Default)]
    struct ScriptedResolver {
        answers: std::collections::HashMap<SocketAddr, Vec<u8>>,
        asked: std::sync::Mutex<Vec<SocketAddr>>,
        down: std::sync::Mutex<std::collections::HashSet<SocketAddr>>,
    }
    impl DnsResolver for ScriptedResolver {
        async fn resolve(
            &self,
            _query: &[u8],
            upstream: SocketAddr,
            _timeout: Duration,
            _enable_logging: bool,
        ) -> Result<Vec<u8>, DnsError> {
            self.asked.lock().unwrap().push(upstream);
            self.answers
                .get(&upstream)
                .cloned()
                .ok_or(DnsError::Timeout)
        }
        fn is_down(&self, upstream: SocketAddr) -> bool {
            self.down.lock().unwrap().contains(&upstream)
        }
        fn report(&self, upstream: SocketAddr, answered: bool) {
            let mut down = self.down.lock().unwrap();
            if answered {
                down.remove(&upstream);
            } else {
                down.insert(upstream);
            }
        }
    }

    fn reply(rcode: ResponseCode) -> Vec<u8> {
        builder::build_response("example.com", "93.184.216.34", 1, 300, rcode)
    }

    async fn ask(
        resolver: &ScriptedResolver,
        upstreams: &[SocketAddr],
        retries: u32,
    ) -> Result<Vec<u8>, DnsError> {
        handle_dns_query_with_resolver(
            resolver,
            &[0, 1],
            upstreams,
            Duration::from_secs(1),
            retries,
            false,
        )
        .await
    }

    /// Regression: SERVFAIL from the first upstream was returned as the
    /// answer and the second upstream was never asked.
    #[tokio::test]
    async fn refusal_from_one_upstream_fails_over_to_the_next() {
        let (a, b): (SocketAddr, SocketAddr) = (
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        );
        for refusal in [
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::NotImp,
        ] {
            let mut resolver = ScriptedResolver::default();
            resolver.answers.insert(a, reply(refusal));
            resolver.answers.insert(b, reply(ResponseCode::NoError));
            let got = ask(&resolver, &[a, b], 1).await.unwrap();
            assert_eq!(got, reply(ResponseCode::NoError), "{refusal:?}");
            assert_eq!(*resolver.asked.lock().unwrap(), vec![a, b]);
        }

        // NXDOMAIN is an answer about the name, not a failure of the server.
        let mut resolver = ScriptedResolver::default();
        resolver.answers.insert(a, reply(ResponseCode::NxDomain));
        resolver.answers.insert(b, reply(ResponseCode::NoError));
        assert_eq!(
            ask(&resolver, &[a, b], 1).await.unwrap(),
            reply(ResponseCode::NxDomain)
        );
        assert_eq!(*resolver.asked.lock().unwrap(), vec![a]);
    }

    /// When every upstream refuses, the client gets that answer (not a
    /// made-up error), and the same servers are not asked again.
    #[tokio::test]
    async fn refusal_from_every_upstream_is_returned_as_is() {
        let (a, b): (SocketAddr, SocketAddr) = (
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        );
        let mut resolver = ScriptedResolver::default();
        resolver.answers.insert(a, reply(ResponseCode::ServFail));
        resolver.answers.insert(b, reply(ResponseCode::Refused));
        assert_eq!(
            ask(&resolver, &[a, b], 3).await.unwrap(),
            reply(ResponseCode::Refused)
        );
        assert_eq!(resolver.asked.lock().unwrap().len(), 2);
    }

    /// Regression: a dead first upstream was tried first on every lookup, so
    /// each one waited out the full timeout. After it fails once it goes to
    /// the back; when it answers again it returns to its place.
    #[tokio::test]
    async fn an_upstream_that_failed_is_tried_last_until_it_answers() {
        let (dead, live): (SocketAddr, SocketAddr) = (
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        );
        let mut resolver = ScriptedResolver::default();
        resolver.answers.insert(live, reply(ResponseCode::NoError));

        ask(&resolver, &[dead, live], 0).await.unwrap();
        assert_eq!(
            std::mem::take(&mut *resolver.asked.lock().unwrap()),
            vec![dead, live]
        );
        // Second lookup: straight to the live one.
        ask(&resolver, &[dead, live], 0).await.unwrap();
        assert_eq!(
            std::mem::take(&mut *resolver.asked.lock().unwrap()),
            vec![live]
        );

        // If the live one dies too, the marked-down one is still tried.
        resolver.answers.clear();
        resolver.answers.insert(dead, reply(ResponseCode::NoError));
        ask(&resolver, &[dead, live], 0).await.unwrap();
        assert_eq!(
            std::mem::take(&mut *resolver.asked.lock().unwrap()),
            vec![live, dead]
        );
        // It answered, so it is first again.
        ask(&resolver, &[dead, live], 0).await.unwrap();
        assert_eq!(
            std::mem::take(&mut *resolver.asked.lock().unwrap()),
            vec![dead]
        );
    }

    #[test]
    fn udp_resolver_remembers_and_forgets_failed_upstreams() {
        let resolver = udp_resolver();
        let upstream: SocketAddr = "192.0.2.1:53".parse().unwrap();
        assert!(!resolver.is_down(upstream));
        resolver.report(upstream, false);
        assert!(resolver.is_down(upstream));
        resolver.report(upstream, true);
        assert!(!resolver.is_down(upstream));
    }

    // ---------- TCP fallback for truncated answers ----------

    /// An upstream that answers over UDP with an empty truncated reply and
    /// over TCP (same port) with the real answer.
    async fn truncating_upstream(answer: Vec<u8>) -> SocketAddr {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, from)) = udp.recv_from(&mut buf).await {
                let mut reply = buf[..len].to_vec();
                reply[2] = 0x83; // response, TC set
                reply[3] = 0x80;
                let _ = udp.send_to(&reply, from).await;
            }
        });
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).await.is_err() {
                    continue;
                }
                let mut query = vec![0u8; u16::from_be_bytes(length) as usize];
                let _ = stream.read_exact(&mut query).await;
                let _ = stream.write_all(&(answer.len() as u16).to_be_bytes()).await;
                let _ = stream.write_all(&answer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn truncated_udp_answer_is_fetched_over_tcp_when_asked_to() {
        let query = builder::build_query("example.com", RecordType::A, 0xBEEF);
        let full = builder::build_response(
            "example.com",
            "93.184.216.34",
            0xBEEF,
            300,
            ResponseCode::NoError,
        );
        let upstream = truncating_upstream(full.clone()).await;
        let wait = Duration::from_secs(3);

        // Without the fallback the truncated answer is passed through.
        let passed = udp_resolver()
            .resolve(&query, upstream, wait, false)
            .await
            .unwrap();
        assert!(is_truncated(&passed));

        let fetched = udp_resolver()
            .with_tcp_fallback()
            .resolve(&query, upstream, wait, false)
            .await
            .unwrap();
        assert_eq!(fetched, full);
    }

    /// An answer over TCP is held to the same checks as one over UDP, and if
    /// TCP yields nothing usable the truncated UDP answer is still returned.
    #[tokio::test]
    async fn tcp_fallback_rejects_a_mismatched_answer() {
        let query = builder::build_query("example.com", RecordType::A, 0xBEEF);
        let wrong = builder::build_response(
            "evil.example",
            "6.6.6.6",
            0xBEEF,
            300,
            ResponseCode::NoError,
        );
        let upstream = truncating_upstream(wrong).await;
        let got = udp_resolver()
            .with_tcp_fallback()
            .resolve(&query, upstream, Duration::from_secs(3), false)
            .await
            .unwrap();
        assert!(is_truncated(&got), "fell back to the UDP answer");
        assert!(crate::dns::wire::extract_ips(&got, RecordType::A).is_empty());
    }
}
