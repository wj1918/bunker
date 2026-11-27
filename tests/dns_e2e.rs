//! In-process integration tests for the DNS server.
//!
//! These start the real server on loopback, with a fake upstream resolver
//! next to it, and talk to it over real sockets — no network access needed.
//! The proxy's counterpart is `tests/engine_e2e.rs`.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use bunker::config::{
    DnsCacheConfig, DnsFailoverConfig, DnsSecurityConfig, LogFormat, LoggingConfig,
};
use bunker::dns::run_dns_server;

/// Helper to find an available UDP port
fn get_available_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

fn test_logging_config() -> LoggingConfig {
    LoggingConfig {
        log_requests: false, // Disable logging for tests to reduce noise
        format: LogFormat::Text,
        redact_sensitive_headers: true,
        sensitive_headers: vec![
            "authorization".to_string(),
            "proxy-authorization".to_string(),
            "cookie".to_string(),
        ],
        file: None,
        level: None,
    }
}

fn test_dns_security_config() -> DnsSecurityConfig {
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

fn test_dns_cache_config() -> DnsCacheConfig {
    DnsCacheConfig {
        enabled: true,
        max_entries: 100,
        min_ttl_seconds: 30,
        max_ttl_seconds: 300,
    }
}

fn test_dns_failover_config() -> DnsFailoverConfig {
    DnsFailoverConfig {
        timeout_ms: 2000,
        max_retries: 1,
        serve_stale: true,
    }
}

/// The address every `FakeUpstream` answers A queries with.
const FAKE_ANSWER: [u8; 4] = [192, 0, 2, 1];

/// Records in the answer for names starting with "big": 16 bytes each, so the
/// answer is well past the 512 bytes a plain UDP client can take.
const BIG_ANSWER_RECORDS: u8 = 50;

/// A stand-in for the upstream resolver, on loopback, so the DNS tests need
/// no network and every assertion can be a hard one. Answers each query with
/// one A record (`FAKE_ANSWER`, TTL 60) and counts the queries it receives.
struct FakeUpstream {
    addr: SocketAddr,
    queries: Arc<std::sync::atomic::AtomicUsize>,
}

impl FakeUpstream {
    async fn start() -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&queries);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut reply = buf[..len].to_vec();
                reply[2] = 0x81; // response, recursion desired
                reply[3] = 0x80; // recursion available, NOERROR
                                 // A name starting with "big" gets an answer too large for a
                                 // plain 512-byte UDP client; everything else gets one record.
                let records: u8 = if reply[12..].starts_with(b"\x03big") {
                    BIG_ANSWER_RECORDS
                } else {
                    1
                };
                reply[7] = records;
                for _ in 0..records {
                    reply.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to the question
                    reply.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
                    reply.extend_from_slice(&60u32.to_be_bytes()); // TTL
                    reply.extend_from_slice(&[0, 4]); // RDLENGTH
                    reply.extend_from_slice(&FAKE_ANSWER);
                }
                let _ = socket.send_to(&reply, from).await;
            }
        });
        FakeUpstream { addr, queries }
    }

    fn queries(&self) -> usize {
        self.queries.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Send `query` to the DNS server and wait for the reply (`None` on timeout).
///
/// Uses an async socket on purpose. These tests run on a single-threaded
/// runtime together with the server under test; a blocking `recv_from` would
/// park the only thread, the server would never run, and the wait would
/// always time out.
async fn dns_exchange(server: SocketAddr, query: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(query, server).await.unwrap();
    let mut response = [0u8; 512];
    match tokio::time::timeout(wait, socket.recv_from(&mut response)).await {
        Ok(Ok((len, _))) => Some(response[..len].to_vec()),
        _ => None,
    }
}

/// `dns_exchange`, for a query that must be answered.
async fn dns_reply(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let reply = dns_exchange(server, query, Duration::from_secs(3))
        .await
        .expect("no reply from the DNS server");
    assert!(reply.len() >= 12, "reply shorter than a DNS header");
    assert_eq!(&reply[..2], &query[..2], "transaction ID must match");
    assert!(reply[2] & 0x80 != 0, "QR bit must mark a response");
    reply
}

/// Send `query` to the DNS server over TCP (two-byte length prefix each way).
async fn dns_reply_tcp(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(server).await.unwrap();
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(query).await.unwrap();
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    };
    let reply = tokio::time::timeout(Duration::from_secs(5), exchange)
        .await
        .expect("no reply from the DNS server over TCP");
    assert_eq!(&reply[..2], &query[..2], "transaction ID must match");
    reply
}

fn answer_count(reply: &[u8]) -> u16 {
    u16::from_be_bytes([reply[6], reply[7]])
}

fn rcode(reply: &[u8]) -> u8 {
    reply[3] & 0x0f
}
const NOERROR: u8 = 0;
const REFUSED: u8 = 5;

/// Start a DNS server forwarding to a resolver that is never reached, for
/// tests of queries the server answers by itself.
async fn start_test_dns_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    // TEST-NET-3: reserved, never routed.
    start_test_dns_server_with("203.0.113.1:53".parse().unwrap()).await
}

/// Start a DNS server forwarding to `upstream` and return its address
async fn start_test_dns_server_with(
    upstream: SocketAddr,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let port = get_available_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let upstreams = vec![upstream.to_string()];
    let security = test_dns_security_config();
    let cache_config = test_dns_cache_config();
    let failover_config = test_dns_failover_config();
    let logging = test_logging_config();
    let allowed_ips = vec![];

    let handle = tokio::spawn(async move {
        let _ = run_dns_server(
            addr,
            upstreams,
            security,
            cache_config,
            failover_config,
            logging,
            allowed_ips,
        )
        .await;
    });

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(100)).await;

    (addr, handle)
}

/// Build a simple DNS query for testing
#[allow(clippy::vec_init_then_push)]
fn build_dns_query(domain: &str, query_id: u16) -> Vec<u8> {
    let mut query = Vec::new();

    // Transaction ID
    query.push((query_id >> 8) as u8);
    query.push((query_id & 0xff) as u8);

    // Flags: standard query, recursion desired
    query.push(0x01);
    query.push(0x00);

    // Questions: 1
    query.push(0x00);
    query.push(0x01);

    // Answer RRs, Authority RRs, Additional RRs: 0
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Domain name
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00); // End of domain

    // Type: A (1)
    query.push(0x00);
    query.push(0x01);

    // Class: IN (1)
    query.push(0x00);
    query.push(0x01);

    query
}

/// Build an ANY type DNS query (should be blocked)
#[allow(clippy::vec_init_then_push)]
fn build_any_dns_query(domain: &str, query_id: u16) -> Vec<u8> {
    let mut query = Vec::new();

    // Transaction ID
    query.push((query_id >> 8) as u8);
    query.push((query_id & 0xff) as u8);

    // Flags: standard query
    query.push(0x01);
    query.push(0x00);

    // Questions: 1
    query.push(0x00);
    query.push(0x01);

    // Answer RRs, Authority RRs, Additional RRs: 0
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Domain name
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);

    // Type: ANY (255)
    query.push(0x00);
    query.push(0xff);

    // Class: IN (1)
    query.push(0x00);
    query.push(0x01);

    query
}

// ============== DNS Tests ==============

#[tokio::test]
async fn test_dns_query_forwarding() {
    let upstream = FakeUpstream::start().await;
    let (dns_addr, _handle) = start_test_dns_server_with(upstream.addr).await;

    let reply = dns_reply(dns_addr, &build_dns_query("google.com", 0x1234)).await;
    assert_eq!(rcode(&reply), NOERROR);
    assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1, "one answer");
    assert!(reply.ends_with(&FAKE_ANSWER), "answer from the upstream");
    assert_eq!(upstream.queries(), 1);
}

#[tokio::test]
async fn test_dns_any_query_blocked() {
    let upstream = FakeUpstream::start().await;
    let (dns_addr, _handle) = start_test_dns_server_with(upstream.addr).await;

    let reply = dns_reply(dns_addr, &build_any_dns_query("example.com", 0x5678)).await;
    assert_eq!(rcode(&reply), REFUSED);
    assert_eq!(
        upstream.queries(),
        0,
        "a blocked query must not be forwarded"
    );
}

/// Regression: a receive error must not end the DNS serve loop. On Windows an
/// oversized datagram (WSAEMSGSIZE) and a reply that hit a closed client port
/// (WSAECONNRESET) both surface as `recv_from` errors; the server used to
/// propagate them and stop answering for good. On Linux neither produces an
/// error, so there this only checks the server keeps serving afterwards.
#[tokio::test]
async fn test_dns_server_survives_receive_errors() {
    let (dns_addr, _handle) = start_test_dns_server().await;

    // 1. Datagram larger than the server's receive buffer.
    let oversized = UdpSocket::bind("127.0.0.1:0").unwrap();
    oversized.send_to(&[0u8; 600], dns_addr).unwrap();

    // 2. Query whose reply lands on a closed port: the ANY query is answered
    //    locally (REFUSED), and the client socket is gone before it arrives.
    {
        let vanishing = UdpSocket::bind("127.0.0.1:0").unwrap();
        vanishing
            .send_to(&build_any_dns_query("example.com", 0x0001), dns_addr)
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. The server must still answer. ANY is refused locally, so this needs
    //    no upstream.
    let reply = dns_reply(dns_addr, &build_any_dns_query("example.com", 0x4242)).await;
    assert_eq!(rcode(&reply), REFUSED);
}

#[tokio::test]
async fn test_dns_multiple_queries() {
    let upstream = FakeUpstream::start().await;
    let (dns_addr, _handle) = start_test_dns_server_with(upstream.addr).await;

    let domains = ["example.com", "google.com", "cloudflare.com"];
    for (i, domain) in domains.iter().enumerate() {
        let reply = dns_reply(dns_addr, &build_dns_query(domain, (0x1000 + i) as u16)).await;
        assert_eq!(rcode(&reply), NOERROR, "{domain}");
        assert!(reply.ends_with(&FAKE_ANSWER), "{domain}");
    }
    assert_eq!(upstream.queries(), domains.len());
}

#[tokio::test]
async fn test_dns_cache_hit() {
    let upstream = FakeUpstream::start().await;
    let (dns_addr, _handle) = start_test_dns_server_with(upstream.addr).await;

    let first = dns_reply(dns_addr, &build_dns_query("example.com", 0x1111)).await;
    assert_eq!(upstream.queries(), 1);

    // Same name again: answered from the cache, under the new transaction ID
    // (checked by `dns_reply`), without asking the upstream.
    let second = dns_reply(dns_addr, &build_dns_query("example.com", 0x2222)).await;
    assert_eq!(
        upstream.queries(),
        1,
        "second query must come from the cache"
    );
    assert_eq!(first[2..], second[2..], "same answer apart from the ID");

    // A different name is not a cache hit.
    dns_reply(dns_addr, &build_dns_query("example.org", 0x3333)).await;
    assert_eq!(upstream.queries(), 2);
}

#[tokio::test]
async fn test_dns_over_tcp_answers_queries() {
    let upstream = FakeUpstream::start().await;
    let (dns_addr, _handle) = start_test_dns_server_with(upstream.addr).await;

    let reply = dns_reply_tcp(dns_addr, &build_dns_query("example.com", 0x7001)).await;
    assert_eq!(rcode(&reply), NOERROR);
    assert_eq!(answer_count(&reply), 1);
    assert!(reply.ends_with(&FAKE_ANSWER));

    // The same policy applies as over UDP.
    let reply = dns_reply_tcp(dns_addr, &build_any_dns_query("example.com", 0x7002)).await;
    assert_eq!(rcode(&reply), REFUSED);
}

/// An answer too big for a plain UDP client comes back truncated (TC bit, no
/// records), and the retry over TCP that this invites returns all of it.
#[tokio::test]
async fn test_dns_large_answer_is_truncated_over_udp_and_whole_over_tcp() {
    let upstream = FakeUpstream::start().await;
    let (dns_addr, _handle) = start_test_dns_server_with(upstream.addr).await;
    let query = build_dns_query("big.example.com", 0x7003);

    // Twice: straight from the upstream, then from the cache.
    for round in 0..2 {
        let over_udp = dns_reply(dns_addr, &query).await;
        assert!(
            over_udp.len() <= 512,
            "round {round}: {} bytes",
            over_udp.len()
        );
        assert!(over_udp[2] & 0x02 != 0, "round {round}: TC bit must be set");
        assert_eq!(answer_count(&over_udp), 0, "round {round}");
    }

    let over_tcp = dns_reply_tcp(dns_addr, &query).await;
    assert!(over_tcp[2] & 0x02 == 0, "the TCP answer is complete");
    assert_eq!(answer_count(&over_tcp), u16::from(BIG_ANSWER_RECORDS));
    assert!(over_tcp.len() > 512);
    assert_eq!(
        upstream.queries(),
        1,
        "one upstream query served all three clients"
    );
}

#[tokio::test]
async fn test_dns_axfr_blocked() {
    let upstream = FakeUpstream::start().await;
    let (dns_addr, _handle) = start_test_dns_server_with(upstream.addr).await;

    // Build AXFR query (zone transfer - should be blocked)
    let mut query = build_dns_query("example.com", 0xABCD);
    // Change type from A (1) to AXFR (252)
    let type_offset = query.len() - 4;
    query[type_offset] = 0x00;
    query[type_offset + 1] = 0xFC; // AXFR = 252

    let reply = dns_reply(dns_addr, &query).await;
    assert_eq!(rcode(&reply), REFUSED);
    assert_eq!(
        upstream.queries(),
        0,
        "a blocked query must not be forwarded"
    );
}

#[tokio::test]
async fn test_dns_malformed_query() {
    let upstream = FakeUpstream::start().await;
    let (dns_addr, _handle) = start_test_dns_server_with(upstream.addr).await;

    // Too short to be a DNS message: just a transaction ID. There is nothing
    // to answer, so the server drops it without forwarding anything.
    let malformed = [0x12, 0x34];
    let reply = dns_exchange(dns_addr, &malformed, Duration::from_millis(300)).await;
    assert_eq!(reply, None, "a 2-byte datagram must not be answered");
    assert_eq!(upstream.queries(), 0);

    // And it keeps serving afterwards.
    let reply = dns_reply(dns_addr, &build_dns_query("example.com", 0x4321)).await;
    assert_eq!(rcode(&reply), NOERROR);
}

// ============== Port/Protocol Tests ==============
