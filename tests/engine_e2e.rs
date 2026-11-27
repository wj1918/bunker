//! End-to-end tests of the forward-proxy engine over real sockets.
//!
//! Everything runs on loopback: the engine (tokio backend, as shipped), a
//! small origin server, and plain blocking clients. No network access is
//! needed, so every assertion is a hard one. These are the only tests that
//! drive the engine through real sockets — its unit tests use scripted
//! in-memory connections.
#![cfg(feature = "engine")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bunker::config::{RateLimitConfig, SecurityConfig, TcpKeepaliveConfig};
use bunker::dns::DnsClient;
use bunker::proxy::engine::{run_forward, Backend, EngineConfig};

const BIG: usize = 8 * 1024 * 1024;

/// A minimal origin. Paths:
///   /ok       200 with body "OK"
///   /headers  200 with the request head as the body
///   /big      200 with `BIG` bytes of a repeating pattern (Content-Length)
///   /chunked  200 with the same bytes, chunked
///   /stream   200 with no length, three lines, then close
///   /silent   reads the request and never answers
///   (POST)    200 with the number of body bytes received
struct Origin {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

impl Origin {
    fn start() -> Origin {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || Origin::serve(stream));
            }
        });
        Origin { addr, connections }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn serve(mut stream: TcpStream) {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            // Read one request head.
            let head_end = loop {
                if let Some(i) = find(&buf, b"\r\n\r\n") {
                    break i + 4;
                }
                let mut chunk = [0u8; 16 * 1024];
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let path = head.split(' ').nth(1).unwrap_or("").to_string();
            let content_length = head
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            let chunked = head
                .to_ascii_lowercase()
                .contains("transfer-encoding: chunked");
            // Read the body, if any, and note how many payload bytes it had.
            let (consumed, body_bytes) = if chunked {
                let mut pos = head_end;
                let mut payload = 0usize;
                loop {
                    // Next chunk-size line.
                    let line_end = loop {
                        if let Some(i) = find(&buf[pos..], b"\r\n") {
                            break pos + i;
                        }
                        let mut chunk = [0u8; 64 * 1024];
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let size_text = String::from_utf8_lossy(&buf[pos..line_end]).into_owned();
                    let size = usize::from_str_radix(size_text.split(';').next().unwrap(), 16)
                        .expect("origin received a bad chunk size");
                    let chunk_end = line_end + 2 + size + 2;
                    while buf.len() < chunk_end {
                        let mut chunk = [0u8; 64 * 1024];
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    pos = chunk_end;
                    if size == 0 {
                        break (pos, payload);
                    }
                    payload += size;
                }
            } else {
                while buf.len() < head_end + content_length {
                    let mut chunk = [0u8; 64 * 1024];
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                (head_end + content_length, content_length)
            };
            buf.drain(..consumed);

            let sized = |body: &[u8]| {
                let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                    .into_bytes();
                out.extend_from_slice(body);
                out
            };
            let result = if head.starts_with("POST ") {
                stream.write_all(&sized(body_bytes.to_string().as_bytes()))
            } else {
                match path.as_str() {
                    "/headers" => stream.write_all(&sized(head.as_bytes())),
                    "/big" => stream.write_all(&sized(&pattern(BIG))),
                    "/chunked" => {
                        let mut out =
                            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                        for piece in pattern(BIG).chunks(60_000) {
                            out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                            out.extend_from_slice(piece);
                            out.extend_from_slice(b"\r\n");
                        }
                        out.extend_from_slice(b"0\r\n\r\n");
                        stream.write_all(&out)
                    }
                    "/stream" => {
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                        for line in ["one\n", "two\n", "three\n"] {
                            let _ = stream.write_all(line.as_bytes());
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        return; // close: that is what ends this body
                    }
                    "/silent" => {
                        std::thread::sleep(Duration::from_secs(30));
                        return;
                    }
                    _ => stream.write_all(&sized(b"OK")),
                }
            };
            if result.is_err() {
                return;
            }
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Settings for one engine instance; the defaults suit most tests.
struct Proxy {
    block_private_ips: bool,
    allowed_source_ips: Vec<String>,
    max_requests_per_conn: u32,
    upstream_read_timeout: Duration,
    forwarded_for: bool,
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            block_private_ips: false, // the origin is on loopback
            allowed_source_ips: vec![],
            max_requests_per_conn: 0,
            upstream_read_timeout: Duration::from_secs(10),
            forwarded_for: true,
        }
    }
}

impl Proxy {
    /// Start the engine on a free loopback port and wait until it accepts.
    fn start(self) -> SocketAddr {
        let addr = {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap()
        };
        let security = SecurityConfig {
            block_private_ips: self.block_private_ips,
            allowed_source_ips: self.allowed_source_ips,
            rate_limit: RateLimitConfig {
                enabled: false,
                ..RateLimitConfig::default()
            },
            ..SecurityConfig::default()
        };
        let cfg = Arc::new(EngineConfig {
            security: Arc::new(security),
            dns_client: Arc::new(DnsClient::new_os(None)),
            rate_limit: RateLimitConfig {
                enabled: false,
                ..RateLimitConfig::default()
            },
            pool_max_per_host: 8,
            pool_max_total: 64,
            pool_idle_timeout: Duration::from_secs(30),
            pool_max_lifetime: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(5),
            header_read_timeout: Duration::from_secs(10),
            upstream_read_timeout: self.upstream_read_timeout,
            client_idle_timeout: Duration::from_secs(10),
            tcp_keepalive: TcpKeepaliveConfig::default(),
            forwarded_for: self.forwarded_for,
            max_request_body_bytes: 64 * 1024 * 1024,
            max_requests_per_conn: self.max_requests_per_conn,
            max_connections: 0,
            log_requests: false,
        });
        // The engine serves until the process exits; the thread is left running.
        std::thread::spawn(move || run_forward(addr, cfg, 2, Backend::Tokio));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if TcpStream::connect(addr).is_ok() {
                return addr;
            }
            assert!(Instant::now() < deadline, "engine did not start listening");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn connect(proxy: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(proxy).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
}

/// Read one response framed by Content-Length. Returns (head, body).
fn read_sized_response(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        let mut chunk = [0u8; 64 * 1024];
        let n = stream.read(&mut chunk).expect("reading a response head");
        assert!(n > 0, "connection closed before a response head arrived");
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let length: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .expect("response has no Content-Length");
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let mut chunk = [0u8; 64 * 1024];
        let n = stream.read(&mut chunk).expect("reading a response body");
        assert!(n > 0, "connection closed mid-body");
        body.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(body.len(), length, "bytes beyond the declared length");
    (head, body)
}

/// Read until the peer closes.
fn read_to_close(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    stream.read_to_end(&mut out).expect("reading until close");
    out
}

fn get(origin: &Origin, path: &str) -> String {
    format!(
        "GET http://{}{path} HTTP/1.1\r\nHost: {}\r\n\r\n",
        origin.addr, origin.addr
    )
}

#[test]
fn get_is_forwarded_and_the_upstream_connection_is_reused() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    for _ in 0..5 {
        client.write_all(get(&origin, "/ok").as_bytes()).unwrap();
        let (head, body) = read_sized_response(&mut client);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert_eq!(body, b"OK");
    }
    assert_eq!(
        origin.connections(),
        1,
        "five requests, one upstream connection"
    );
}

#[test]
fn request_is_rewritten_for_the_origin() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    let request = format!(
        "GET http://{}/headers HTTP/1.1\r\nHost: spoofed.example\r\n\
         X-Forwarded-For: 1.2.3.4\r\nConnection: X-Hop\r\nX-Hop: 1\r\nX-Kept: yes\r\n\r\n",
        origin.addr
    );
    client.write_all(request.as_bytes()).unwrap();
    let (_, body) = read_sized_response(&mut client);
    let seen = String::from_utf8(body).unwrap();
    assert!(seen.starts_with("GET /headers HTTP/1.1\r\n"), "{seen}");
    assert!(
        seen.contains(&format!("Host: {}\r\n", origin.addr)),
        "{seen}"
    );
    assert!(!seen.contains("spoofed.example"), "{seen}");
    assert!(seen.contains("X-Forwarded-For: 127.0.0.1\r\n"), "{seen}");
    assert!(!seen.contains("1.2.3.4"), "{seen}");
    assert!(!seen.contains("X-Hop"), "{seen}");
    assert!(seen.contains("X-Kept: yes\r\n"), "{seen}");
}

#[test]
fn forwarded_for_can_be_switched_off() {
    let origin = Origin::start();
    let proxy = Proxy {
        forwarded_for: false,
        ..Proxy::default()
    }
    .start();
    let mut client = connect(proxy);
    client
        .write_all(get(&origin, "/headers").as_bytes())
        .unwrap();
    let (_, body) = read_sized_response(&mut client);
    let seen = String::from_utf8(body).unwrap().to_ascii_lowercase();
    assert!(!seen.contains("x-forwarded-for"), "{seen}");
}

#[test]
fn large_bodies_arrive_intact_in_both_framings() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let expected = pattern(BIG);

    let mut client = connect(proxy);
    client.write_all(get(&origin, "/big").as_bytes()).unwrap();
    let (_, body) = read_sized_response(&mut client);
    assert!(body == expected, "Content-Length body differs");

    // Chunked: decode what the client receives and compare.
    client
        .write_all(get(&origin, "/chunked").as_bytes())
        .unwrap();
    let mut raw = Vec::new();
    while !raw.ends_with(b"\r\n0\r\n\r\n") {
        let mut chunk = [0u8; 64 * 1024];
        let n = client.read(&mut chunk).expect("reading a chunked body");
        assert!(n > 0, "connection closed mid-body");
        raw.extend_from_slice(&chunk[..n]);
    }
    let mut pos = find(&raw, b"\r\n\r\n").unwrap() + 4;
    let mut decoded = Vec::with_capacity(BIG);
    loop {
        let line_end = pos + find(&raw[pos..], b"\r\n").unwrap();
        let size =
            usize::from_str_radix(std::str::from_utf8(&raw[pos..line_end]).unwrap(), 16).unwrap();
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&raw[line_end + 2..line_end + 2 + size]);
        pos = line_end + 2 + size + 2;
    }
    assert!(decoded == expected, "chunked body differs");

    // The connection is still usable afterwards.
    client.write_all(get(&origin, "/ok").as_bytes()).unwrap();
    assert_eq!(read_sized_response(&mut client).1, b"OK");
}

#[test]
fn upload_reaches_the_origin_whole() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    let body = pattern(3 * 1024 * 1024);
    let head = format!(
        "POST http://{}/upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        origin.addr,
        body.len()
    );
    client.write_all(head.as_bytes()).unwrap();
    client.write_all(&body).unwrap();
    let (_, answer) = read_sized_response(&mut client);
    assert_eq!(answer, body.len().to_string().as_bytes());
}

#[test]
fn chunked_upload_reaches_the_origin_whole() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    client
        .write_all(
            format!(
                "POST http://{}/upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
                origin.addr
            )
            .as_bytes(),
        )
        .unwrap();
    let piece = pattern(50_000);
    for _ in 0..60 {
        client
            .write_all(format!("{:x}\r\n", piece.len()).as_bytes())
            .unwrap();
        client.write_all(&piece).unwrap();
        client.write_all(b"\r\n").unwrap();
    }
    client.write_all(b"0\r\n\r\n").unwrap();
    let (_, answer) = read_sized_response(&mut client);
    assert_eq!(answer, (60 * 50_000).to_string().as_bytes());

    // The connection carries on after a streamed upload.
    client.write_all(get(&origin, "/ok").as_bytes()).unwrap();
    assert_eq!(read_sized_response(&mut client).1, b"OK");
}

/// A client that asks for a go-ahead (`Expect: 100-continue`) and really
/// waits for it must get one, or the upload never starts.
#[test]
fn expect_100_continue_gets_a_go_ahead() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    for size in [1000usize, 500_000] {
        let mut client = connect(proxy);
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let body = pattern(size);
        client
            .write_all(
                format!(
                    "POST http://{}/upload HTTP/1.1\r\nHost: x\r\nContent-Length: {size}\r\n\
                     Expect: 100-continue\r\n\r\n",
                    origin.addr
                )
                .as_bytes(),
            )
            .unwrap();
        // Send nothing more until the go-ahead arrives.
        let mut go_ahead = [0u8; 25];
        client
            .read_exact(&mut go_ahead)
            .expect("no 100 Continue: the client would wait forever");
        assert_eq!(&go_ahead, b"HTTP/1.1 100 Continue\r\n\r\n", "size {size}");
        client.write_all(&body).unwrap();
        let (head, answer) = read_sized_response(&mut client);
        assert!(head.starts_with("HTTP/1.1 200 OK"), "size {size}: {head}");
        assert_eq!(answer, size.to_string().as_bytes());
    }
}

#[test]
fn body_without_a_length_is_relayed_until_close() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    client
        .write_all(get(&origin, "/stream").as_bytes())
        .unwrap();
    let all = read_to_close(&mut client);
    assert_eq!(all, b"HTTP/1.1 200 OK\r\n\r\none\ntwo\nthree\n");
}

#[test]
fn connect_tunnel_carries_bytes_both_ways() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    client
        .write_all(format!("CONNECT {} HTTP/1.1\r\nHost: x\r\n\r\n", origin.addr).as_bytes())
        .unwrap();
    let mut established = [0u8; 39];
    client.read_exact(&mut established).unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    // Inside the tunnel we talk to the origin directly, in origin-form.
    for _ in 0..3 {
        client
            .write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        assert_eq!(read_sized_response(&mut client).1, b"OK");
    }
}

#[test]
fn hostnames_are_resolved() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    let request = format!(
        "GET http://localhost:{}/ok HTTP/1.1\r\nHost: x\r\n\r\n",
        origin.addr.port()
    );
    client.write_all(request.as_bytes()).unwrap();
    let (head, body) = read_sized_response(&mut client);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert_eq!(body, b"OK");
}

#[test]
fn private_targets_are_refused_when_blocking_is_on() {
    let origin = Origin::start();
    let proxy = Proxy {
        block_private_ips: true,
        ..Proxy::default()
    }
    .start();
    for request in [
        get(&origin, "/ok"),
        format!("CONNECT {} HTTP/1.1\r\nHost: x\r\n\r\n", origin.addr),
        format!(
            "GET http://localhost:{}/ok HTTP/1.1\r\nHost: x\r\n\r\n",
            origin.addr.port()
        ),
        "GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        "GET http://[::ffff:127.0.0.1]/ HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
    ] {
        let mut client = connect(proxy);
        client.write_all(request.as_bytes()).unwrap();
        let answer = String::from_utf8_lossy(&read_to_close(&mut client)).into_owned();
        assert!(
            answer.starts_with("HTTP/1.1 403 Forbidden\r\n"),
            "{request} -> {answer}"
        );
    }
    assert_eq!(origin.connections(), 0, "nothing may reach the origin");
}

#[test]
fn https_url_in_a_plain_request_is_refused() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    let request = format!(
        "GET https://{}/ok HTTP/1.1\r\nHost: x\r\nCookie: secret=1\r\n\r\n",
        origin.addr
    );
    client.write_all(request.as_bytes()).unwrap();
    let answer = String::from_utf8_lossy(&read_to_close(&mut client)).into_owned();
    assert!(
        answer.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{answer}"
    );
    assert_eq!(
        origin.connections(),
        0,
        "the request must not be sent in clear text"
    );
}

#[test]
fn malformed_chunked_upload_is_refused() {
    let origin = Origin::start();
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    let request = format!(
        "POST http://{}/x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\
         5;a=b\nfoo\r\nhello\r\n0\r\n\r\n",
        origin.addr
    );
    client.write_all(request.as_bytes()).unwrap();
    let answer = String::from_utf8_lossy(&read_to_close(&mut client)).into_owned();
    assert!(
        answer.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{answer}"
    );
    assert_eq!(origin.connections(), 0);
}

#[test]
fn clients_outside_the_allowlist_get_no_response() {
    let origin = Origin::start();
    let proxy = Proxy {
        allowed_source_ips: vec!["192.0.2.55".to_string()],
        ..Proxy::default()
    }
    .start();
    let mut client = connect(proxy);
    // The proxy closes without a word; depending on timing the write may
    // already fail, which is equally a refusal.
    let _ = client.write_all(get(&origin, "/ok").as_bytes());
    let mut answer = Vec::new();
    let _ = client.read_to_end(&mut answer);
    assert!(answer.is_empty(), "{:?}", String::from_utf8_lossy(&answer));
    assert_eq!(origin.connections(), 0);
}

#[test]
fn request_cap_announces_the_close_and_fails_no_request() {
    let origin = Origin::start();
    let proxy = Proxy {
        max_requests_per_conn: 3,
        ..Proxy::default()
    }
    .start();
    let mut client = connect(proxy);
    for n in 1..=3 {
        client.write_all(get(&origin, "/ok").as_bytes()).unwrap();
        let (head, body) = read_sized_response(&mut client);
        assert!(head.starts_with("HTTP/1.1 200 OK"), "request {n}: {head}");
        assert_eq!(body, b"OK");
        assert_eq!(
            head.to_ascii_lowercase().contains("connection: close"),
            n == 3,
            "request {n}: {head}"
        );
    }
    assert!(
        read_to_close(&mut client).is_empty(),
        "closed after the third response"
    );
}

#[test]
fn silent_origin_gets_a_504() {
    let origin = Origin::start();
    let proxy = Proxy {
        upstream_read_timeout: Duration::from_millis(500),
        ..Proxy::default()
    }
    .start();
    let mut client = connect(proxy);
    let started = Instant::now();
    client
        .write_all(get(&origin, "/silent").as_bytes())
        .unwrap();
    let answer = String::from_utf8_lossy(&read_to_close(&mut client)).into_owned();
    assert!(
        answer.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"),
        "{answer}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn unreachable_origin_gets_a_502() {
    // A port nothing listens on.
    let dead = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    };
    let proxy = Proxy::default().start();
    let mut client = connect(proxy);
    client
        .write_all(format!("GET http://{dead}/ HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .unwrap();
    let answer = String::from_utf8_lossy(&read_to_close(&mut client)).into_owned();
    assert!(
        answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "{answer}"
    );
}
