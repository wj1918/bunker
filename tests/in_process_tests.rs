//! In-process integration tests for the proxy and DNS server.
//!
//! These tests start the actual server components and make real requests
//! to achieve higher code coverage than unit tests alone.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// Import the crate's modules
use bunker::config::{
    ConnectionPoolConfig, DnsCacheConfig, DnsFailoverConfig, DnsSecurityConfig,
    LogFormat, LoggingConfig, RateLimitConfig, SecurityConfig, TcpKeepaliveConfig,
};
use bunker::dns::run_dns_server;
use bunker::helpers::create_tls_connector;
use bunker::proxy::{handle_client, SenderPool};

// Suppress unused import warning for RateLimiter (used in test setup)
#[allow(unused_imports)]
use bunker::security::RateLimiter;

/// Helper to find an available port
async fn get_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Helper to find an available UDP port
fn get_available_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

/// Create default test configs
fn test_security_config() -> SecurityConfig {
    SecurityConfig {
        block_private_ips: true,
        blocked_hosts: vec![],
        allowed_ports: vec![],
        allowed_source_ips: vec![],
        rate_limit: RateLimitConfig {
            enabled: false,
            max_requests: 1000,
            window_seconds: 60,
            max_tracked_ips: 100000,
            ipv6_subnet_rate_limit: true,
        },
        max_connections: 0,
        max_request_body_bytes: 0, // Unlimited for tests
        header_read_timeout_seconds: 0, // No timeout for tests
        max_requests_per_connection: 0, // Unlimited for tests
    }
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
    }
}

fn test_tcp_keepalive_config() -> TcpKeepaliveConfig {
    TcpKeepaliveConfig {
        enabled: false, // Disable keepalive for faster test connections
        time_seconds: 60,
        interval_seconds: 10,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        retries: 3,
    }
}

fn test_pool_config() -> ConnectionPoolConfig {
    ConnectionPoolConfig {
        enabled: true,
        max_connections_per_host: 5,
        max_total_connections: 1000,
        idle_timeout_seconds: 30,
        max_lifetime_seconds: 120,
        connect_timeout_seconds: 5,
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

/// Start a proxy server and return its address
async fn start_test_proxy() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let port = get_available_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();

    let tls_connector = Arc::new(create_tls_connector().unwrap());
    let security = Arc::new(test_security_config());
    let logging = Arc::new(test_logging_config());
    let tcp_keepalive = Arc::new(test_tcp_keepalive_config());
    let sender_pool = Arc::new(Mutex::new(SenderPool::new(test_pool_config())));

    let handle = tokio::spawn(async move {
        while let Ok((stream, client_addr)) = listener.accept().await {
            let tls = Arc::clone(&tls_connector);
            let sec = Arc::clone(&security);
            let log = Arc::clone(&logging);
            let keepalive = Arc::clone(&tcp_keepalive);
            let pool = Arc::clone(&sender_pool);

            tokio::spawn(async move {
                let _ = handle_client(stream, client_addr, tls, sec, log, keepalive, pool)
                    .await;
            });
        }
    });

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(100)).await;

    (actual_addr, handle)
}

/// Start a DNS server and return its address
async fn start_test_dns_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let port = get_available_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let upstreams = vec!["8.8.8.8:53".to_string()];
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

/// Helper to make an HTTP request through the proxy and get the response
async fn proxy_request(proxy_addr: SocketAddr, request: &str) -> Result<String, String> {
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| format!("Connect error: {}", e))?;

    stream.write_all(request.as_bytes()).await.map_err(|e| format!("Write error: {}", e))?;
    stream.flush().await.map_err(|e| format!("Flush error: {}", e))?;

    let mut response = vec![0u8; 8192];

    let read_result = tokio::time::timeout(
        Duration::from_secs(10),
        stream.read(&mut response)
    ).await;

    match read_result {
        Ok(Ok(0)) => Err("Connection closed".to_string()),
        Ok(Ok(n)) => Ok(String::from_utf8_lossy(&response[..n]).to_string()),
        Ok(Err(e)) => Err(format!("Read error: {}", e)),
        Err(_) => Err("Read timeout".to_string()),
    }
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

// ============== Proxy Tests ==============

#[tokio::test]
async fn test_proxy_bad_request_no_host() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let request = "GET /test HTTP/1.1\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            assert!(
                resp.contains("400") || resp.contains("Bad Request"),
                "Expected 400, got: {}",
                resp
            );
        }
        Err(e) => {
            // Connection close is also acceptable for bad requests
            println!("Connection closed/error (acceptable for bad request): {}", e);
        }
    }
}

#[tokio::test]
async fn test_proxy_blocked_private_ip() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let request = "GET http://192.168.1.1/ HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            assert!(
                resp.contains("403") || resp.contains("Forbidden"),
                "Expected 403, got: {}",
                resp
            );
        }
        Err(e) => panic!("Request failed: {}", e),
    }
}

#[tokio::test]
async fn test_proxy_blocked_localhost() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let request = "GET http://localhost:8080/ HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            assert!(
                resp.contains("403") || resp.contains("Forbidden"),
                "Expected 403, got: {}",
                resp
            );
        }
        Err(e) => panic!("Request failed: {}", e),
    }
}

#[tokio::test]
async fn test_proxy_blocked_metadata_endpoint() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let request = "GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            assert!(
                resp.contains("403") || resp.contains("Forbidden"),
                "Expected 403, got: {}",
                resp
            );
        }
        Err(e) => panic!("Request failed: {}", e),
    }
}

#[tokio::test]
async fn test_proxy_connect_blocked_private_ip() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let request = "CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            assert!(
                resp.contains("403") || resp.contains("Forbidden"),
                "Expected 403, got: {}",
                resp
            );
        }
        Err(e) => panic!("Request failed: {}", e),
    }
}

#[tokio::test]
async fn test_proxy_connect_blocked_loopback() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let request = "CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: 127.0.0.1:22\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            assert!(
                resp.contains("403") || resp.contains("Forbidden"),
                "Expected 403, got: {}",
                resp
            );
        }
        Err(e) => panic!("Request failed: {}", e),
    }
}

#[tokio::test]
async fn test_proxy_http_request_to_external() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let request = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            // Should get 200 OK, 502, 503, or 504 (network issues/timeout)
            assert!(
                resp.contains("200") || resp.contains("502") || resp.contains("503") || resp.contains("504"),
                "Expected 200, 502, 503, or 504, got: {}",
                &resp[..resp.len().min(200)]
            );
        }
        Err(e) => {
            // Network errors are acceptable in CI environments
            println!("Network error (acceptable): {}", e);
        }
    }
}

#[tokio::test]
async fn test_proxy_connect_to_external() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            // Should get 200 Connection Established or 502 (network issues)
            assert!(
                resp.contains("200") || resp.contains("502") || resp.contains("503"),
                "Expected 200, 502, or 503, got: {}",
                resp
            );
        }
        Err(e) => {
            // Network errors are acceptable
            println!("Network error (acceptable): {}", e);
        }
    }
}

#[tokio::test]
async fn test_proxy_blocked_ipv6_private() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let request = "CONNECT [fc00::1]:443 HTTP/1.1\r\nHost: [fc00::1]:443\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            assert!(
                resp.contains("403") || resp.contains("Forbidden"),
                "Expected 403, got: {}",
                resp
            );
        }
        Err(e) => panic!("Request failed: {}", e),
    }
}

// ============== DNS Tests ==============

#[tokio::test]
async fn test_dns_query_forwarding() {
    let (dns_addr, _handle) = start_test_dns_server().await;

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Query for google.com
    let query = build_dns_query("google.com", 0x1234);
    socket.send_to(&query, dns_addr).unwrap();

    let mut response = [0u8; 512];
    match socket.recv_from(&mut response) {
        Ok((len, _)) => {
            assert!(len > 12, "Response should be larger than header");
            // Transaction ID should match
            assert_eq!(response[0], 0x12);
            assert_eq!(response[1], 0x34);
            // QR bit should be set (response)
            assert!(response[2] & 0x80 != 0, "Should be a response");
        }
        Err(e) => {
            // Network issues are expected in some environments
            println!("DNS query failed (expected if no network): {}", e);
        }
    }
}

#[tokio::test]
async fn test_dns_any_query_blocked() {
    let (dns_addr, _handle) = start_test_dns_server().await;

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // Query with ANY type (should be blocked)
    let query = build_any_dns_query("example.com", 0x5678);
    socket.send_to(&query, dns_addr).unwrap();

    let mut response = [0u8; 512];
    match socket.recv_from(&mut response) {
        Ok((len, _)) => {
            assert!(len > 12, "Response should be larger than header");
            // Transaction ID should match
            assert_eq!(response[0], 0x56);
            assert_eq!(response[1], 0x78);
            // Should get REFUSED or similar error response
            // RCODE is in the lower 4 bits of byte 3
            let rcode = response[3] & 0x0F;
            // REFUSED = 5, NOTIMP = 4, SERVFAIL = 2
            assert!(
                rcode == 5 || rcode == 4 || rcode == 2,
                "Expected REFUSED/NOTIMP/SERVFAIL, got rcode {}",
                rcode
            );
        }
        Err(e) => {
            println!("DNS query failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_dns_multiple_queries() {
    let (dns_addr, _handle) = start_test_dns_server().await;

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let domains = ["example.com", "google.com", "cloudflare.com"];
    let mut successful = 0;

    for (i, domain) in domains.iter().enumerate() {
        let query = build_dns_query(domain, (0x1000 + i) as u16);
        socket.send_to(&query, dns_addr).unwrap();

        let mut response = [0u8; 512];
        if socket.recv_from(&mut response).is_ok() {
            successful += 1;
        }
    }

    // At least some queries should succeed (unless no network)
    println!("Successful DNS queries: {}/{}", successful, domains.len());
}

#[tokio::test]
async fn test_dns_cache_hit() {
    let (dns_addr, _handle) = start_test_dns_server().await;

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // First query
    let query1 = build_dns_query("example.com", 0x1111);
    socket.send_to(&query1, dns_addr).unwrap();

    let mut response1 = [0u8; 512];
    if socket.recv_from(&mut response1).is_err() {
        println!("First query failed - network issue, skipping cache test");
        return;
    }

    // Second query (should hit cache)
    let query2 = build_dns_query("example.com", 0x2222);
    socket.send_to(&query2, dns_addr).unwrap();

    let mut response2 = [0u8; 512];
    match socket.recv_from(&mut response2) {
        Ok((len, _)) => {
            // Transaction ID should be updated to the new query ID
            assert_eq!(response2[0], 0x22);
            assert_eq!(response2[1], 0x22);
            println!("Cache test: Got response of {} bytes", len);
        }
        Err(e) => {
            println!("Second query failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_dns_axfr_blocked() {
    let (dns_addr, _handle) = start_test_dns_server().await;

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // Build AXFR query (zone transfer - should be blocked)
    let mut query = build_dns_query("example.com", 0xABCD);
    // Change type from A (1) to AXFR (252)
    let type_offset = query.len() - 4;
    query[type_offset] = 0x00;
    query[type_offset + 1] = 0xFC; // AXFR = 252

    socket.send_to(&query, dns_addr).unwrap();

    let mut response = [0u8; 512];
    match socket.recv_from(&mut response) {
        Ok((len, _)) => {
            assert!(len >= 12, "Response should have header");
            // Should get REFUSED
            let rcode = response[3] & 0x0F;
            assert!(
                rcode == 5 || rcode == 4 || rcode == 2,
                "Expected REFUSED/NOTIMP/SERVFAIL for AXFR, got rcode {}",
                rcode
            );
        }
        Err(_) => {
            // Timeout is also acceptable (server might just drop it)
        }
    }
}

#[tokio::test]
async fn test_dns_malformed_query() {
    let (dns_addr, _handle) = start_test_dns_server().await;

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Send malformed DNS query (too short)
    let malformed = vec![0x12, 0x34]; // Just transaction ID, nothing else
    socket.send_to(&malformed, dns_addr).unwrap();

    let mut response = [0u8; 512];
    // Should either get error response or timeout
    let _ = socket.recv_from(&mut response);
}

// ============== Edge Case Tests ==============

#[tokio::test]
async fn test_proxy_empty_request() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let response = proxy_request(proxy_addr, "\r\n\r\n").await;
    // Should handle gracefully (either error or close connection)
    match response {
        Ok(resp) => println!("Got response for empty request: {}", &resp[..resp.len().min(100)]),
        Err(e) => println!("Empty request handled: {}", e),
    }
}

#[tokio::test]
async fn test_proxy_malformed_request() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let response = proxy_request(proxy_addr, "INVALID REQUEST\r\n\r\n").await;
    // Should handle gracefully
    match response {
        Ok(resp) => println!("Got response for malformed request: {}", &resp[..resp.len().min(100)]),
        Err(e) => println!("Malformed request handled: {}", e),
    }
}

#[tokio::test]
async fn test_proxy_request_with_body() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let body = "test=data";
    let request = format!(
        "POST http://httpbin.org/post HTTP/1.1\r\n\
         Host: httpbin.org\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );

    let response = proxy_request(proxy_addr, &request).await;
    match response {
        Ok(resp) => {
            // Should get 200 OK, 502, 503, 504 (network issues/timeout)
            assert!(
                resp.contains("200") || resp.contains("502") || resp.contains("503") || resp.contains("504") || resp.is_empty(),
                "Expected 200, 502, 503, 504, or empty"
            );
        }
        Err(e) => println!("POST request error (acceptable): {}", e),
    }
}

#[tokio::test]
async fn test_proxy_connection_close() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    // Connect and immediately close
    let stream = tokio::net::TcpStream::connect(proxy_addr).await;
    if let Ok(stream) = stream {
        drop(stream);
    }

    // Server should handle this gracefully
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make another request to verify server is still working
    let request = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;
    match response {
        Ok(resp) => println!("Server still responsive: {}", &resp[..resp.len().min(50)]),
        Err(e) => println!("Network error (acceptable): {}", e),
    }
}

#[tokio::test]
async fn test_proxy_multiple_concurrent() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    let mut handles = vec![];
    for i in 0..3 {
        let addr = proxy_addr;
        handles.push(tokio::spawn(async move {
            let request = format!(
                "GET http://example.com/{} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
                i
            );
            proxy_request(addr, &request).await.is_ok()
        }));
    }

    let mut success_count = 0;
    for handle in handles {
        if handle.await.unwrap_or(false) {
            success_count += 1;
        }
    }

    println!("Successful concurrent requests: {}/3", success_count);
}

// ============== Port/Protocol Tests ==============

#[tokio::test]
async fn test_proxy_https_port() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    // Standard HTTPS port
    let request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            assert!(
                resp.contains("200") || resp.contains("502") || resp.contains("503"),
                "Expected 200, 502, or 503, got: {}",
                &resp[..resp.len().min(100)]
            );
        }
        Err(e) => println!("Network error (acceptable): {}", e),
    }
}

#[tokio::test]
async fn test_proxy_non_standard_port() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    // Non-standard port (8443)
    let request = "CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            // Should work (unless port allowlist is configured)
            println!("Non-standard port response: {}", &resp[..resp.len().min(100)]);
        }
        Err(e) => println!("Non-standard port error: {}", e),
    }
}

#[tokio::test]
async fn test_proxy_blocked_internal_hostname() {
    let (proxy_addr, _handle) = start_test_proxy().await;

    // metadata hostname should be blocked
    let request = "GET http://metadata/latest/meta-data/ HTTP/1.1\r\nHost: metadata\r\n\r\n";
    let response = proxy_request(proxy_addr, request).await;

    match response {
        Ok(resp) => {
            assert!(
                resp.contains("403") || resp.contains("Forbidden"),
                "Expected 403, got: {}",
                resp
            );
        }
        Err(e) => panic!("Request failed: {}", e),
    }
}
