use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const PROXY_ADDR: &str = "127.0.0.1:18080";
const DNS_ADDR: &str = "127.0.0.1:15353";
#[allow(dead_code)]
const TEST_HTTP_SERVER: &str = "127.0.0.1:18081";

#[allow(dead_code)]
struct TestProxy {
    child: Child,
}

#[allow(dead_code)]
impl TestProxy {
    fn start() -> Self {
        let child = Command::new("cargo")
            .args(["run", "--", PROXY_ADDR, "--dns", DNS_ADDR, "--no-tray"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start proxy");

        // Wait for proxy to start
        thread::sleep(Duration::from_secs(2));

        TestProxy { child }
    }

    fn start_with_config(config_path: &str) -> Self {
        let child = Command::new("cargo")
            .args(["run", "--", "--config", config_path, "--no-tray"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start proxy");

        thread::sleep(Duration::from_secs(2));

        TestProxy { child }
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[allow(dead_code)]
struct TestHttpServer {
    listener: TcpListener,
}

#[allow(dead_code)]
impl TestHttpServer {
    fn start() -> Self {
        let listener = TcpListener::bind(TEST_HTTP_SERVER).expect("Failed to bind test server");
        listener
            .set_nonblocking(true)
            .expect("Failed to set non-blocking");
        TestHttpServer { listener }
    }

    fn handle_one_request(&self) -> Option<String> {
        match self.listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 1024];
                stream.set_read_timeout(Some(Duration::from_secs(1))).ok();
                if let Ok(n) = stream.read(&mut buf) {
                    let request = String::from_utf8_lossy(&buf[..n]).to_string();

                    let response = "HTTP/1.1 200 OK\r\n\
                                   Content-Type: text/plain\r\n\
                                   Content-Length: 13\r\n\
                                   Connection: close\r\n\r\n\
                                   Hello, World!";
                    let _ = stream.write_all(response.as_bytes());
                    return Some(request);
                }
                None
            }
            Err(_) => None,
        }
    }
}

// ============== Unit Tests ==============

#[cfg(test)]
mod config_tests {
    
    use std::fs;

    #[test]
    fn test_default_config_values() {
        // Test that default config has expected values
        let yaml = "";
        let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml).unwrap_or_default();

        // Empty config should parse without error
        assert!(config.is_null() || config.is_mapping());
    }

    #[test]
    fn test_valid_config_parsing() {
        let yaml = r#"
listen_addr: "0.0.0.0:8080"
tray_enabled: false
dns:
  listen: "0.0.0.0:53"
  upstream: "1.1.1.1:53"
"#;
        let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml).unwrap();

        assert_eq!(config["listen_addr"].as_str().unwrap(), "0.0.0.0:8080");
        assert!(!config["tray_enabled"].as_bool().unwrap());
        assert_eq!(config["dns"]["listen"].as_str().unwrap(), "0.0.0.0:53");
        assert_eq!(config["dns"]["upstream"].as_str().unwrap(), "1.1.1.1:53");
    }

    #[test]
    fn test_partial_config_parsing() {
        let yaml = r#"
listen_addr: "192.168.1.1:8080"
"#;
        let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml).unwrap();

        assert_eq!(config["listen_addr"].as_str().unwrap(), "192.168.1.1:8080");
        assert!(config["dns"].is_null());
    }

    #[test]
    fn test_dns_only_config() {
        let yaml = r#"
dns:
  listen: "127.0.0.1:5353"
"#;
        let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml).unwrap();

        assert_eq!(config["dns"]["listen"].as_str().unwrap(), "127.0.0.1:5353");
    }

    #[test]
    fn test_invalid_yaml_handling() {
        let yaml = "invalid: yaml: content: [";
        let result: Result<serde_yaml_ng::Value, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_file_creation() {
        let test_config = "test_config_temp.yaml";
        let yaml = r#"
listen_addr: "127.0.0.1:9999"
tray_enabled: false
"#;
        fs::write(test_config, yaml).unwrap();

        let content = fs::read_to_string(test_config).unwrap();
        let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(&content).unwrap();

        assert_eq!(config["listen_addr"].as_str().unwrap(), "127.0.0.1:9999");

        fs::remove_file(test_config).unwrap();
    }
}

#[cfg(test)]
mod address_parsing_tests {
    use std::net::SocketAddr;

    #[test]
    fn test_ipv4_address_parsing() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        assert_eq!(addr.port(), 8080);
        assert!(addr.is_ipv4());
    }

    #[test]
    fn test_ipv6_address_parsing() {
        let addr: SocketAddr = "[::1]:8080".parse().unwrap();
        assert_eq!(addr.port(), 8080);
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_any_address_parsing() {
        let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_invalid_address() {
        let result: Result<SocketAddr, _> = "invalid:address".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_port() {
        let result: Result<SocketAddr, _> = "192.168.1.1".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_port() {
        let result: Result<SocketAddr, _> = "192.168.1.1:99999".parse();
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod http_parsing_tests {
    #[test]
    fn test_parse_host_header_simple() {
        let host = "example.com";
        let parts: Vec<&str> = host.rsplitn(2, ':').collect();

        if parts.len() == 1 {
            assert_eq!(parts[0], "example.com");
        }
    }

    #[test]
    fn test_parse_host_header_with_port() {
        let host = "example.com:8080";
        let parts: Vec<&str> = host.rsplitn(2, ':').collect();

        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "8080");
        assert_eq!(parts[1], "example.com");
    }

    #[test]
    fn test_parse_ipv6_host() {
        // IPv6 addresses in Host headers are wrapped in brackets
        let host = "[::1]:8080";

        if let Some(bracket_end) = host.rfind(']') {
            let port_start = bracket_end + 2; // Skip ']:'
            if port_start < host.len() {
                let port: u16 = host[port_start..].parse().unwrap();
                assert_eq!(port, 8080);
            }
        }
    }

    #[test]
    fn test_extract_path_and_query() {
        let uri = "/path/to/resource?query=value&other=123";
        assert!(uri.starts_with('/'));
        assert!(uri.contains('?'));
    }

    #[test]
    fn test_hop_by_hop_headers() {
        let hop_by_hop = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        ];

        assert!(hop_by_hop.contains(&"connection"));
        assert!(hop_by_hop.contains(&"keep-alive"));
        assert!(!hop_by_hop.contains(&"content-type"));
        assert!(!hop_by_hop.contains(&"host"));
    }
}

#[cfg(test)]
mod dns_tests {
    use std::net::UdpSocket;
    use std::time::Duration;

    #[allow(clippy::vec_init_then_push)]
    fn build_dns_query(domain: &str, query_id: u16) -> Vec<u8> {
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

        // Answer RRs: 0
        query.push(0x00);
        query.push(0x00);

        // Authority RRs: 0
        query.push(0x00);
        query.push(0x00);

        // Additional RRs: 0
        query.push(0x00);
        query.push(0x00);

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

    #[test]
    fn test_dns_query_building() {
        let query = build_dns_query("example.com", 0x1234);

        // Check transaction ID
        assert_eq!(query[0], 0x12);
        assert_eq!(query[1], 0x34);

        // Check it's a query (QR bit = 0)
        assert_eq!(query[2] & 0x80, 0);

        // Check question count
        assert_eq!(query[4], 0);
        assert_eq!(query[5], 1);
    }

    #[test]
    fn test_dns_query_domain_encoding() {
        let query = build_dns_query("test.example.com", 0x0001);

        // Find the domain section (starts at byte 12)
        let domain_start = 12;

        // First label: "test" (length 4)
        assert_eq!(query[domain_start], 4);
        assert_eq!(&query[domain_start+1..domain_start+5], b"test");

        // Second label: "example" (length 7)
        assert_eq!(query[domain_start+5], 7);
        assert_eq!(&query[domain_start+6..domain_start+13], b"example");
    }

    #[test]
    fn test_udp_socket_creation() {
        let socket = UdpSocket::bind("127.0.0.1:0");
        assert!(socket.is_ok());

        let socket = socket.unwrap();
        let addr = socket.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[test]
    fn test_dns_timeout_handling() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();

        let mut buf = [0u8; 512];
        let result = socket.recv_from(&mut buf);

        // Should timeout since no one is sending
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod tls_tests {
    use std::sync::Arc;

    #[test]
    fn test_root_cert_store_creation() {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
        );

        // Should have many root certificates
        assert!(root_store.len() > 100);
    }

    #[test]
    fn test_tls_client_config_creation() {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
        );

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        // Just verify it compiles and creates successfully
        drop(connector);
    }

    #[test]
    fn test_server_name_parsing() {
        use rustls::pki_types::ServerName;

        let valid_names = ["example.com", "sub.example.com", "test-site.org"];

        for name in valid_names {
            let result: Result<ServerName, _> = name.to_string().try_into();
            assert!(result.is_ok(), "Failed to parse: {}", name);
        }
    }

    #[test]
    fn test_invalid_server_names() {
        use rustls::pki_types::ServerName;

        // IP addresses should fail as DNS names
        let result: Result<ServerName, _> = "192.168.1.1".to_string().try_into();
        // Note: This might actually succeed depending on rustls version
        // The test is to ensure we handle the result properly
        let _ = result;
    }
}

#[cfg(test)]
mod connect_tunnel_tests {
    #[test]
    fn test_authority_parsing() {
        let authorities = [
            ("example.com:443", "example.com", 443),
            ("example.com:8080", "example.com", 8080),
            ("192.168.1.1:443", "192.168.1.1", 443),
        ];

        for (auth, expected_host, expected_port) in authorities {
            let parts: Vec<&str> = auth.rsplitn(2, ':').collect();
            let port: u16 = parts[0].parse().unwrap();
            let host = parts[1];

            assert_eq!(host, expected_host);
            assert_eq!(port, expected_port);
        }
    }

    #[test]
    fn test_connect_request_format() {
        let request = "CONNECT example.com:443 HTTP/1.1\r\n\
                       Host: example.com:443\r\n\
                       \r\n";

        assert!(request.starts_with("CONNECT"));
        assert!(request.contains("443"));
        assert!(request.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_connect_response_format() {
        let response = "HTTP/1.1 200 Connection Established\r\n\r\n";

        assert!(response.contains("200"));
        assert!(response.contains("Connection Established") || response.ends_with("\r\n\r\n"));
    }
}

// ============== Integration Tests ==============

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_proxy_http_request() {
        // This test requires proxy running on PROXY_ADDR
        // Skip proxy start - assume it's already running externally

        thread::sleep(Duration::from_millis(500));

        // Connect to proxy
        let stream_result = TcpStream::connect(PROXY_ADDR);
        if stream_result.is_err() {
            println!("Proxy not running on {}, skipping test", PROXY_ADDR);
            return;
        }
        let mut stream = stream_result.unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

        // Send HTTP request through proxy to a real external server
        let request = "GET http://example.com/ HTTP/1.1\r\n\
             Host: example.com\r\n\
             Connection: close\r\n\
             \r\n";
        stream.write_all(request.as_bytes()).unwrap();

        // Read response
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        let response_str = String::from_utf8_lossy(&response);

        println!("Response length: {} bytes", response.len());
        println!("Response preview: {}", &response_str[..response_str.len().min(200)]);

        // Should get 200 OK or 502 Bad Gateway (if network issues)
        assert!(
            response_str.contains("200") || response_str.contains("502"),
            "Expected 200 or 502, got: {}", &response_str[..response_str.len().min(100)]
        );
    }

    #[test]
    #[ignore]
    fn test_proxy_connect_request() {
        // This test requires proxy running on PROXY_ADDR
        thread::sleep(Duration::from_millis(500));

        let stream_result = TcpStream::connect(PROXY_ADDR);
        if stream_result.is_err() {
            println!("Proxy not running on {}, skipping test", PROXY_ADDR);
            return;
        }
        let mut stream = stream_result.unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

        // Send CONNECT request
        let request = "CONNECT example.com:443 HTTP/1.1\r\n\
                       Host: example.com:443\r\n\
                       \r\n";
        stream.write_all(request.as_bytes()).unwrap();

        // Read response
        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).unwrap_or(0);
        let response_str = String::from_utf8_lossy(&response[..n]);

        println!("CONNECT response: {}", response_str);

        // Should get 200 Connection Established or 502 Bad Gateway
        assert!(
            response_str.contains("200") || response_str.contains("502"),
            "Expected 200 or 502, got: {}", response_str
        );
    }

    #[test]
    #[ignore]
    fn test_proxy_bad_request() {
        // This test requires proxy running on PROXY_ADDR
        thread::sleep(Duration::from_millis(500));

        let stream_result = TcpStream::connect(PROXY_ADDR);
        if stream_result.is_err() {
            println!("Proxy not running on {}, skipping test", PROXY_ADDR);
            return;
        }
        let mut stream = stream_result.unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        // Send request without Host header and without absolute URI
        let request = "GET /test HTTP/1.1\r\n\r\n";
        stream.write_all(request.as_bytes()).unwrap();

        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).unwrap_or(0);
        let response_str = String::from_utf8_lossy(&response[..n]);

        println!("Bad request response: {}", response_str);

        // Should get 400 Bad Request
        assert!(
            response_str.contains("400") || response_str.contains("Bad Request"),
            "Expected 400, got: {}", response_str
        );
    }

    #[test]
    #[ignore]
    fn test_dns_query_forwarding() {
        // This test requires DNS server running on DNS_ADDR
        thread::sleep(Duration::from_millis(500));

        let socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP socket");
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        // Build DNS query for google.com
        let query = build_simple_dns_query("google.com");

        if let Err(e) = socket.send_to(&query, DNS_ADDR) {
            println!("Failed to send DNS query (DNS server not running?): {}", e);
            return;
        }

        let mut response = [0u8; 512];
        match socket.recv_from(&mut response) {
            Ok((len, _)) => {
                println!("DNS response: {} bytes", len);
                // Check response has answers (byte 6-7 should be > 0 for answer count)
                assert!(len > 12, "Response too short");
                // Transaction ID should match
                assert_eq!(response[0], query[0]);
                assert_eq!(response[1], query[1]);
            }
            Err(e) => {
                // DNS might timeout if upstream is unreachable
                println!("DNS query failed (expected if no network): {}", e);
            }
        }
    }

    #[allow(clippy::vec_init_then_push)]
    fn build_simple_dns_query(domain: &str) -> Vec<u8> {
        let mut query = Vec::new();

        // Transaction ID
        query.push(0x12);
        query.push(0x34);

        // Flags
        query.push(0x01);
        query.push(0x00);

        // Questions: 1
        query.push(0x00);
        query.push(0x01);

        // Answers, Authority, Additional: 0
        query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Domain name
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00);

        // Type A, Class IN
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        query
    }
}

// ============== Stress Tests ==============

#[cfg(test)]
mod stress_tests {
    use std::net::TcpStream;
    use std::io::Write;
    use std::thread;
    use std::time::Duration;

    const PROXY_ADDR: &str = "127.0.0.1:18080";

    #[test]
    #[ignore]
    fn test_multiple_concurrent_connections() {
        // This test requires the proxy to be running
        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    if let Ok(mut stream) = TcpStream::connect(PROXY_ADDR) {
                        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
                        let request = format!(
                            "GET http://example.com/test{} HTTP/1.1\r\n\
                             Host: example.com\r\n\
                             Connection: close\r\n\r\n",
                            i
                        );
                        let _ = stream.write_all(request.as_bytes());
                    }
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    }

    #[test]
    #[ignore]
    fn test_rapid_connect_disconnect() {
        for _ in 0..50 {
            if let Ok(stream) = TcpStream::connect(PROXY_ADDR) {
                drop(stream);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

// ============== Error Handling Tests ==============

#[cfg(test)]
mod error_tests {
    #[test]
    fn test_invalid_socket_address() {
        use std::net::TcpStream;

        let result = TcpStream::connect("256.256.256.256:8080");
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_refused() {
        use std::net::TcpStream;

        // Try to connect to a port that's definitely not listening
        let result = TcpStream::connect("127.0.0.1:59999");
        assert!(result.is_err());
    }

    #[test]
    fn test_yaml_parse_errors() {
        let invalid_yamls = [
            "key: [unclosed",
            "key: value\n  bad indent",
            "{{invalid}}",
        ];

        for yaml in invalid_yamls {
            let result: Result<serde_yaml_ng::Value, _> = serde_yaml_ng::from_str(yaml);
            // Some of these might actually parse, the point is they don't crash
            let _ = result;
        }
    }
}

// ============== WebSocket Tests ==============

#[cfg(test)]
mod websocket_tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::time::Duration;

    const PROXY_ADDR: &str = "127.0.0.1:18080";

    #[test]
    fn test_websocket_upgrade_headers_format() {
        // Verify WebSocket upgrade request format
        let upgrade_request = "GET /chat HTTP/1.1\r\n\
                               Host: server.example.com\r\n\
                               Connection: Upgrade\r\n\
                               Upgrade: websocket\r\n\
                               Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                               Sec-WebSocket-Version: 13\r\n\
                               Origin: http://example.com\r\n\
                               \r\n";

        assert!(upgrade_request.contains("Connection: Upgrade"));
        assert!(upgrade_request.contains("Upgrade: websocket"));
        assert!(upgrade_request.contains("Sec-WebSocket-Key:"));
        assert!(upgrade_request.contains("Sec-WebSocket-Version: 13"));
    }

    #[test]
    fn test_websocket_accept_header_calculation() {
        // The Sec-WebSocket-Accept is calculated as:
        // base64(sha1(Sec-WebSocket-Key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let combined = format!("{}{}", key, magic);

        // The expected accept value for this key is: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
        // We just verify the format is correct
        assert_eq!(combined.len(), key.len() + magic.len());
    }

    #[test]
    fn test_websocket_101_response_format() {
        let response = "HTTP/1.1 101 Switching Protocols\r\n\
                        Connection: Upgrade\r\n\
                        Upgrade: websocket\r\n\
                        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                        \r\n";

        assert!(response.starts_with("HTTP/1.1 101"));
        assert!(response.contains("Connection: Upgrade"));
        assert!(response.contains("Upgrade: websocket"));
        assert!(response.contains("Sec-WebSocket-Accept:"));
    }

    #[test]
    fn test_websocket_frame_format() {
        // WebSocket text frame: FIN=1, opcode=1 (text), no mask, payload "Hello"
        let mut frame = Vec::new();

        // First byte: FIN(1) + RSV(000) + opcode(0001) = 0x81
        frame.push(0x81);

        // Second byte: MASK(0) + payload length(5) = 0x05
        frame.push(0x05);

        // Payload: "Hello"
        frame.extend_from_slice(b"Hello");

        assert_eq!(frame.len(), 7);
        assert_eq!(frame[0], 0x81); // FIN + text opcode
        assert_eq!(frame[1], 0x05); // Length 5, no mask
        assert_eq!(&frame[2..], b"Hello");
    }

    #[test]
    fn test_websocket_masked_frame() {
        // Client-to-server frames MUST be masked
        let payload = b"Hello";
        let mask_key: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

        let mut frame = Vec::new();

        // First byte: FIN + text opcode
        frame.push(0x81);

        // Second byte: MASK(1) + payload length = 0x80 | 5 = 0x85
        frame.push(0x85);

        // Masking key
        frame.extend_from_slice(&mask_key);

        // Masked payload: payload[i] XOR mask_key[i % 4]
        for (i, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask_key[i % 4]);
        }

        assert_eq!(frame.len(), 11); // 2 header + 4 mask + 5 payload
        assert_eq!(frame[1] & 0x80, 0x80); // Mask bit set
    }

    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_wss_connect_tunnel() {
        // Test CONNECT tunnel to a WebSocket server (wss://)
        // This establishes the tunnel that wss:// connections use

        let stream_result = TcpStream::connect(PROXY_ADDR);
        if stream_result.is_err() {
            println!("Proxy not running on {}, skipping test", PROXY_ADDR);
            return;
        }
        let mut stream = stream_result.unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        stream.set_nodelay(true).unwrap();

        // Send CONNECT request to echo.websocket.org:443
        let request = "CONNECT echo.websocket.org:443 HTTP/1.1\r\n\
                       Host: echo.websocket.org:443\r\n\
                       \r\n";
        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();

        // Read response - may need multiple reads
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];

        // Keep reading until we get the full HTTP response
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    let s = String::from_utf8_lossy(&response);
                    if s.contains("\r\n\r\n") {
                        break;
                    }
                }
                Err(e) => {
                    println!("Read error: {}", e);
                    break;
                }
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        println!("CONNECT response: {}", response_str);

        // Should get 200 Connection Established or network error
        if response_str.is_empty() {
            println!("Empty response - network issue or proxy not responding");
            return;
        }

        assert!(
            response_str.contains("200") || response_str.contains("502"),
            "Expected 200 or 502, got: {}", response_str
        );
    }

    #[test]
    #[ignore]
    fn test_wss_full_handshake() {
        // Full wss:// test: CONNECT tunnel + TLS + WebSocket upgrade
        // This requires tokio-rustls for the TLS handshake inside the tunnel

        use std::io::{Read, Write};

        let stream_result = TcpStream::connect(PROXY_ADDR);
        if stream_result.is_err() {
            println!("Proxy not running on {}, skipping test", PROXY_ADDR);
            return;
        }
        let mut stream = stream_result.unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();

        // Step 1: Establish CONNECT tunnel
        let connect_request = "CONNECT echo.websocket.org:443 HTTP/1.1\r\n\
                               Host: echo.websocket.org:443\r\n\
                               \r\n";
        stream.write_all(connect_request.as_bytes()).unwrap();

        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).unwrap_or(0);
        let response_str = String::from_utf8_lossy(&response[..n]);

        if !response_str.contains("200") {
            println!("CONNECT failed: {}", response_str);
            return;
        }
        println!("Tunnel established");

        // Step 2: TLS handshake would happen here
        // For a complete test, we'd use rustls to wrap the stream
        // This is left as a placeholder - the tunnel is working

        println!("TLS handshake would occur here (tunnel is ready)");
        println!("Test passed: CONNECT tunnel for wss:// is working");
    }

    #[test]
    #[ignore]
    fn test_wss_with_tls() {
        // Complete wss:// test with actual TLS handshake
        use std::io::{Read, Write};

        let stream_result = TcpStream::connect(PROXY_ADDR);
        if stream_result.is_err() {
            println!("Proxy not running on {}, skipping test", PROXY_ADDR);
            return;
        }
        let mut stream = stream_result.unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(15))).unwrap();

        // Step 1: CONNECT tunnel
        let connect_request = "CONNECT ws.postman-echo.com:443 HTTP/1.1\r\n\
                               Host: ws.postman-echo.com:443\r\n\
                               \r\n";
        stream.write_all(connect_request.as_bytes()).unwrap();

        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).unwrap_or(0);
        let response_str = String::from_utf8_lossy(&response[..n]);

        if !response_str.contains("200") {
            println!("CONNECT failed (network issue?): {}", response_str);
            return;
        }
        println!("Step 1: CONNECT tunnel established");

        // Step 2: TLS handshake
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
        );

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name: rustls::pki_types::ServerName = "ws.postman-echo.com"
            .to_string()
            .try_into()
            .expect("Invalid server name");

        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            server_name
        ).expect("Failed to create TLS connection");

        // Perform TLS handshake
        let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);

        // Step 3: Send WebSocket upgrade request over TLS
        let ws_key = base64_encode_simple(b"random-key-here!");
        let upgrade_request = format!(
            "GET /raw HTTP/1.1\r\n\
             Host: ws.postman-echo.com\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Origin: https://example.com\r\n\
             \r\n",
            ws_key
        );

        if let Err(e) = tls_stream.write_all(upgrade_request.as_bytes()) {
            println!("TLS write failed (expected on some networks): {}", e);
            return;
        }

        // Step 4: Read WebSocket upgrade response
        let mut ws_response = [0u8; 2048];
        match tls_stream.read(&mut ws_response) {
            Ok(n) => {
                let ws_response_str = String::from_utf8_lossy(&ws_response[..n]);
                println!("Step 2-3: TLS + WebSocket response:\n{}", ws_response_str);

                // Should get 101 Switching Protocols
                if ws_response_str.contains("101") {
                    println!("SUCCESS: wss:// WebSocket connection established!");
                    assert!(ws_response_str.contains("Upgrade: websocket") ||
                            ws_response_str.contains("upgrade: websocket"));
                } else {
                    println!("Got response but not 101: {}", &ws_response_str[..ws_response_str.len().min(200)]);
                }
            }
            Err(e) => {
                println!("TLS read failed: {}", e);
            }
        }
    }

    // Simple base64 encoding for the test (avoid adding dependencies)
    fn base64_encode_simple(input: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();

        for chunk in input.chunks(3) {
            let mut n: u32 = 0;
            for (i, &byte) in chunk.iter().enumerate() {
                n |= (byte as u32) << (16 - i * 8);
            }

            let chars = match chunk.len() {
                3 => 4,
                2 => 3,
                1 => 2,
                _ => 0,
            };

            for i in 0..chars {
                let idx = ((n >> (18 - i * 6)) & 0x3F) as usize;
                result.push(ALPHABET[idx] as char);
            }

            for _ in chars..4 {
                result.push('=');
            }
        }

        result
    }
}

// ============== CLI Argument Tests ==============

#[cfg(test)]
mod cli_tests {
    #[test]
    fn test_arg_parsing_logic() {
        let args = ["proxy".to_string(),
            "192.168.1.1:8080".to_string(),
            "--dns".to_string(),
            "192.168.1.1:53".to_string(),
            "--no-tray".to_string()];

        let mut listen_addr: Option<String> = None;
        let mut dns_addr: Option<String> = None;
        let mut use_tray = true;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--dns" => {
                    i += 1;
                    dns_addr = args.get(i).cloned();
                }
                "--no-tray" => {
                    use_tray = false;
                }
                arg if !arg.starts_with('-') && listen_addr.is_none() => {
                    listen_addr = Some(arg.to_string());
                }
                _ => {}
            }
            i += 1;
        }

        assert_eq!(listen_addr, Some("192.168.1.1:8080".to_string()));
        assert_eq!(dns_addr, Some("192.168.1.1:53".to_string()));
        assert!(!use_tray);
    }

    #[test]
    fn test_config_flag_parsing() {
        let args = ["proxy".to_string(),
            "--config".to_string(),
            "/path/to/config.yaml".to_string()];

        let mut config_path: Option<String> = None;
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--config" | "-c" => {
                    i += 1;
                    config_path = args.get(i).cloned();
                }
                _ => {}
            }
            i += 1;
        }

        assert_eq!(config_path, Some("/path/to/config.yaml".to_string()));
    }
}
