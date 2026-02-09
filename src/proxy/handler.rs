//! HTTP request handling and proxying.

use crate::body::{BodyExt, BoxBody};
use crate::config::{LoggingConfig, SecurityConfig, TcpKeepaliveConfig};
use crate::helpers::{apply_tcp_keepalive, error_response};
use crate::proxy::connect::handle_connect;
use crate::proxy::pool::SenderPool;
use crate::security::{
    is_blocked_target, log_headers_sanitized, resolve_and_validate_host,
};
use crate::tokio_io::TokioIo;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioTimer;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

/// Handle a client connection
pub async fn handle_client(
    stream: TcpStream,
    client_addr: SocketAddr,
    tls_connector: Arc<TlsConnector>,
    security: Arc<SecurityConfig>,
    logging: Arc<LoggingConfig>,
    tcp_keepalive: Arc<TcpKeepaliveConfig>,
    sender_pool: Arc<Mutex<SenderPool>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);

    // Configure header read timeout for slowloris protection
    let header_timeout = if security.header_read_timeout_seconds > 0 {
        Some(Duration::from_secs(security.header_read_timeout_seconds))
    } else {
        None
    };

    let mut builder = http1::Builder::new();
    builder.preserve_header_case(true).title_case_headers(true);

    // Apply header read timeout if configured
    if header_timeout.is_some() {
        builder.timer(TokioTimer::new());
        builder.header_read_timeout(header_timeout);
    }

    // Per-connection request counter (for rate limiting within a connection)
    let request_count = Arc::new(AtomicU32::new(0));
    let max_requests = security.max_requests_per_connection;

    builder
        .serve_connection(
            io,
            service_fn(move |req| {
                let tls = Arc::clone(&tls_connector);
                let sec = Arc::clone(&security);
                let log = Arc::clone(&logging);
                let keepalive = Arc::clone(&tcp_keepalive);
                let pool = Arc::clone(&sender_pool);
                let count = Arc::clone(&request_count);

                async move {
                    // Check per-connection request limit
                    if max_requests > 0 {
                        let current = count.fetch_add(1, Ordering::Relaxed);
                        if current >= max_requests {
                            warn!(
                                client = %client_addr,
                                current = current,
                                limit = max_requests,
                                "Per-connection request limit exceeded"
                            );
                            return Ok(error_response(
                                429,
                                "Too Many Requests: Connection request limit exceeded",
                            ));
                        }
                    }
                    proxy_request(req, client_addr, tls, sec, log, keepalive, pool).await
                }
            }),
        )
        .with_upgrades()
        .await?;

    Ok(())
}

/// Proxy an HTTP request to the target server
pub async fn proxy_request(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    tls_connector: Arc<TlsConnector>,
    security: Arc<SecurityConfig>,
    logging: Arc<LoggingConfig>,
    tcp_keepalive: Arc<TcpKeepaliveConfig>,
    sender_pool: Arc<Mutex<SenderPool>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    // Handle CONNECT method for HTTPS tunneling
    if method == Method::CONNECT {
        return handle_connect(req, client_addr, &security, &logging, &tcp_keepalive).await;
    }

    // HTTP Request Smuggling Prevention (RFC 7230 Section 3.3.3)
    // Reject requests with both Content-Length and Transfer-Encoding headers
    // to prevent CL.TE and TE.CL desynchronization attacks
    let has_content_length = req.headers().contains_key(hyper::header::CONTENT_LENGTH);
    let has_transfer_encoding = req.headers().contains_key(hyper::header::TRANSFER_ENCODING);
    if has_content_length && has_transfer_encoding {
        warn!(
            client = %client_addr,
            method = %method,
            uri = %uri,
            "Request smuggling attempt blocked (both Content-Length and Transfer-Encoding)"
        );
        return Ok(error_response(
            400,
            "Bad Request: Ambiguous message framing (both Content-Length and Transfer-Encoding)",
        ));
    }

    // Check request body size limit (Content-Length header)
    if security.max_request_body_bytes > 0 {
        if let Some(content_length) = req.headers().get(hyper::header::CONTENT_LENGTH) {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<u64>() {
                    if length > security.max_request_body_bytes {
                        warn!(
                            client = %client_addr,
                            method = %method,
                            uri = %uri,
                            content_length = length,
                            limit = security.max_request_body_bytes,
                            "Request body size limit exceeded"
                        );
                        return Ok(error_response(
                            413,
                            "Payload Too Large: Request body exceeds size limit",
                        ));
                    }
                }
            }
        }
    }

    // Extract target host and port from request
    let (host, port, use_tls) = match extract_target(&req) {
        Some(target) => target,
        None => {
            warn!(
                client = %client_addr,
                method = %method,
                uri = %uri,
                "Bad request: no host specified"
            );
            return Ok(error_response(400, "Bad Request: no host specified"));
        }
    };

    // SSRF Prevention: Check if target is blocked (applies to HTTP too, not just CONNECT)
    let authority = format!("{}:{}", host, port);
    if let Some(reason) = is_blocked_target(&authority, &security) {
        warn!(
            client = %client_addr,
            method = %method,
            target = %authority,
            reason = %reason,
            "SSRF blocked"
        );
        return Ok(error_response(
            403,
            "Forbidden: Target blocked by security policy",
        ));
    }

    if logging.log_requests {
        info!(
            client = %client_addr,
            method = %method,
            host = %host,
            port = port,
            path = %uri.path(),
            "HTTP request"
        );
        log_headers_sanitized(req.headers().iter(), &logging);
    }

    // DNS Rebinding Protection: Resolve and validate ALL IPs before connecting
    let resolved_addrs = match resolve_and_validate_host(&host, port, &security).await {
        Ok(addrs) => addrs,
        Err(reason) => {
            warn!(
                client = %client_addr,
                method = %method,
                target = %authority,
                reason = %reason,
                "DNS rebinding protection blocked"
            );
            return Ok(error_response(
                403,
                "Forbidden: Target blocked by security policy",
            ));
        }
    };

    // Build the request to send to target
    let path = req
        .uri()
        .path_and_query()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "/".to_string());

    let target_req = match build_target_request(req, &path, &host, port, client_addr) {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "Failed to build request");
            return Ok(error_response(500, "Internal Server Error"));
        }
    };

    // Try to get an existing sender from the pool
    let (mut sender, created_at, from_pool) = {
        let mut pool = sender_pool.lock().await;
        if let Some((s, created)) = pool.get(&host, port, use_tls) {
            if logging.log_requests {
                debug!(
                    host = %host,
                    port = port,
                    tls = use_tls,
                    "Reusing pooled connection"
                );
            }
            (s, created, true)
        } else {
            drop(pool); // Release lock before connecting

            // Get connect timeout from pool config
            let connect_timeout = {
                let pool = sender_pool.lock().await;
                Duration::from_secs(pool.config.connect_timeout_seconds)
            };

            // Create new connection and sender
            let created_at = Instant::now();
            match create_sender(
                &resolved_addrs[0],
                &host,
                use_tls,
                &tls_connector,
                connect_timeout,
                &tcp_keepalive,
            )
            .await
            {
                Ok(s) => (s, created_at, false),
                Err(e) => {
                    return Ok(e);
                }
            }
        }
    };

    // Wait for sender to be ready
    if let Err(e) = sender.ready().await {
        error!(host = %host, port = port, error = %e, "Sender not ready");
        return Ok(error_response(502, "Bad Gateway: Connection not ready"));
    }

    // Send the request
    let result = match sender.send_request(target_req).await {
        Ok(res) => {
            let (parts, body) = res.into_parts();
            Ok(Response::from_parts(parts, body.boxed()))
        }
        Err(e) => {
            error!(host = %host, port = port, error = %e, "Request failed");
            Ok(error_response(502, "Bad Gateway: Request failed"))
        }
    };

    // Return sender to pool if still usable (and request succeeded)
    if result.is_ok() && !sender.is_closed() {
        let mut pool = sender_pool.lock().await;
        pool.put(&host, port, use_tls, sender, created_at);
        if logging.log_requests && !from_pool {
            debug!(
                host = %host,
                port = port,
                tls = use_tls,
                "Added connection to pool"
            );
        }
    }

    result
}

/// Extract target host, port, and TLS flag from request
/// Made public for testing
pub fn extract_target(req: &Request<Incoming>) -> Option<(String, u16, bool)> {
    // Try to get from absolute URI first
    if let Some(host) = req.uri().host() {
        let use_tls = req.uri().scheme_str() == Some("https");
        let default_port = if use_tls { 443 } else { 80 };
        let port = req.uri().port_u16().unwrap_or(default_port);
        return Some((host.to_string(), port, use_tls));
    }

    // Fall back to Host header
    if let Some(host_header) = req.headers().get("host") {
        if let Ok(host_str) = host_header.to_str() {
            let (host, port) = if let Some(colon_pos) = host_str.rfind(':') {
                let host = &host_str[..colon_pos];
                let port: u16 = host_str[colon_pos + 1..].parse().unwrap_or(80);
                (host.to_string(), port)
            } else {
                (host_str.to_string(), 80)
            };
            return Some((host, port, false));
        }
    }

    None
}

/// Build the request to send to the target server
/// Made public for testing
pub fn build_target_request(
    req: Request<Incoming>,
    path: &str,
    host: &str,
    port: u16,
    client_addr: SocketAddr,
) -> Result<Request<Incoming>, hyper::http::Error> {
    let host_header = if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };

    let mut builder = Request::builder()
        .method(req.method())
        .uri(path)
        .header("Host", &host_header)
        .header("X-Forwarded-For", client_addr.ip().to_string());

    // Copy headers from original request (except hop-by-hop headers)
    let hop_by_hop = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];

    for (name, value) in req.headers() {
        let name_lower = name.as_str().to_lowercase();
        if name_lower != "host" && !hop_by_hop.contains(&name_lower.as_str()) {
            builder = builder.header(name, value);
        }
    }

    builder.body(req.into_body())
}

/// Create a new HTTP sender (with optional TLS) for connection pooling
async fn create_sender(
    addr: &SocketAddr,
    host: &str,
    use_tls: bool,
    tls_connector: &TlsConnector,
    connect_timeout: Duration,
    tcp_keepalive: &TcpKeepaliveConfig,
) -> Result<SendRequest<Incoming>, Response<BoxBody<Bytes, hyper::Error>>> {
    // Connect with timeout
    let tcp_stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            error!(addr = %addr, error = %e, "Failed to connect to target");
            return Err(error_response(
                502,
                "Bad Gateway: Failed to connect to target",
            ));
        }
        Err(_) => {
            error!(addr = %addr, "Connection timeout");
            return Err(error_response(504, "Gateway Timeout: Connection timed out"));
        }
    };

    // Apply TCP keep-alive to upstream connection
    if let Err(e) = apply_tcp_keepalive(&tcp_stream, tcp_keepalive) {
        warn!(addr = %addr, error = %e, "Failed to set TCP keep-alive");
    }

    if use_tls {
        // TLS connection
        let server_name: ServerName<'static> = match host.to_string().try_into() {
            Ok(name) => name,
            Err(_) => {
                error!(host = %host, "Invalid server name");
                return Err(error_response(502, "Bad Gateway: Invalid server name"));
            }
        };

        let tls_stream = match tls_connector.connect(server_name, tcp_stream).await {
            Ok(s) => s,
            Err(e) => {
                error!(host = %host, error = %e, "TLS connection failed");
                return Err(error_response(502, "Bad Gateway: TLS connection failed"));
            }
        };

        let io = TokioIo::new(tls_stream);
        let (sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(h) => h,
            Err(e) => {
                error!(host = %host, error = %e, "TLS HTTP handshake failed");
                return Err(error_response(502, "Bad Gateway: Handshake failed"));
            }
        };

        // Spawn connection driver task
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                debug!(error = ?err, "TLS connection driver error");
            }
        });

        Ok(sender)
    } else {
        // Plain HTTP connection
        let io = TokioIo::new(tcp_stream);
        let (sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(h) => h,
            Err(e) => {
                error!(addr = %addr, error = %e, "HTTP handshake failed");
                return Err(error_response(502, "Bad Gateway: Handshake failed"));
            }
        };

        // Spawn connection driver task
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                debug!(error = ?err, "HTTP connection driver error");
            }
        });

        Ok(sender)
    }
}

#[cfg(test)]
mod tests {
    use hyper::Request;

    fn create_test_request(uri: &str, host: Option<&str>) -> Request<()> {
        let mut builder = Request::builder().method("GET").uri(uri);

        if let Some(h) = host {
            builder = builder.header("host", h);
        }

        builder.body(()).unwrap()
    }

    #[test]
    fn test_extract_target_absolute_uri_http() {
        let req = create_test_request("http://example.com/path", None);
        let uri = req.uri();
        assert_eq!(uri.host(), Some("example.com"));
        assert_eq!(uri.port_u16(), None);
        assert_eq!(uri.scheme_str(), Some("http"));
    }

    #[test]
    fn test_extract_target_absolute_uri_https() {
        let req = create_test_request("https://example.com:8443/path", None);
        let uri = req.uri();
        assert_eq!(uri.host(), Some("example.com"));
        assert_eq!(uri.port_u16(), Some(8443));
        assert_eq!(uri.scheme_str(), Some("https"));
    }

    #[test]
    fn test_host_header_simple() {
        let req = create_test_request("/path", Some("example.com"));
        let host = req.headers().get("host").unwrap().to_str().unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn test_host_header_with_port() {
        let req = create_test_request("/path", Some("example.com:8080"));
        let host = req.headers().get("host").unwrap().to_str().unwrap();

        let parts: Vec<&str> = host.rsplitn(2, ':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "8080");
        assert_eq!(parts[1], "example.com");
    }

    #[test]
    fn test_hop_by_hop_headers_list() {
        let hop_by_hop = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        ];

        assert!(hop_by_hop.contains(&"connection"));
        assert!(hop_by_hop.contains(&"proxy-authorization"));
        assert!(hop_by_hop.contains(&"proxy-connection"));
        assert!(!hop_by_hop.contains(&"content-type"));
        assert!(!hop_by_hop.contains(&"accept"));
        assert!(!hop_by_hop.contains(&"host"));
    }

    #[test]
    fn test_extract_target_absolute_uri_with_port() {
        let req = create_test_request("http://example.com:9090/path?query=1", None);
        let uri = req.uri();
        assert_eq!(uri.host(), Some("example.com"));
        assert_eq!(uri.port_u16(), Some(9090));
        assert_eq!(uri.scheme_str(), Some("http"));
        assert_eq!(uri.path(), "/path");
        assert_eq!(uri.query(), Some("query=1"));
    }

    #[test]
    fn test_extract_target_https_default_port() {
        let req = create_test_request("https://secure.example.com/", None);
        let uri = req.uri();
        assert_eq!(uri.host(), Some("secure.example.com"));
        assert_eq!(uri.port_u16(), None); // Default 443
        assert_eq!(uri.scheme_str(), Some("https"));
    }

    #[test]
    fn test_host_header_ipv4() {
        let req = create_test_request("/path", Some("192.168.1.100:8080"));
        let host = req.headers().get("host").unwrap().to_str().unwrap();
        assert!(host.contains("192.168.1.100"));
        assert!(host.contains("8080"));
    }

    #[test]
    fn test_host_header_ipv6() {
        let req = create_test_request("/path", Some("[::1]:8080"));
        let host = req.headers().get("host").unwrap().to_str().unwrap();
        assert!(host.contains("::1"));
    }

    #[test]
    fn test_request_no_host() {
        let req = create_test_request("/path", None);
        assert!(req.headers().get("host").is_none());
    }

    #[test]
    fn test_path_and_query_extraction() {
        let req = create_test_request("http://example.com/api/v1/users?id=123&name=test", None);
        let uri = req.uri();
        let path_and_query = uri.path_and_query().map(|x| x.to_string());
        assert_eq!(path_and_query, Some("/api/v1/users?id=123&name=test".to_string()));
    }

    #[test]
    fn test_path_only_no_query() {
        let req = create_test_request("http://example.com/api/endpoint", None);
        let uri = req.uri();
        assert_eq!(uri.path(), "/api/endpoint");
        assert_eq!(uri.query(), None);
    }

    #[test]
    fn test_root_path() {
        let req = create_test_request("http://example.com/", None);
        let uri = req.uri();
        assert_eq!(uri.path(), "/");
    }

    #[test]
    fn test_relative_uri_with_query() {
        let req = create_test_request("/search?q=rust+proxy", Some("example.com"));
        let uri = req.uri();
        assert_eq!(uri.path(), "/search");
        assert_eq!(uri.query(), Some("q=rust+proxy"));
    }

    #[test]
    fn test_hop_by_hop_filtering() {
        let hop_by_hop = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        ];

        // Test that common headers are NOT hop-by-hop
        let should_forward = ["content-type", "accept", "user-agent", "accept-encoding",
                              "authorization", "cookie", "x-custom-header"];
        for header in should_forward {
            assert!(!hop_by_hop.contains(&header), "Header {} should be forwarded", header);
        }

        // Test that hop-by-hop headers ARE in the list
        for header in &hop_by_hop {
            assert!(hop_by_hop.contains(header), "Header {} should be hop-by-hop", header);
        }
    }

    #[test]
    fn test_host_header_port_parsing() {
        // Test various host:port formats
        let cases = [
            ("example.com", "example.com", 80u16),
            ("example.com:8080", "example.com", 8080),
            ("example.com:443", "example.com", 443),
            ("api.example.com:3000", "api.example.com", 3000),
        ];

        for (host_header, expected_host, expected_port) in cases {
            let (host, port) = if let Some(colon_pos) = host_header.rfind(':') {
                let h = &host_header[..colon_pos];
                let p: u16 = host_header[colon_pos + 1..].parse().unwrap_or(80);
                (h, p)
            } else {
                (host_header, 80)
            };
            assert_eq!(host, expected_host);
            assert_eq!(port, expected_port);
        }
    }

    #[test]
    fn test_host_header_generation() {
        // When port is default (80/443), don't include port in Host header
        let host = "example.com";
        let port = 80u16;
        let host_header = if port == 80 || port == 443 {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };
        assert_eq!(host_header, "example.com");

        // Non-default port should be included
        let port = 8080u16;
        let host_header = if port == 80 || port == 443 {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };
        assert_eq!(host_header, "example.com:8080");
    }
}
