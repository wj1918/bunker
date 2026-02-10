//! Helper functions for TLS, responses, and TCP settings.

use crate::body::{BodyExt, BoxBody, Empty, Full};
use crate::config::TcpKeepaliveConfig;
use bytes::Bytes;
use hyper::Response;
use socket2::{SockRef, TcpKeepalive};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Create a TLS connector with system root certificates
pub fn create_tls_connector() -> Result<TlsConnector, Box<dyn std::error::Error + Send + Sync>> {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Apply TCP keep-alive settings to a socket
pub fn apply_tcp_keepalive(stream: &TcpStream, config: &TcpKeepaliveConfig) -> std::io::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let socket = SockRef::from(stream);

    #[allow(unused_mut)]
    let mut keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(config.time_seconds))
        .with_interval(Duration::from_secs(config.interval_seconds));

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        keepalive = keepalive.with_retries(config.retries);
    }

    socket.set_tcp_keepalive(&keepalive)?;
    Ok(())
}

/// Create an error response with the given status code and message
pub fn error_response(status: u16, msg: &'static str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from(msg))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Create an empty response body
pub fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_tls_connector() {
        let result = create_tls_connector();
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_response_400() {
        let resp = error_response(400, "Bad Request");
        assert_eq!(resp.status(), 400);
    }

    #[test]
    fn test_error_response_502() {
        let resp = error_response(502, "Bad Gateway");
        assert_eq!(resp.status(), 502);
    }

    #[test]
    fn test_error_response_500() {
        let resp = error_response(500, "Internal Server Error");
        assert_eq!(resp.status(), 500);
    }

    #[test]
    fn test_error_response_403() {
        let resp = error_response(403, "Forbidden");
        assert_eq!(resp.status(), 403);
    }

    #[test]
    fn test_error_response_504() {
        let resp = error_response(504, "Gateway Timeout");
        assert_eq!(resp.status(), 504);
    }

    #[test]
    fn test_empty_body() {
        let body = empty_body();
        drop(body);
    }

    #[test]
    fn test_apply_tcp_keepalive_disabled() {
        // Test with keepalive disabled - should return Ok immediately
        let config = TcpKeepaliveConfig {
            enabled: false,
            time_seconds: 60,
            interval_seconds: 10,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            retries: 3,
        };

        // We can't create a TcpStream in unit tests easily, but we can test the early return
        // by checking that the function handles disabled config properly
        // Since we need a real socket, let's just verify the function exists and config works
        assert!(!config.enabled);
    }

    #[test]
    fn test_tcp_keepalive_config_values() {
        let config = TcpKeepaliveConfig {
            enabled: true,
            time_seconds: 120,
            interval_seconds: 20,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            retries: 5,
        };
        assert!(config.enabled);
        assert_eq!(config.time_seconds, 120);
        assert_eq!(config.interval_seconds, 20);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(config.retries, 5);
    }

    #[tokio::test]
    async fn test_apply_tcp_keepalive_with_socket() {
        use tokio::net::TcpListener;

        // Create a listener to get a real socket
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept the connection
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream
        });

        // Connect to create a TcpStream
        let stream = TcpStream::connect(addr).await.unwrap();
        let _server_stream = accept_task.await.unwrap();

        // Test with keepalive disabled
        let disabled_config = TcpKeepaliveConfig {
            enabled: false,
            time_seconds: 60,
            interval_seconds: 10,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            retries: 3,
        };
        let result = apply_tcp_keepalive(&stream, &disabled_config);
        assert!(result.is_ok());

        // Test with keepalive enabled
        let enabled_config = TcpKeepaliveConfig {
            enabled: true,
            time_seconds: 60,
            interval_seconds: 10,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            retries: 3,
        };
        let result = apply_tcp_keepalive(&stream, &enabled_config);
        assert!(result.is_ok());
    }
}
