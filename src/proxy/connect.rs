//! HTTP CONNECT tunnel handling for HTTPS proxying.

use crate::body::BoxBody;
use crate::config::{LoggingConfig, SecurityConfig, TcpKeepaliveConfig};
use crate::helpers::{apply_tcp_keepalive, empty_body, error_response};
use crate::security::{is_blocked_target, log_headers_sanitized, resolve_and_validate_host};
use crate::tokio_io::TokioIo;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::Request;
use hyper::Response;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::{error, info, warn};

/// Handle HTTP CONNECT method for HTTPS tunneling
pub async fn handle_connect(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    security: &SecurityConfig,
    logging: &LoggingConfig,
    tcp_keepalive: &TcpKeepaliveConfig,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let uri = req.uri().clone();

    // Extract host:port from CONNECT request
    let authority = match uri.authority() {
        Some(auth) => auth.to_string(),
        None => {
            warn!(client = %client_addr, "CONNECT bad request: no authority");
            return Ok(error_response(400, "Bad Request: no authority"));
        }
    };

    // SSRF Protection: Check if target is blocked
    if let Some(reason) = is_blocked_target(&authority, security) {
        warn!(
            client = %client_addr,
            target = %authority,
            reason = %reason,
            "CONNECT SSRF blocked"
        );
        return Ok(error_response(
            403,
            "Forbidden: Target blocked by security policy",
        ));
    }

    // Parse host and port for DNS resolution
    let (host, port) = if let Some(colon_pos) = authority.rfind(':') {
        let h = &authority[..colon_pos];
        let p: u16 = authority[colon_pos + 1..].parse().unwrap_or(443);
        (h.to_string(), p)
    } else {
        (authority.clone(), 443)
    };

    // DNS Rebinding Protection: Resolve and validate ALL IPs before connecting
    let resolved_addrs = match resolve_and_validate_host(&host, port, security).await {
        Ok(addrs) => addrs,
        Err(reason) => {
            warn!(
                client = %client_addr,
                target = %authority,
                reason = %reason,
                "CONNECT DNS rebinding blocked"
            );
            return Ok(error_response(
                403,
                "Forbidden: Target blocked by security policy",
            ));
        }
    };

    if logging.log_requests {
        info!(
            client = %client_addr,
            target = %authority,
            resolved_ip = %resolved_addrs[0].ip(),
            "CONNECT tunnel"
        );
        log_headers_sanitized(req.headers().iter(), logging);
    }

    // Connect to first resolved address (already validated)
    let target_stream = match TcpStream::connect(&resolved_addrs[0]).await {
        Ok(stream) => stream,
        Err(e) => {
            error!(addr = %resolved_addrs[0], error = %e, "CONNECT failed to connect");
            return Ok(error_response(502, "Bad Gateway: Failed to connect"));
        }
    };

    // Apply TCP keep-alive to tunnel connection
    if let Err(e) = apply_tcp_keepalive(&target_stream, tcp_keepalive) {
        if logging.log_requests {
            warn!(target = %authority, error = %e, "Failed to set TCP keep-alive on tunnel");
        }
    }

    // Spawn a task to handle the tunnel after upgrade
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                let mut target = target_stream;

                // Bidirectional copy
                let (mut client_read, mut client_write) = tokio::io::split(&mut upgraded);
                let (mut target_read, mut target_write) = tokio::io::split(&mut target);

                let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
                let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

                tokio::select! {
                    _ = client_to_target => {}
                    _ = target_to_client => {}
                }
            }
            Err(e) => {
                error!(target = %authority, error = %e, "CONNECT upgrade error");
            }
        }
    });

    // Return 200 Connection Established
    Ok(Response::builder().status(200).body(empty_body()).unwrap())
}
