//! Structured error types for the proxy application.

use std::fmt;
use std::io;

/// Main error type for proxy operations
#[derive(Debug)]
#[allow(dead_code)]
pub enum ProxyError {
    /// IO error (network, file operations)
    Io(io::Error),
    /// Configuration error
    Config(String),
    /// Security policy violation
    Security(SecurityError),
    /// DNS resolution or query error
    Dns(DnsError),
    /// HTTP protocol error
    Http(String),
    /// Connection pool error
    Pool(String),
    /// TLS/SSL error
    Tls(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Io(e) => write!(f, "IO error: {}", e),
            ProxyError::Config(msg) => write!(f, "Configuration error: {}", msg),
            ProxyError::Security(e) => write!(f, "Security error: {}", e),
            ProxyError::Dns(e) => write!(f, "DNS error: {}", e),
            ProxyError::Http(msg) => write!(f, "HTTP error: {}", msg),
            ProxyError::Pool(msg) => write!(f, "Connection pool error: {}", msg),
            ProxyError::Tls(msg) => write!(f, "TLS error: {}", msg),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProxyError::Io(e) => Some(e),
            ProxyError::Security(e) => Some(e),
            ProxyError::Dns(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ProxyError {
    fn from(err: io::Error) -> Self {
        ProxyError::Io(err)
    }
}

/// Security-related errors
#[derive(Debug)]
#[allow(dead_code)]
pub enum SecurityError {
    /// Request blocked due to private IP (SSRF prevention)
    PrivateIpBlocked(String),
    /// Request blocked due to blocked host pattern
    HostBlocked(String),
    /// Request blocked due to port restriction
    PortBlocked(u16),
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Source IP not in allowlist
    SourceIpNotAllowed(String),
    /// DNS rebinding attack detected
    DnsRebindingBlocked(String),
    /// Connection limit reached
    ConnectionLimitReached,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::PrivateIpBlocked(ip) => {
                write!(f, "Private/internal IP blocked: {}", ip)
            }
            SecurityError::HostBlocked(host) => {
                write!(f, "Host blocked by policy: {}", host)
            }
            SecurityError::PortBlocked(port) => {
                write!(f, "Port {} not in allowlist", port)
            }
            SecurityError::RateLimitExceeded => {
                write!(f, "Rate limit exceeded")
            }
            SecurityError::SourceIpNotAllowed(ip) => {
                write!(f, "Source IP not in allowlist: {}", ip)
            }
            SecurityError::DnsRebindingBlocked(host) => {
                write!(f, "DNS rebinding attack blocked: {}", host)
            }
            SecurityError::ConnectionLimitReached => {
                write!(f, "Maximum connection limit reached")
            }
        }
    }
}

impl std::error::Error for SecurityError {}

/// DNS-related errors
#[derive(Debug)]
#[allow(dead_code)]
pub enum DnsError {
    /// Failed to parse DNS query
    ParseError(String),
    /// Query type blocked (ANY, AXFR, etc.)
    QueryTypeBlocked(String),
    /// All upstream servers failed
    UpstreamFailed,
    /// DNS response spoofing detected
    SpoofingDetected,
    /// Timeout waiting for response
    Timeout,
    /// Rate limit exceeded
    RateLimitExceeded,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::ParseError(msg) => write!(f, "DNS parse error: {}", msg),
            DnsError::QueryTypeBlocked(qtype) => {
                write!(f, "DNS query type blocked: {}", qtype)
            }
            DnsError::UpstreamFailed => write!(f, "All upstream DNS servers failed"),
            DnsError::SpoofingDetected => write!(f, "DNS response spoofing detected"),
            DnsError::Timeout => write!(f, "DNS query timeout"),
            DnsError::RateLimitExceeded => write!(f, "DNS rate limit exceeded"),
        }
    }
}

impl std::error::Error for DnsError {}

/// Convenience type alias for Results using ProxyError
#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, ProxyError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_proxy_error_io_display() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = ProxyError::Io(io_err);
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn test_proxy_error_config_display() {
        let err = ProxyError::Config("invalid port".to_string());
        assert_eq!(err.to_string(), "Configuration error: invalid port");
    }

    #[test]
    fn test_proxy_error_http_display() {
        let err = ProxyError::Http("bad request".to_string());
        assert_eq!(err.to_string(), "HTTP error: bad request");
    }

    #[test]
    fn test_proxy_error_pool_display() {
        let err = ProxyError::Pool("pool exhausted".to_string());
        assert_eq!(err.to_string(), "Connection pool error: pool exhausted");
    }

    #[test]
    fn test_proxy_error_tls_display() {
        let err = ProxyError::Tls("certificate expired".to_string());
        assert_eq!(err.to_string(), "TLS error: certificate expired");
    }

    #[test]
    fn test_proxy_error_security_display() {
        let sec_err = SecurityError::RateLimitExceeded;
        let err = ProxyError::Security(sec_err);
        assert!(err.to_string().contains("Security error"));
    }

    #[test]
    fn test_proxy_error_dns_display() {
        let dns_err = DnsError::Timeout;
        let err = ProxyError::Dns(dns_err);
        assert!(err.to_string().contains("DNS error"));
    }

    #[test]
    fn test_proxy_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let err: ProxyError = io_err.into();
        assert!(matches!(err, ProxyError::Io(_)));
    }

    #[test]
    fn test_proxy_error_source_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let err = ProxyError::Io(io_err);
        assert!(err.source().is_some());
    }

    #[test]
    fn test_proxy_error_source_security() {
        let err = ProxyError::Security(SecurityError::RateLimitExceeded);
        assert!(err.source().is_some());
    }

    #[test]
    fn test_proxy_error_source_dns() {
        let err = ProxyError::Dns(DnsError::Timeout);
        assert!(err.source().is_some());
    }

    #[test]
    fn test_proxy_error_source_none() {
        let err = ProxyError::Config("test".to_string());
        assert!(err.source().is_none());

        let err = ProxyError::Http("test".to_string());
        assert!(err.source().is_none());

        let err = ProxyError::Pool("test".to_string());
        assert!(err.source().is_none());

        let err = ProxyError::Tls("test".to_string());
        assert!(err.source().is_none());
    }

    #[test]
    fn test_security_error_private_ip_blocked() {
        let err = SecurityError::PrivateIpBlocked("192.168.1.1".to_string());
        assert!(err.to_string().contains("192.168.1.1"));
        assert!(err.to_string().contains("Private"));
    }

    #[test]
    fn test_security_error_host_blocked() {
        let err = SecurityError::HostBlocked("evil.com".to_string());
        assert!(err.to_string().contains("evil.com"));
        assert!(err.to_string().contains("Host blocked"));
    }

    #[test]
    fn test_security_error_port_blocked() {
        let err = SecurityError::PortBlocked(22);
        assert!(err.to_string().contains("22"));
        assert!(err.to_string().contains("not in allowlist"));
    }

    #[test]
    fn test_security_error_rate_limit_exceeded() {
        let err = SecurityError::RateLimitExceeded;
        assert!(err.to_string().contains("Rate limit"));
    }

    #[test]
    fn test_security_error_source_ip_not_allowed() {
        let err = SecurityError::SourceIpNotAllowed("10.0.0.1".to_string());
        assert!(err.to_string().contains("10.0.0.1"));
        assert!(err.to_string().contains("not in allowlist"));
    }

    #[test]
    fn test_security_error_dns_rebinding_blocked() {
        let err = SecurityError::DnsRebindingBlocked("malicious.com".to_string());
        assert!(err.to_string().contains("malicious.com"));
        assert!(err.to_string().contains("rebinding"));
    }

    #[test]
    fn test_security_error_connection_limit_reached() {
        let err = SecurityError::ConnectionLimitReached;
        assert!(err.to_string().contains("connection limit"));
    }

    #[test]
    fn test_dns_error_parse_error() {
        let err = DnsError::ParseError("invalid query".to_string());
        assert!(err.to_string().contains("parse error"));
        assert!(err.to_string().contains("invalid query"));
    }

    #[test]
    fn test_dns_error_query_type_blocked() {
        let err = DnsError::QueryTypeBlocked("AXFR".to_string());
        assert!(err.to_string().contains("AXFR"));
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn test_dns_error_upstream_failed() {
        let err = DnsError::UpstreamFailed;
        assert!(err.to_string().contains("upstream"));
    }

    #[test]
    fn test_dns_error_spoofing_detected() {
        let err = DnsError::SpoofingDetected;
        assert!(err.to_string().contains("spoofing"));
    }

    #[test]
    fn test_dns_error_timeout() {
        let err = DnsError::Timeout;
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_dns_error_rate_limit_exceeded() {
        let err = DnsError::RateLimitExceeded;
        assert!(err.to_string().contains("rate limit"));
    }

    #[test]
    fn test_security_error_is_error() {
        // Verify SecurityError implements std::error::Error
        let err: &dyn std::error::Error = &SecurityError::RateLimitExceeded;
        assert!(err.to_string().contains("Rate limit"));
    }

    #[test]
    fn test_dns_error_is_error() {
        // Verify DnsError implements std::error::Error
        let err: &dyn std::error::Error = &DnsError::Timeout;
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_proxy_error_debug() {
        let err = ProxyError::Config("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Config"));
    }

    #[test]
    fn test_security_error_debug() {
        let err = SecurityError::RateLimitExceeded;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("RateLimitExceeded"));
    }

    #[test]
    fn test_dns_error_debug() {
        let err = DnsError::Timeout;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Timeout"));
    }
}
