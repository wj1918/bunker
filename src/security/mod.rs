//! Security module for SSRF prevention, rate limiting, and access control.

mod ip_filter;
mod rate_limiter;

pub use ip_filter::{is_blocked_target, is_source_ip_allowed, resolve_and_validate_host};
pub use rate_limiter::{DnsRateLimiter, RateLimiter};

use crate::config::LoggingConfig;
use tracing::debug;

/// Sanitize header value for logging (redact sensitive data)
pub fn sanitize_header_value(name: &str, value: &str, logging: &LoggingConfig) -> String {
    if !logging.redact_sensitive_headers {
        return value.to_string();
    }

    let name_lower = name.to_lowercase();
    let is_sensitive = logging
        .sensitive_headers
        .iter()
        .any(|h| h.to_lowercase() == name_lower);

    if is_sensitive {
        // Show type but redact value
        let value_lower = value.to_lowercase();
        if value_lower.starts_with("bearer ") {
            "Bearer [REDACTED]".to_string()
        } else if value_lower.starts_with("basic ") {
            "Basic [REDACTED]".to_string()
        } else if value_lower.starts_with("digest ") {
            "Digest [REDACTED]".to_string()
        } else {
            "[REDACTED]".to_string()
        }
    } else {
        value.to_string()
    }
}

/// Log headers with sensitive data redacted
pub fn log_headers_sanitized<'a, I>(headers: I, logging: &LoggingConfig)
where
    I: Iterator<Item = (&'a hyper::header::HeaderName, &'a hyper::header::HeaderValue)>,
{
    for (name, value) in headers {
        let value_str = value.to_str().unwrap_or("[binary]");
        let safe_value = sanitize_header_value(name.as_str(), value_str, logging);
        debug!(header = %name, value = %safe_value, "HTTP header");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logging_with_redaction() -> LoggingConfig {
        LoggingConfig {
            log_requests: true,
            format: crate::config::LogFormat::Text,
            redact_sensitive_headers: true,
            sensitive_headers: vec![
                "authorization".to_string(),
                "proxy-authorization".to_string(),
                "cookie".to_string(),
            ],
            file: None,
        }
    }

    fn logging_without_redaction() -> LoggingConfig {
        LoggingConfig {
            log_requests: true,
            format: crate::config::LogFormat::Text,
            redact_sensitive_headers: false,
            sensitive_headers: vec![],
            file: None,
        }
    }

    #[test]
    fn test_sanitize_header_value_non_sensitive() {
        let logging = logging_with_redaction();
        let result = sanitize_header_value("content-type", "application/json", &logging);
        assert_eq!(result, "application/json");
    }

    #[test]
    fn test_sanitize_header_value_bearer_token() {
        let logging = logging_with_redaction();
        let result = sanitize_header_value("authorization", "Bearer abc123xyz", &logging);
        assert_eq!(result, "Bearer [REDACTED]");
    }

    #[test]
    fn test_sanitize_header_value_basic_auth() {
        let logging = logging_with_redaction();
        let result = sanitize_header_value("authorization", "Basic dXNlcjpwYXNz", &logging);
        assert_eq!(result, "Basic [REDACTED]");
    }

    #[test]
    fn test_sanitize_header_value_digest_auth() {
        let logging = logging_with_redaction();
        let result = sanitize_header_value("authorization", "Digest username=\"user\"", &logging);
        assert_eq!(result, "Digest [REDACTED]");
    }

    #[test]
    fn test_sanitize_header_value_generic_sensitive() {
        let logging = logging_with_redaction();
        let result = sanitize_header_value("cookie", "session=abc123", &logging);
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn test_sanitize_header_value_proxy_authorization() {
        let logging = logging_with_redaction();
        let result = sanitize_header_value("proxy-authorization", "Bearer token123", &logging);
        assert_eq!(result, "Bearer [REDACTED]");
    }

    #[test]
    fn test_sanitize_header_value_case_insensitive() {
        let logging = logging_with_redaction();
        let result = sanitize_header_value("AUTHORIZATION", "Bearer secret", &logging);
        assert_eq!(result, "Bearer [REDACTED]");
    }

    #[test]
    fn test_sanitize_header_value_redaction_disabled() {
        let logging = logging_without_redaction();
        let result = sanitize_header_value("authorization", "Bearer secret", &logging);
        assert_eq!(result, "Bearer secret");
    }

    #[test]
    fn test_sanitize_header_value_empty_value() {
        let logging = logging_with_redaction();
        let result = sanitize_header_value("authorization", "", &logging);
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn test_log_headers_sanitized() {
        // This test just verifies it doesn't panic
        use hyper::header::{HeaderMap, HeaderValue};
        let logging = logging_with_redaction();

        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));

        // Call the function - it prints to stdout but we verify it doesn't panic
        log_headers_sanitized(headers.iter(), &logging);
    }
}
