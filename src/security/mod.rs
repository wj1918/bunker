//! Security module for SSRF prevention, rate limiting, and access control.

mod ip_filter;
mod rate_limiter;

pub use ip_filter::{
    is_blocked_target, is_source_ip_allowed, resolved_addrs_blocked, split_host_port,
};
pub use rate_limiter::{DnsRateLimiter, RateLimiter};
