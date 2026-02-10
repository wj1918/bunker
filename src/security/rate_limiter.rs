//! Rate limiting for HTTP proxy and DNS requests.
//!
//! Security hardening features:
//! - Bounded HashMap to prevent memory exhaustion attacks
//! - IPv6 /64 subnet normalization to prevent bypass via address rotation
//! - O(1) LRU eviction using VecDeque

use crate::config::{DnsSecurityConfig, RateLimitConfig};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};
use tracing::warn;

/// Normalize an IP address for rate limiting purposes.
/// For IPv6 with subnet rate limiting enabled, maps to /64 subnet.
fn normalize_ip_for_rate_limit(ip: IpAddr, ipv6_subnet: bool) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if ipv6_subnet {
                // Zero out the last 64 bits (interface identifier)
                let segments = v6.segments();
                let normalized = Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    0,
                    0,
                    0,
                    0,
                );
                IpAddr::V6(normalized)
            } else {
                ip
            }
        }
    }
}

/// Rate limiter for tracking HTTP requests per IP
pub struct RateLimiter {
    requests: HashMap<IpAddr, Vec<Instant>>,
    /// Track insertion order for LRU eviction (O(1) front removal)
    insertion_order: VecDeque<IpAddr>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        RateLimiter {
            requests: HashMap::new(),
            insertion_order: VecDeque::new(),
            config,
        }
    }

    /// Check if a request from this IP should be allowed
    pub fn is_allowed(&mut self, ip: IpAddr) -> bool {
        if !self.config.enabled {
            return true;
        }

        // Normalize IPv6 to /64 subnet if enabled
        let key = normalize_ip_for_rate_limit(ip, self.config.ipv6_subnet_rate_limit);

        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_seconds);
        let window_start = now.checked_sub(window).unwrap_or(now);

        // Evict oldest entries if we're at capacity and this is a new IP
        if !self.requests.contains_key(&key) {
            self.evict_if_needed();
        }

        let is_new = !self.requests.contains_key(&key);
        let timestamps = self.requests.entry(key).or_default();

        // Track insertion order for new entries
        if is_new {
            self.insertion_order.push_back(key);
        }

        // Remove old entries outside window
        timestamps.retain(|&t| t > window_start);

        if timestamps.len() >= self.config.max_requests as usize {
            return false; // Rate limited
        }

        timestamps.push(now);
        true
    }

    /// Evict oldest entries if at capacity (O(1) using VecDeque)
    fn evict_if_needed(&mut self) {
        if self.requests.len() >= self.config.max_tracked_ips {
            // Security alert: rate limiter at capacity
            // This could indicate a distributed attack or need to increase max_tracked_ips
            warn!(
                tracked_ips = self.config.max_tracked_ips,
                "HTTP rate limiter at capacity, evicting oldest entries"
            );
        }
        while self.requests.len() >= self.config.max_tracked_ips {
            if let Some(oldest_ip) = self.insertion_order.pop_front() {
                self.requests.remove(&oldest_ip);
            } else {
                break;
            }
        }
    }

    /// Cleanup old entries to prevent memory growth
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_seconds);
        let window_start = now.checked_sub(window).unwrap_or(now);

        self.requests.retain(|_, timestamps| {
            timestamps.retain(|&t| t > window_start);
            !timestamps.is_empty()
        });

        // Also clean up insertion_order
        self.insertion_order
            .retain(|ip| self.requests.contains_key(ip));
    }

    /// Get current number of tracked IPs (for monitoring)
    #[allow(dead_code)]
    pub fn tracked_ip_count(&self) -> usize {
        self.requests.len()
    }
}

/// DNS-specific rate limiter (queries per second)
pub struct DnsRateLimiter {
    queries: HashMap<IpAddr, (u32, Instant)>, // (count, window_start)
    /// Track insertion order for LRU eviction (O(1) front removal)
    insertion_order: VecDeque<IpAddr>,
    config: DnsSecurityConfig,
}

impl DnsRateLimiter {
    pub fn new(config: DnsSecurityConfig) -> Self {
        DnsRateLimiter {
            queries: HashMap::new(),
            insertion_order: VecDeque::new(),
            config,
        }
    }

    pub fn is_allowed(&mut self, ip: IpAddr) -> bool {
        if !self.config.rate_limit_enabled {
            return true;
        }

        // Normalize IPv6 to /64 subnet if enabled
        let key = normalize_ip_for_rate_limit(ip, self.config.ipv6_subnet_rate_limit);

        let now = Instant::now();

        // Evict oldest entries if we're at capacity and this is a new IP
        if !self.queries.contains_key(&key) {
            self.evict_if_needed();
            self.insertion_order.push_back(key);
        }

        let entry = self.queries.entry(key).or_insert((0, now));

        // Reset window every second
        if now.saturating_duration_since(entry.1) > Duration::from_secs(1) {
            *entry = (1, now);
            return true;
        }

        entry.0 += 1;
        entry.0 <= self.config.max_qps
    }

    /// Evict oldest entries if at capacity (O(1) using VecDeque)
    fn evict_if_needed(&mut self) {
        if self.queries.len() >= self.config.max_tracked_ips {
            // Security alert: DNS rate limiter at capacity
            // This could indicate a distributed attack or need to increase max_tracked_ips
            warn!(
                tracked_ips = self.config.max_tracked_ips,
                "DNS rate limiter at capacity, evicting oldest entries"
            );
        }
        while self.queries.len() >= self.config.max_tracked_ips {
            if let Some(oldest_ip) = self.insertion_order.pop_front() {
                self.queries.remove(&oldest_ip);
            } else {
                break;
            }
        }
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.queries.retain(|_, (_, window_start)| {
            now.saturating_duration_since(*window_start) <= Duration::from_secs(5)
        });

        // Also clean up insertion_order
        self.insertion_order
            .retain(|ip| self.queries.contains_key(ip));
    }

    /// Get current number of tracked IPs (for monitoring)
    #[allow(dead_code)]
    pub fn tracked_ip_count(&self) -> usize {
        self.queries.len()
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn test_config() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            max_requests: 5,
            window_seconds: 60,
            max_tracked_ips: 100000,
            ipv6_subnet_rate_limit: true,
        }
    }

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let mut config = test_config();
        config.max_requests = 5;
        let mut limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        for _ in 0..5 {
            assert!(limiter.is_allowed(ip));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut config = test_config();
        config.max_requests = 3;
        let mut limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        for _ in 0..3 {
            assert!(limiter.is_allowed(ip));
        }

        assert!(!limiter.is_allowed(ip));
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let mut config = test_config();
        config.enabled = false;
        config.max_requests = 1;
        let mut limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        for _ in 0..100 {
            assert!(limiter.is_allowed(ip));
        }
    }

    #[test]
    fn test_rate_limiter_separate_ips() {
        let mut config = test_config();
        config.max_requests = 2;
        let mut limiter = RateLimiter::new(config);
        let ip1: IpAddr = "192.168.1.100".parse().unwrap();
        let ip2: IpAddr = "192.168.1.101".parse().unwrap();

        assert!(limiter.is_allowed(ip1));
        assert!(limiter.is_allowed(ip1));
        assert!(!limiter.is_allowed(ip1)); // blocked

        assert!(limiter.is_allowed(ip2));
        assert!(limiter.is_allowed(ip2));
        assert!(!limiter.is_allowed(ip2)); // blocked
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let config = test_config();
        let mut limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        assert!(limiter.is_allowed(ip));
        assert!(!limiter.requests.is_empty());

        limiter.cleanup();
        // Entries should still exist since window hasn't passed
        assert!(!limiter.requests.is_empty());
    }

    #[test]
    fn test_rate_limiter_ipv6_subnet_grouping() {
        // Test that IPv6 addresses in same /64 share rate limit
        let mut config = test_config();
        config.max_requests = 2;
        config.ipv6_subnet_rate_limit = true;
        let mut limiter = RateLimiter::new(config);

        // These are in the same /64 subnet (2001:db8:1234:5678::/64)
        let ip1: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8:1234:5678::2".parse().unwrap();
        let ip3: IpAddr = "2001:db8:1234:5678:aaaa:bbbb:cccc:dddd".parse().unwrap();

        assert!(limiter.is_allowed(ip1)); // Count: 1
        assert!(limiter.is_allowed(ip2)); // Count: 2 (same /64)
        assert!(!limiter.is_allowed(ip3)); // Blocked (same /64, limit reached)

        // Different /64 should have separate limit
        let ip4: IpAddr = "2001:db8:1234:9999::1".parse().unwrap();
        assert!(limiter.is_allowed(ip4)); // Different /64, allowed
    }

    #[test]
    fn test_rate_limiter_ipv6_subnet_disabled() {
        // Test that disabling subnet grouping treats each IPv6 separately
        let mut config = test_config();
        config.max_requests = 1;
        config.ipv6_subnet_rate_limit = false;
        let mut limiter = RateLimiter::new(config);

        let ip1: IpAddr = "2001:db8::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8::2".parse().unwrap();

        assert!(limiter.is_allowed(ip1));
        assert!(!limiter.is_allowed(ip1)); // blocked

        assert!(limiter.is_allowed(ip2)); // Different IP, allowed
    }

    #[test]
    fn test_rate_limiter_max_tracked_ips() {
        let mut config = test_config();
        config.max_requests = 100;
        config.max_tracked_ips = 3; // Only track 3 IPs
        let mut limiter = RateLimiter::new(config);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        let ip4: IpAddr = "10.0.0.4".parse().unwrap();

        assert!(limiter.is_allowed(ip1));
        assert!(limiter.is_allowed(ip2));
        assert!(limiter.is_allowed(ip3));
        assert_eq!(limiter.tracked_ip_count(), 3);

        // Adding 4th IP should evict the oldest (ip1)
        assert!(limiter.is_allowed(ip4));
        assert_eq!(limiter.tracked_ip_count(), 3);

        // ip1 should be evicted, so it gets a fresh limit
        assert!(limiter.is_allowed(ip1)); // Treated as new IP
    }

    #[test]
    fn test_rate_limiter_exact_limit() {
        let mut config = test_config();
        config.max_requests = 1;
        let mut limiter = RateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(limiter.is_allowed(ip)); // First request allowed
        assert!(!limiter.is_allowed(ip)); // Second blocked
    }

    // DNS Rate Limiter tests
    #[test]
    fn test_dns_rate_limiter_allows() {
        let mut config = DnsSecurityConfig::default();
        config.rate_limit_enabled = true;
        config.max_qps = 10;
        let mut limiter = DnsRateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..10 {
            assert!(limiter.is_allowed(ip));
        }
    }

    #[test]
    fn test_dns_rate_limiter_blocks() {
        let mut config = DnsSecurityConfig::default();
        config.rate_limit_enabled = true;
        config.max_qps = 2;
        let mut limiter = DnsRateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(limiter.is_allowed(ip));
        assert!(limiter.is_allowed(ip));
        assert!(!limiter.is_allowed(ip));
    }

    #[test]
    fn test_dns_rate_limiter_disabled() {
        let mut config = DnsSecurityConfig::default();
        config.rate_limit_enabled = false;
        config.max_qps = 1;
        let mut limiter = DnsRateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..100 {
            assert!(limiter.is_allowed(ip));
        }
    }

    #[test]
    fn test_dns_rate_limiter_cleanup() {
        let mut config = DnsSecurityConfig::default();
        config.rate_limit_enabled = true;
        config.max_qps = 10;
        let mut limiter = DnsRateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(limiter.is_allowed(ip));
        limiter.cleanup();
        // Entry may or may not exist depending on timing
    }

    #[test]
    fn test_dns_rate_limiter_multiple_ips() {
        let mut config = DnsSecurityConfig::default();
        config.rate_limit_enabled = true;
        config.max_qps = 1;
        let mut limiter = DnsRateLimiter::new(config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        assert!(limiter.is_allowed(ip1));
        assert!(!limiter.is_allowed(ip1)); // blocked

        assert!(limiter.is_allowed(ip2)); // Different IP, allowed
        assert!(!limiter.is_allowed(ip2)); // blocked
    }

    #[test]
    fn test_dns_rate_limiter_window_reset() {
        let mut config = DnsSecurityConfig::default();
        config.rate_limit_enabled = true;
        config.max_qps = 2;
        let mut limiter = DnsRateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Make queries to hit limit
        assert!(limiter.is_allowed(ip));
        assert!(limiter.is_allowed(ip));
        assert!(!limiter.is_allowed(ip)); // blocked

        // Wait for window to reset (1+ second)
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Window should be reset, allowing queries again
        assert!(limiter.is_allowed(ip));
    }

    #[test]
    fn test_dns_rate_limiter_ipv6_subnet() {
        let mut config = DnsSecurityConfig::default();
        config.rate_limit_enabled = true;
        config.max_qps = 2;
        config.ipv6_subnet_rate_limit = true;
        let mut limiter = DnsRateLimiter::new(config);

        // Same /64 subnet
        let ip1: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8:abcd:1234::ffff".parse().unwrap();

        assert!(limiter.is_allowed(ip1));
        assert!(limiter.is_allowed(ip2)); // Same /64, counts together
        assert!(!limiter.is_allowed(ip1)); // Blocked
    }

    #[test]
    fn test_dns_rate_limiter_max_tracked_ips() {
        let mut config = DnsSecurityConfig::default();
        config.rate_limit_enabled = true;
        config.max_qps = 100;
        config.max_tracked_ips = 2;
        let mut limiter = DnsRateLimiter::new(config);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();

        assert!(limiter.is_allowed(ip1));
        assert!(limiter.is_allowed(ip2));
        assert_eq!(limiter.tracked_ip_count(), 2);

        // Adding 3rd should evict oldest
        assert!(limiter.is_allowed(ip3));
        assert_eq!(limiter.tracked_ip_count(), 2);
    }

    #[test]
    fn test_normalize_ip_for_rate_limit() {
        // IPv4 should pass through unchanged
        let ipv4: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(normalize_ip_for_rate_limit(ipv4, true), ipv4);
        assert_eq!(normalize_ip_for_rate_limit(ipv4, false), ipv4);

        // IPv6 with subnet enabled should normalize to /64
        let ipv6: IpAddr = "2001:db8:1234:5678:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let expected: IpAddr = "2001:db8:1234:5678::".parse().unwrap();
        assert_eq!(normalize_ip_for_rate_limit(ipv6, true), expected);

        // IPv6 with subnet disabled should pass through
        assert_eq!(normalize_ip_for_rate_limit(ipv6, false), ipv6);
    }
}
