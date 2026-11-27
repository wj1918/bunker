//! Regression tests for the IPv4-mapped IPv6 SSRF bypass.
//!
//! Before the fix to `src/security/ip_filter.rs::is_private_ip`, addresses like
//! `::ffff:127.0.0.1` slipped through the private-IP check: the V6 branch only
//! matched `::1` / `fc00::/7` / `fe80::/10`, and `Ipv6Addr::is_loopback()`
//! does not consider mapped IPv4 loopback. These tests confirm the fix holds
//! across every SSRF entry point that consults `is_private_ip`:
//!   - `is_blocked_target` (the literal-IP CONNECT/HTTP path)
//!   - `resolved_addrs_blocked` (the pre-resolved-addresses check used by the
//!     engine, which the original reproduction didn't cover)

use bunker::config::SecurityConfig;
use bunker::security::{is_blocked_target, resolved_addrs_blocked};
use std::net::SocketAddr;

fn ssrf_security() -> SecurityConfig {
    SecurityConfig {
        block_private_ips: true,
        ..SecurityConfig::default()
    }
}

#[test]
fn is_blocked_target_blocks_mapped_loopback() {
    let s = ssrf_security();
    assert!(is_blocked_target("127.0.0.1", Some(80), &s).is_some());
    assert!(
        is_blocked_target("::ffff:127.0.0.1", Some(80), &s).is_some(),
        "::ffff:127.0.0.1 must be blocked the same as 127.0.0.1"
    );
}

#[test]
fn is_blocked_target_blocks_mapped_private_range() {
    let s = ssrf_security();
    assert!(is_blocked_target("192.168.1.1", Some(80), &s).is_some());
    assert!(
        is_blocked_target("::ffff:192.168.1.1", Some(80), &s).is_some(),
        "::ffff:192.168.1.1 must be blocked the same as 192.168.1.1"
    );
}

#[test]
fn resolved_addrs_blocked_catches_mapped_private() {
    let s = ssrf_security();
    let native: SocketAddr = "127.0.0.1:80".parse().unwrap();
    let mapped: SocketAddr = "[::ffff:127.0.0.1]:80".parse().unwrap();
    assert!(resolved_addrs_blocked(&[native], &s).is_some());
    assert!(
        resolved_addrs_blocked(&[mapped], &s).is_some(),
        "resolved_addrs_blocked must catch ::ffff:127.0.0.1"
    );
}
