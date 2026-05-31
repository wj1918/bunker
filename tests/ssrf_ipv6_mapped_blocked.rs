//! Regression tests for the IPv4-mapped IPv6 SSRF bypass.
//!
//! Before the fix to `src/security/ip_filter.rs::is_private_ip`, addresses like
//! `::ffff:127.0.0.1` slipped through the private-IP check: the V6 branch only
//! matched `::1` / `fc00::/7` / `fe80::/10`, and `Ipv6Addr::is_loopback()`
//! does not consider mapped IPv4 loopback. These tests confirm the fix holds
//! across every SSRF entry point that consults `is_private_ip`:
//!   - `is_blocked_target` (the literal-IP CONNECT/HTTP path)
//!   - `resolve_and_validate_host` (the resolve-then-validate path)
//!   - `resolved_addrs_blocked` (the pre-resolved-addresses check used by the
//!     engine, which the original reproduction didn't cover)

use bunker::config::SecurityConfig;
use bunker::dns::DnsClient;
use bunker::security::{is_blocked_target, resolve_and_validate_host, resolved_addrs_blocked};
use std::net::SocketAddr;
use std::sync::Arc;

fn ssrf_security() -> SecurityConfig {
    let mut s = SecurityConfig::default();
    s.block_private_ips = true;
    s
}

/// Literal-IP targets short-circuit before the resolver is consulted, so
/// the simplest possible DnsClient (Os variant, no cache) is enough for
/// these tests — its `resolve()` is never invoked on the literal-IP path.
fn test_dns_client() -> Arc<DnsClient> {
    Arc::new(DnsClient::new_os(None))
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

#[tokio::test]
async fn resolve_and_validate_host_blocks_mapped_loopback() {
    let s = ssrf_security();
    let dns = test_dns_client();
    assert!(resolve_and_validate_host("127.0.0.1", 80, &s, &dns)
        .await
        .is_err());
    assert!(
        resolve_and_validate_host("::ffff:127.0.0.1", 80, &s, &dns)
            .await
            .is_err(),
        "resolve_and_validate_host must reject ::ffff:127.0.0.1"
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
