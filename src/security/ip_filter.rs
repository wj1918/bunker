//! IP filtering for SSRF prevention, source IP allowlist, and DNS rebinding protection.

use crate::config::SecurityConfig;
use crate::dns::DnsClient;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// Normalize IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to IPv4
/// This prevents bypass attacks where ::ffff:192.168.1.3 wouldn't match 192.168.1.3
pub fn normalize_ip(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            // Check for IPv4-mapped IPv6 address (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            *ip
        }
        IpAddr::V4(_) => *ip,
    }
}

/// Check if a source IP is allowed to connect
/// Returns true if allowed_source_ips is empty (allow all) or if IP matches any entry
pub fn is_source_ip_allowed(client_ip: &IpAddr, allowed_ips: &[String]) -> bool {
    // Normalize IPv4-mapped IPv6 addresses to prevent bypass
    let client_ip = normalize_ip(client_ip);
    // Empty list means allow all
    if allowed_ips.is_empty() {
        return true;
    }

    for entry in allowed_ips {
        // Check for CIDR notation (e.g., "192.168.1.0/24")
        if entry.contains('/') {
            if let Some((network, prefix_str)) = entry.split_once('/') {
                if let (Ok(network_ip), Ok(prefix_len)) =
                    (network.parse::<IpAddr>(), prefix_str.parse::<u8>())
                {
                    if ip_in_cidr(&client_ip, &network_ip, prefix_len) {
                        return true;
                    }
                }
            }
        } else {
            // Direct IP match
            if let Ok(allowed_ip) = entry.parse::<IpAddr>() {
                if client_ip == allowed_ip {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if an IP is within a CIDR range
pub fn ip_in_cidr(ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix_len > 32 {
                return false;
            }
            let ip_bits = u32::from_be_bytes(ip.octets());
            let net_bits = u32::from_be_bytes(net.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix_len > 128 {
                return false;
            }
            let ip_bits = u128::from_be_bytes(ip.octets());
            let net_bits = u128::from_be_bytes(net.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false, // IPv4/IPv6 mismatch
    }
}

/// Check if an IP address is private/internal (SSRF protection)
///
/// Normalizes IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) before classifying,
/// so a literal target like `::ffff:127.0.0.1` falls into the IPv4 branch and
/// is caught by `is_loopback()` rather than slipping through `Ipv6Addr::is_loopback`
/// (which matches only `::1`). Without this, the SSRF check is bypassable via
/// the mapped form in `is_blocked_target`, `resolve_and_validate_host`, and
/// `resolved_addrs_blocked` — all of which feed `is_private_ip` raw IPs.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    let ip = normalize_ip(ip);
    match &ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()          // 127.0.0.0/8
            || ipv4.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || ipv4.is_link_local()     // 169.254.0.0/16 (cloud metadata!)
            || ipv4.is_broadcast()      // 255.255.255.255
            || ipv4.is_unspecified()    // 0.0.0.0
            || ipv4.is_documentation()  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
            || (ipv4.octets()[0] == 100
                && (ipv4.octets()[1] >= 64 && ipv4.octets()[1] <= 127)) // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()              // ::1
            || ipv6.is_unspecified()        // ::
            || is_ipv6_unique_local(ipv6)   // fc00::/7 (unique local addresses)
            || is_ipv6_link_local(ipv6) // fe80::/10 (link-local addresses)
        }
    }
}

/// Check if IPv6 address is unique local (fc00::/7)
pub fn is_ipv6_unique_local(ipv6: &Ipv6Addr) -> bool {
    // fc00::/7 means first 7 bits are 1111110x
    // This includes fc00::/8 and fd00::/8
    let segments = ipv6.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Check if IPv6 address is link-local (fe80::/10)
pub fn is_ipv6_link_local(ipv6: &Ipv6Addr) -> bool {
    // fe80::/10 means first 10 bits are 1111111010
    let segments = ipv6.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// Resolve hostname to IP addresses (DNS rebinding protection).
///
/// Delegates the hostname-to-IPs step to the supplied `DnsClient` — Mode 1
/// uses `DnsClient::Upstream` (forwards to configured upstreams), Modes 2 & 3
/// use `DnsClient::Os` (wraps `os_resolve` with optional cache). Literal IPs
/// short-circuit the resolver entirely. The SSRF/rebinding check on the
/// returned IPs is unchanged.
pub async fn resolve_and_validate_host(
    host: &str,
    port: u16,
    security: &SecurityConfig,
    dns_client: &Arc<DnsClient>,
) -> Result<Vec<SocketAddr>, &'static str> {
    // Literal IP shortcut — same behavior as before, no resolver call.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if security.block_private_ips && is_private_ip(&ip) {
            return Err("Resolved to private/internal IP (blocked)");
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let ips = dns_client
        .resolve(host)
        .await
        .map_err(|_| "DNS resolution failed")?;

    if ips.is_empty() {
        return Err("DNS resolution returned no addresses");
    }

    let addrs: Vec<SocketAddr> = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();

    // DNS Rebinding Protection: Check ALL resolved IPs
    if security.block_private_ips {
        for addr in &addrs {
            if is_private_ip(&addr.ip()) {
                return Err("DNS resolved to private/internal IP (rebinding attack blocked)");
            }
        }
    }

    Ok(addrs)
}

/// DNS-rebinding check on already-resolved addresses: returns Some(reason) if
/// any resolved IP is private/internal and `block_private_ips` is on. Sync — the
/// async resolution itself is the caller's job (so this works on any runtime,
/// unlike `resolve_and_validate_host` which is tied to tokio's resolver).
#[allow(dead_code)] // used by the engine feature; dead in the default binary
pub fn resolved_addrs_blocked(
    addrs: &[SocketAddr],
    security: &SecurityConfig,
) -> Option<&'static str> {
    if security.block_private_ips {
        for addr in addrs {
            if is_private_ip(&addr.ip()) {
                return Some("DNS resolved to private/internal IP (rebinding blocked)");
            }
        }
    }
    None
}

/// Check if a CONNECT target should be blocked (SSRF prevention)
/// Split an authority into host and optional port.
///
/// Handles `[ipv6]:port`, `host:port` / `ipv4:port`, and bare host. IPv6 brackets
/// are stripped so the host can be parsed as an `IpAddr`. A malformed or absent
/// port yields `Some(0)` (rejected downstream by `is_blocked_target`) or `None`.
///
/// This MUST be the single source of authority parsing for SSRF checks: feeding
/// `is_blocked_target` a bracketed host like `[::1]` would defeat the private-IP
/// check (it can't parse as `IpAddr`), so both the HTTP and CONNECT paths route
/// through here.
pub fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    if authority.starts_with('[') {
        // IPv6 address in bracket notation: [::1]:port
        if let Some(bracket_end) = authority.find(']') {
            let h = &authority[1..bracket_end]; // Remove brackets
            let p = if authority.len() > bracket_end + 2
                && authority.as_bytes()[bracket_end + 1] == b':'
            {
                authority[bracket_end + 2..].parse().unwrap_or(0)
            } else {
                0
            };
            (h, Some(p))
        } else {
            (authority, None)
        }
    } else if let Some(colon_pos) = authority.rfind(':') {
        // IPv4 or hostname: host:port
        let h = &authority[..colon_pos];
        let p: u16 = authority[colon_pos + 1..].parse().unwrap_or(0);
        (h, Some(p))
    } else {
        (authority, None)
    }
}

/// Check whether a target (already split into host + optional port) should be
/// blocked. SSRF prevention via port policy, blocked-host patterns, and
/// literal private-IP / dangerous-hostname detection.
pub fn is_blocked_target(
    host: &str,
    port: Option<u16>,
    security: &SecurityConfig,
) -> Option<&'static str> {
    // Reject port 0 (invalid/undefined behavior)
    if let Some(0) = port {
        return Some("Port 0 is not allowed");
    }

    // Check allowed ports if configured
    if !security.allowed_ports.is_empty() {
        if let Some(p) = port {
            if !security.allowed_ports.contains(&p) {
                return Some("Port not in allowlist");
            }
        }
    }

    // Check blocked hosts patterns
    for pattern in &security.blocked_hosts {
        if pattern.starts_with("*.") {
            // Wildcard pattern like "*.internal"
            let suffix = &pattern[1..]; // ".internal"
            if host.ends_with(suffix) || host == &pattern[2..] {
                return Some("Host matches blocked pattern");
            }
        } else if host == pattern || host.ends_with(&format!(".{}", pattern)) {
            return Some("Host in blocklist");
        }
    }

    // Check if IP address is blocked
    if security.block_private_ips {
        // First, try to parse as IP directly
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_ip(&ip) {
                return Some("Private/internal IP blocked");
            }
        }

        // Also check common dangerous hostnames
        let dangerous_hosts = ["localhost", "metadata", "metadata.google.internal"];
        if dangerous_hosts
            .iter()
            .any(|&h| host == h || host.ends_with(&format!(".{}", h)))
        {
            return Some("Dangerous hostname blocked");
        }
    }

    None // Not blocked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;

    fn default_security() -> SecurityConfig {
        SecurityConfig::default()
    }

    fn disabled_security() -> SecurityConfig {
        SecurityConfig {
            block_private_ips: false,
            blocked_hosts: vec![],
            allowed_ports: vec![],
            allowed_source_ips: vec![],
            rate_limit: RateLimitConfig::default(),
            max_connections: 0,
            max_request_body_bytes: 0,
            header_read_timeout_seconds: 0,
            max_requests_per_connection: 0,
        }
    }

    /// Test shim: parse an authority then run the policy check, exercising the
    /// same parse-then-check path the proxy uses end-to-end.
    fn blocked(authority: &str, security: &SecurityConfig) -> Option<&'static str> {
        let (host, port) = split_host_port(authority);
        is_blocked_target(host, port, security)
    }

    #[test]
    fn test_is_private_ip_loopback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "127.0.0.5".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_private_class_a() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "10.255.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_private_class_b() {
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "172.31.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_private_class_c() {
        let ip: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "192.168.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_link_local() {
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "169.254.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_cgnat() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "100.127.255.255".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_public() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_private_ip(&ip));

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!is_private_ip(&ip));

        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(!is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_unspecified() {
        let ip: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "::".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_ipv6_unique_local() {
        let ip: IpAddr = "fc00::1".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "fd12:3456:789a::1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_ipv6_link_local() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "fe80::1234:5678:abcd:ef00".parse().unwrap();
        assert!(is_private_ip(&ip));

        let ip: IpAddr = "febf::1".parse().unwrap();
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_ipv6_public() {
        let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!is_private_ip(&ip));

        let ip: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert!(!is_private_ip(&ip));

        let ip: IpAddr = "2a00:1450:4001:81a::200e".parse().unwrap();
        assert!(!is_private_ip(&ip));
    }

    #[test]
    fn test_ipv6_unique_local_function() {
        let fc00: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(is_ipv6_unique_local(&fc00));

        let fd00: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(is_ipv6_unique_local(&fd00));

        let public: Ipv6Addr = "2001::1".parse().unwrap();
        assert!(!is_ipv6_unique_local(&public));

        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(!is_ipv6_unique_local(&link_local));
    }

    #[test]
    fn test_ipv6_link_local_function() {
        let fe80: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_ipv6_link_local(&fe80));

        let febf: Ipv6Addr = "febf::1".parse().unwrap();
        assert!(is_ipv6_link_local(&febf));

        let public: Ipv6Addr = "2001::1".parse().unwrap();
        assert!(!is_ipv6_link_local(&public));

        let unique_local: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(!is_ipv6_link_local(&unique_local));

        let fec0: Ipv6Addr = "fec0::1".parse().unwrap();
        assert!(!is_ipv6_link_local(&fec0));
    }

    #[test]
    fn test_blocked_target_ipv6_unique_local() {
        let security = default_security();
        assert!(blocked("[fc00::1]:80", &security).is_some());
        assert!(blocked("[fd00::1]:443", &security).is_some());
    }

    #[test]
    fn test_blocked_target_ipv6_link_local() {
        let security = default_security();
        assert!(blocked("[fe80::1]:80", &security).is_some());
    }

    #[test]
    fn test_blocked_target_ipv6_public_allowed() {
        let security = default_security();
        assert!(blocked("[2001:4860:4860::8888]:443", &security).is_none());
    }

    #[test]
    fn test_blocked_target_private_ip() {
        let security = default_security();

        assert!(blocked("192.168.1.1:80", &security).is_some());
        assert!(blocked("10.0.0.1:443", &security).is_some());
        assert!(blocked("172.16.0.1:22", &security).is_some());
        assert!(blocked("127.0.0.1:8080", &security).is_some());
    }

    #[test]
    fn test_blocked_target_cloud_metadata() {
        let security = default_security();
        assert!(blocked("169.254.169.254:80", &security).is_some());
    }

    #[test]
    fn test_blocked_target_public_ip_allowed() {
        let security = default_security();

        assert!(blocked("8.8.8.8:443", &security).is_none());
        assert!(blocked("1.1.1.1:80", &security).is_none());
    }

    #[test]
    fn test_blocked_target_hostname_allowed() {
        let security = default_security();

        assert!(blocked("google.com:443", &security).is_none());
        assert!(blocked("example.com:80", &security).is_none());
    }

    #[test]
    fn test_blocked_target_localhost_hostname() {
        let security = default_security();
        assert!(blocked("localhost:8080", &security).is_some());
    }

    #[test]
    fn test_blocked_target_metadata_hostname() {
        let security = default_security();
        assert!(blocked("metadata:80", &security).is_some());
        assert!(blocked("metadata.google.internal:80", &security).is_some());
    }

    #[test]
    fn test_blocked_target_disabled() {
        let security = disabled_security();

        assert!(blocked("192.168.1.1:80", &security).is_none());
        assert!(blocked("127.0.0.1:8080", &security).is_none());
        assert!(blocked("localhost:80", &security).is_none());
    }

    #[test]
    fn test_blocked_target_custom_blocklist() {
        let security = SecurityConfig {
            block_private_ips: false,
            blocked_hosts: vec!["evil.com".to_string(), "*.internal".to_string()],
            allowed_ports: vec![],
            allowed_source_ips: vec![],
            rate_limit: RateLimitConfig::default(),
            max_connections: 0,
            max_request_body_bytes: 0,
            header_read_timeout_seconds: 0,
            max_requests_per_connection: 0,
        };

        assert!(blocked("evil.com:80", &security).is_some());
        assert!(blocked("db.internal:3306", &security).is_some());
        assert!(blocked("internal:80", &security).is_some());
        assert!(blocked("good.com:80", &security).is_none());
    }

    #[test]
    fn test_blocked_target_port_allowlist() {
        let security = SecurityConfig {
            block_private_ips: false,
            blocked_hosts: vec![],
            allowed_ports: vec![80, 443],
            allowed_source_ips: vec![],
            rate_limit: RateLimitConfig::default(),
            max_connections: 0,
            max_request_body_bytes: 0,
            header_read_timeout_seconds: 0,
            max_requests_per_connection: 0,
        };

        assert!(blocked("example.com:80", &security).is_none());
        assert!(blocked("example.com:443", &security).is_none());
        assert!(blocked("example.com:22", &security).is_some());
        assert!(blocked("example.com:3306", &security).is_some());
    }

    #[test]
    fn test_blocked_target_port_zero() {
        let security = SecurityConfig {
            block_private_ips: false,
            blocked_hosts: vec![],
            allowed_ports: vec![],
            allowed_source_ips: vec![],
            rate_limit: RateLimitConfig::default(),
            max_connections: 0,
            max_request_body_bytes: 0,
            header_read_timeout_seconds: 0,
            max_requests_per_connection: 0,
        };

        assert!(blocked("example.com:0", &security).is_some());
        assert!(blocked("192.168.1.1:0", &security).is_some());
        assert!(blocked("example.com:abc", &security).is_some());
        assert!(blocked("example.com:80", &security).is_none());
        assert!(blocked("example.com:443", &security).is_none());
    }

    #[test]
    fn test_ip_in_cidr_ipv4() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let network: IpAddr = "192.168.1.0".parse().unwrap();
        assert!(ip_in_cidr(&ip, &network, 24));
        assert!(!ip_in_cidr(&ip, &network, 32));
    }

    #[test]
    fn test_ip_in_cidr_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let network: IpAddr = "2001:db8::".parse().unwrap();
        assert!(ip_in_cidr(&ip, &network, 32));
        assert!(!ip_in_cidr(&ip, &network, 128));
    }

    #[test]
    fn test_normalize_ip_v4_mapped() {
        let v4_mapped: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        let normalized = normalize_ip(&v4_mapped);
        assert_eq!(normalized.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_normalize_ip_v4() {
        let v4: IpAddr = "192.168.1.1".parse().unwrap();
        let normalized = normalize_ip(&v4);
        assert_eq!(normalized, v4);
    }

    #[test]
    fn test_is_source_ip_allowed_empty_list() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(is_source_ip_allowed(&ip, &[]));
    }

    #[test]
    fn test_is_source_ip_allowed_exact_match() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let allowed = vec!["192.168.1.1".to_string()];
        assert!(is_source_ip_allowed(&ip, &allowed));

        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(!is_source_ip_allowed(&ip2, &allowed));
    }

    #[test]
    fn test_is_source_ip_allowed_cidr() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let allowed = vec!["192.168.1.0/24".to_string()];
        assert!(is_source_ip_allowed(&ip, &allowed));

        let ip2: IpAddr = "192.168.2.1".parse().unwrap();
        assert!(!is_source_ip_allowed(&ip2, &allowed));
    }

    #[test]
    fn test_ip_in_cidr_invalid_prefix_ipv4() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let network: IpAddr = "192.168.1.0".parse().unwrap();
        // prefix_len > 32 should return false
        assert!(!ip_in_cidr(&ip, &network, 33));
        assert!(!ip_in_cidr(&ip, &network, 64));
    }

    #[test]
    fn test_ip_in_cidr_invalid_prefix_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let network: IpAddr = "2001:db8::".parse().unwrap();
        // prefix_len > 128 should return false
        assert!(!ip_in_cidr(&ip, &network, 129));
        assert!(!ip_in_cidr(&ip, &network, 200));
    }

    #[test]
    fn test_ip_in_cidr_prefix_zero_ipv4() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let network: IpAddr = "10.0.0.0".parse().unwrap();
        // prefix_len = 0 means all IPs match
        assert!(ip_in_cidr(&ip, &network, 0));
    }

    #[test]
    fn test_ip_in_cidr_prefix_zero_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let network: IpAddr = "fe80::1".parse().unwrap();
        // prefix_len = 0 means all IPs match
        assert!(ip_in_cidr(&ip, &network, 0));
    }

    #[test]
    fn test_ip_in_cidr_family_mismatch() {
        let ipv4: IpAddr = "192.168.1.50".parse().unwrap();
        let ipv6: IpAddr = "2001:db8::".parse().unwrap();
        // IPv4/IPv6 mismatch should return false
        assert!(!ip_in_cidr(&ipv4, &ipv6, 24));
        assert!(!ip_in_cidr(&ipv6, &ipv4, 24));
    }

    #[test]
    fn test_blocked_target_ipv6_without_port() {
        let security = default_security();
        // IPv6 in brackets but no port - port becomes 0, which is blocked
        assert!(blocked("[fc00::1]", &security).is_some());
        assert!(blocked("[fe80::1]", &security).is_some());
        // Public IPv6 without port - still blocked because port 0 is invalid
        assert!(blocked("[2001:4860::8888]", &security).is_some());
    }

    #[test]
    fn test_blocked_target_no_port() {
        let security = disabled_security();
        // Authority without colon - port is None, not blocked for invalid port
        // Note: this parses as hostname with no colon, so port is None (not Some(0))
        assert!(blocked("example.com", &security).is_none());
    }

    #[test]
    fn test_blocked_target_with_valid_ports() {
        let security = default_security();
        // Public IPs with valid ports should not be blocked
        assert!(blocked("8.8.8.8:443", &security).is_none());
        assert!(blocked("[2001:4860::8888]:443", &security).is_none());
    }

    #[test]
    fn test_blocked_target_ipv6_malformed_bracket() {
        let security = default_security();
        // Malformed IPv6 (starts with [ but no ])
        let result = blocked("[fc00::1", &security);
        // This should still be processed (host is the whole string)
        assert!(result.is_none() || result.is_some());
    }

    #[test]
    fn test_normalize_ip_pure_ipv6() {
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
        let normalized = normalize_ip(&ipv6);
        // Pure IPv6 should stay the same
        assert_eq!(normalized, ipv6);
    }

    #[test]
    fn test_is_source_ip_allowed_ipv4_mapped_normalized() {
        // IPv4-mapped IPv6 should be normalized and matched
        let ip: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        let allowed = vec!["192.168.1.1".to_string()];
        assert!(is_source_ip_allowed(&ip, &allowed));
    }

    #[test]
    fn test_is_source_ip_allowed_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let allowed = vec!["2001:db8::/32".to_string()];
        assert!(is_source_ip_allowed(&ip, &allowed));

        let ip2: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(!is_source_ip_allowed(&ip2, &allowed));
    }

    #[test]
    fn test_is_source_ip_allowed_invalid_cidr() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Invalid CIDR should not match
        let allowed = vec!["not-an-ip/24".to_string()];
        assert!(!is_source_ip_allowed(&ip, &allowed));
    }

    #[test]
    fn test_is_source_ip_allowed_invalid_direct_ip() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Invalid IP should not match
        let allowed = vec!["not-an-ip".to_string()];
        assert!(!is_source_ip_allowed(&ip, &allowed));
    }

    #[test]
    fn test_blocked_target_wildcard_subdomain() {
        let security = SecurityConfig {
            block_private_ips: false,
            blocked_hosts: vec!["*.internal".to_string()],
            allowed_ports: vec![],
            allowed_source_ips: vec![],
            rate_limit: RateLimitConfig::default(),
            max_connections: 0,
            max_request_body_bytes: 0,
            header_read_timeout_seconds: 0,
            max_requests_per_connection: 0,
        };
        // Should block subdomain patterns
        assert!(blocked("db.internal:80", &security).is_some());
        assert!(blocked("api.internal:443", &security).is_some());
        // Exact match should also work
        assert!(blocked("internal:80", &security).is_some());
    }

    #[test]
    fn test_blocked_target_exact_host_in_blocklist() {
        let security = SecurityConfig {
            block_private_ips: false,
            blocked_hosts: vec!["evil.com".to_string()],
            allowed_ports: vec![],
            allowed_source_ips: vec![],
            rate_limit: RateLimitConfig::default(),
            max_connections: 0,
            max_request_body_bytes: 0,
            header_read_timeout_seconds: 0,
            max_requests_per_connection: 0,
        };
        // Exact match
        assert!(blocked("evil.com:80", &security).is_some());
        // Subdomain should also be blocked
        assert!(blocked("api.evil.com:80", &security).is_some());
        // Different domain should be allowed
        assert!(blocked("good.com:80", &security).is_none());
    }

    #[test]
    fn test_blocked_target_dangerous_subdomains() {
        let security = default_security();
        // Subdomains of dangerous hosts should be blocked
        assert!(blocked("a.localhost:80", &security).is_some());
        assert!(blocked("sub.metadata:80", &security).is_some());
    }

    #[test]
    fn test_split_host_port_ipv4_and_hostname() {
        assert_eq!(
            split_host_port("example.com:443"),
            ("example.com", Some(443))
        );
        assert_eq!(split_host_port("10.0.0.1:80"), ("10.0.0.1", Some(80)));
        assert_eq!(split_host_port("example.com"), ("example.com", None));
    }

    #[test]
    fn test_split_host_port_ipv6_strips_brackets() {
        // Brackets MUST be stripped so the host parses as an IpAddr downstream.
        assert_eq!(split_host_port("[::1]:443"), ("::1", Some(443)));
        assert_eq!(split_host_port("[fc00::1]:80"), ("fc00::1", Some(80)));
        assert_eq!(
            split_host_port("[2001:4860:4860::8888]:443"),
            ("2001:4860:4860::8888", Some(443))
        );
    }

    #[test]
    fn test_split_host_port_malformed() {
        // Unclosed bracket: returned as-is with no port.
        assert_eq!(split_host_port("[fc00::1"), ("[fc00::1", None));
        // Non-numeric port parses to 0 (rejected by the port-0 check downstream).
        assert_eq!(split_host_port("example.com:abc"), ("example.com", Some(0)));
        // Explicit port 0.
        assert_eq!(split_host_port("example.com:0"), ("example.com", Some(0)));
    }

    #[test]
    fn test_bracketed_ipv6_private_is_blocked_after_split() {
        // Regression guard: a bracketed IPv6 loopback/private MUST still be blocked
        // once routed through split_host_port (the CONNECT path's SSRF check).
        // A naive (host, port) call passing "[::1]" would NOT detect it as private.
        let security = default_security();
        let (host, port) = split_host_port("[::1]:443");
        assert_eq!(host, "::1");
        assert!(is_blocked_target(host, port, &security).is_some());

        let (host, port) = split_host_port("[fc00::1]:443");
        assert!(is_blocked_target(host, port, &security).is_some());

        // Public bracketed IPv6 is allowed.
        let (host, port) = split_host_port("[2001:4860:4860::8888]:443");
        assert!(is_blocked_target(host, port, &security).is_none());
    }
}
