//! Network interface discovery for `bunker --init lan` and `bunker --init custom`.
//!
//! Enumerates the host's IPv4 interfaces and identifies which ones look like
//! "the LAN" — i.e. carry an RFC 1918 private address, are not loopback, and
//! are not IPv4 link-local (APIPA). Interface up/down state is intentionally
//! not consulted: a NIC that's down at init time may be up at launch time, and
//! the kernel will surface a precise bind error if it isn't.

use if_addrs::{IfAddr, Interface};
use std::net::{IpAddr, Ipv4Addr};

/// A single candidate interface, ready to be baked into the generated config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanInterface {
    /// Interface name (Unix) or adapter GUID-string (Windows). Used only for
    /// human-readable diagnostics.
    pub name: String,
    /// The interface's IPv4 address — what `proxy.listen` / `dns.listen` get
    /// bound to.
    pub ip: Ipv4Addr,
    /// The interface's network in CIDR form (e.g. `192.168.5.0/24`). What
    /// `allowed_source_ips` gets set to.
    pub cidr: String,
}

/// Errors produced by `lan`-mode auto-discovery. `custom` mode never errors.
#[derive(Debug)]
pub enum DiscoveryError {
    /// The OS interface list could not be read.
    EnumerationFailed(std::io::Error),
    /// No interface matched the LAN filter (typical: cloud VM with only a
    /// public IP, container with only loopback).
    NoCandidates,
    /// More than one interface matched. The caller should display the list
    /// and ask the user to disambiguate via `bunker --init custom --listen ...`.
    MultipleCandidates(Vec<LanInterface>),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnumerationFailed(e) => write!(f, "failed to enumerate network interfaces: {}", e),
            Self::NoCandidates => write!(
                f,
                "no LAN interface detected (no non-loopback IPv4 address in 10/8, 172.16/12, or 192.168/16)"
            ),
            Self::MultipleCandidates(candidates) => {
                writeln!(f, "multiple LAN-like interfaces detected:")?;
                for c in candidates {
                    writeln!(f, "  {:<16} {}/{}", c.name, c.ip, prefix_from_cidr(&c.cidr))?;
                }
                write!(
                    f,
                    "re-run with an explicit address, e.g.:\n  bunker --init custom --listen <ip>:8080 --dns <ip>:53 --dns-upstream 9.9.9.9:53"
                )
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Pick exactly one LAN interface, or fail with a diagnostic the user can act
/// on. Used by `--init lan`. Wi-Fi interfaces are excluded — they're rarely
/// the right choice for a LAN-serving proxy, and a host with both Ethernet
/// and Wi-Fi should auto-select the wired one. Users who want Wi-Fi
/// explicitly can use `--init custom --listen <wifi-ip>:8080`.
pub fn discover_lan_interface() -> Result<LanInterface, DiscoveryError> {
    let interfaces = if_addrs::get_if_addrs().map_err(DiscoveryError::EnumerationFailed)?;
    let candidates = select_lan_candidates(&interfaces);
    match candidates.len() {
        0 => Err(DiscoveryError::NoCandidates),
        1 => Ok(candidates.into_iter().next().unwrap()),
        _ => Err(DiscoveryError::MultipleCandidates(candidates)),
    }
}

/// `filter_candidates` minus Wi-Fi adapters. Split out so the Wi-Fi exclusion
/// only applies to `--init lan` (single-NIC auto-pick), not to `--init custom`
/// with a wildcard listen address (which legitimately wants all subnets in
/// the allowlist).
fn select_lan_candidates(interfaces: &[Interface]) -> Vec<LanInterface> {
    filter_candidates(interfaces)
        .into_iter()
        .filter(|c| !is_wifi_interface(&c.name))
        .collect()
}

/// Heuristic: identify Wi-Fi adapters by name.
///
/// - Windows: default friendly name is `Wi-Fi` (or legacy `Wireless Network Connection`).
/// - Linux: predictable names start with `wl` (`wlan0`, `wlp3s0`, `wlo1`, `wls1`).
/// - macOS: Wi-Fi is conventionally `en1`, but `en*` is also Ethernet — skip.
///
/// Users who renamed their adapter or are on macOS can still force a Wi-Fi
/// listen via `--init custom`.
fn is_wifi_interface(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "wi-fi"
        || lower == "wifi"
        || lower.starts_with("wireless")
        || (lower.starts_with("wl") && lower.len() > 2)
}

/// Return every LAN-like interface on the host. Used by `--init custom` when
/// the user passed a wildcard listen address (`0.0.0.0` / `[::]`) — we union
/// all matching subnets into the allowlist so the wildcard bind is still
/// gated by a sane set of private networks.
pub fn discover_all_lan_interfaces() -> Vec<LanInterface> {
    if_addrs::get_if_addrs()
        .map(|ifs| filter_candidates(&ifs))
        .unwrap_or_default()
}

/// Look up the local interface that owns `ip` and return its CIDR. Used by
/// `--init custom` to derive the allowlist from a concrete `--listen` IP.
/// Returns `None` if no local interface has that address.
pub fn interface_for_ipv4(ip: Ipv4Addr) -> Option<LanInterface> {
    let interfaces = if_addrs::get_if_addrs().ok()?;
    interfaces.iter().find_map(|iface| {
        if let IfAddr::V4(v4) = &iface.addr {
            if v4.ip == ip {
                return Some(LanInterface {
                    name: iface.name.clone(),
                    ip: v4.ip,
                    cidr: compute_cidr(v4.ip, v4.prefixlen),
                });
            }
        }
        None
    })
}

/// Apply the LAN-candidate filter to a pre-enumerated interface list. Kept
/// separate from the live enumeration so it can be unit-tested with synthetic
/// input.
fn filter_candidates(interfaces: &[Interface]) -> Vec<LanInterface> {
    interfaces
        .iter()
        .filter_map(|iface| match &iface.addr {
            IfAddr::V4(v4) if is_lan_candidate_v4(&v4.ip) => Some(LanInterface {
                name: iface.name.clone(),
                ip: v4.ip,
                cidr: compute_cidr(v4.ip, v4.prefixlen),
            }),
            _ => None,
        })
        .collect()
}

/// Apply the three filtering rules: keep if RFC 1918, drop if loopback, drop
/// if IPv4 link-local (169.254/16 — APIPA, signals a broken network). The
/// loopback check is redundant with the RFC 1918 check (127/8 isn't in any of
/// the three blocks) but we keep it explicit so the rule reads as intended.
fn is_lan_candidate_v4(ip: &Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_link_local() && is_rfc1918(ip)
}

fn is_rfc1918(ip: &Ipv4Addr) -> bool {
    let oct = ip.octets();
    oct[0] == 10
        || (oct[0] == 172 && (16..=31).contains(&oct[1]))
        || (oct[0] == 192 && oct[1] == 168)
}

/// Compute the network address from an IP + prefix length and format as CIDR.
fn compute_cidr(ip: Ipv4Addr, prefixlen: u8) -> String {
    let net = network_address(ip, prefixlen);
    format!("{}/{}", net, prefixlen)
}

/// Mask out the host bits from `ip` to get the network address.
fn network_address(ip: Ipv4Addr, prefixlen: u8) -> Ipv4Addr {
    if prefixlen >= 32 {
        return ip;
    }
    let mask: u32 = if prefixlen == 0 {
        0
    } else {
        !0u32 << (32 - prefixlen)
    };
    Ipv4Addr::from(u32::from(ip) & mask)
}

/// Apply a /24 default to a listen IP when no matching local interface
/// exists. Used by `--init custom` for IPs the user is configuring for a
/// future deployment (e.g. an IP they're about to assign).
pub fn assume_slash_24(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => Some(compute_cidr(v4, 24)),
        IpAddr::V6(_) => None,
    }
}

fn prefix_from_cidr(cidr: &str) -> &str {
    cidr.split_once('/').map(|(_, p)| p).unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;
    use if_addrs::Ifv4Addr;

    fn iface_v4(name: &str, ip: &str, prefixlen: u8) -> Interface {
        let ip: Ipv4Addr = ip.parse().unwrap();
        let mask_bits: u32 = if prefixlen == 0 {
            0
        } else {
            !0u32 << (32 - prefixlen)
        };
        Interface {
            name: name.to_string(),
            addr: IfAddr::V4(Ifv4Addr {
                ip,
                netmask: Ipv4Addr::from(mask_bits),
                prefixlen,
                broadcast: None,
            }),
            index: Some(1),
            #[cfg(windows)]
            adapter_name: String::new(),
        }
    }

    #[test]
    fn rfc1918_class_a() {
        assert!(is_rfc1918(&"10.0.0.1".parse().unwrap()));
        assert!(is_rfc1918(&"10.255.255.255".parse().unwrap()));
    }

    #[test]
    fn rfc1918_class_b() {
        assert!(is_rfc1918(&"172.16.0.1".parse().unwrap()));
        assert!(is_rfc1918(&"172.31.255.255".parse().unwrap()));
        assert!(!is_rfc1918(&"172.15.0.1".parse().unwrap()));
        assert!(!is_rfc1918(&"172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn rfc1918_class_c() {
        assert!(is_rfc1918(&"192.168.0.1".parse().unwrap()));
        assert!(is_rfc1918(&"192.168.255.255".parse().unwrap()));
        assert!(!is_rfc1918(&"192.169.0.1".parse().unwrap()));
    }

    #[test]
    fn rfc1918_rejects_public() {
        assert!(!is_rfc1918(&"8.8.8.8".parse().unwrap()));
        assert!(!is_rfc1918(&"100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn lan_candidate_rejects_loopback() {
        assert!(!is_lan_candidate_v4(&"127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn lan_candidate_rejects_link_local() {
        assert!(!is_lan_candidate_v4(&"169.254.34.122".parse().unwrap()));
    }

    #[test]
    fn lan_candidate_accepts_rfc1918() {
        assert!(is_lan_candidate_v4(&"192.168.5.42".parse().unwrap()));
        assert!(is_lan_candidate_v4(&"10.5.0.17".parse().unwrap()));
        assert!(is_lan_candidate_v4(&"172.20.4.3".parse().unwrap()));
    }

    #[test]
    fn network_address_basic() {
        let ip: Ipv4Addr = "192.168.5.42".parse().unwrap();
        assert_eq!(network_address(ip, 24).to_string(), "192.168.5.0");
        assert_eq!(network_address(ip, 16).to_string(), "192.168.0.0");
        assert_eq!(network_address(ip, 8).to_string(), "192.0.0.0");
    }

    #[test]
    fn network_address_edge_prefixes() {
        let ip: Ipv4Addr = "192.168.5.42".parse().unwrap();
        assert_eq!(network_address(ip, 0).to_string(), "0.0.0.0");
        assert_eq!(network_address(ip, 32).to_string(), "192.168.5.42");
    }

    #[test]
    fn compute_cidr_basic() {
        assert_eq!(
            compute_cidr("192.168.5.42".parse().unwrap(), 24),
            "192.168.5.0/24"
        );
        assert_eq!(
            compute_cidr("10.5.0.17".parse().unwrap(), 16),
            "10.5.0.0/16"
        );
        assert_eq!(
            compute_cidr("172.20.4.3".parse().unwrap(), 22),
            "172.20.4.0/22"
        );
    }

    #[test]
    fn filter_candidates_single_match() {
        let ifs = vec![
            iface_v4("lo", "127.0.0.1", 8),
            iface_v4("eth0", "192.168.5.42", 24),
        ];
        let got = filter_candidates(&ifs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "eth0");
        assert_eq!(got[0].cidr, "192.168.5.0/24");
    }

    #[test]
    fn filter_candidates_drops_link_local() {
        let ifs = vec![
            iface_v4("lo", "127.0.0.1", 8),
            iface_v4("wlan0", "169.254.34.122", 16),
        ];
        assert!(filter_candidates(&ifs).is_empty());
    }

    #[test]
    fn filter_candidates_multi_nic() {
        let ifs = vec![
            iface_v4("lo", "127.0.0.1", 8),
            iface_v4("eth0", "192.168.1.5", 24),
            iface_v4("wlan0", "192.168.5.10", 24),
            iface_v4("tun0", "10.8.0.3", 24),
        ];
        let got = filter_candidates(&ifs);
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn filter_candidates_rejects_public_ipv4() {
        let ifs = vec![
            iface_v4("eth0", "1.2.3.4", 24), // public IP on a cloud VM
        ];
        assert!(filter_candidates(&ifs).is_empty());
    }

    #[test]
    fn assume_slash_24_basic() {
        let ip: IpAddr = "10.20.30.40".parse().unwrap();
        assert_eq!(assume_slash_24(ip).unwrap(), "10.20.30.0/24");
    }

    #[test]
    fn assume_slash_24_returns_none_for_v6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(assume_slash_24(ip).is_none());
    }

    #[test]
    fn is_wifi_interface_matches_windows_default() {
        assert!(is_wifi_interface("Wi-Fi"));
        assert!(is_wifi_interface("wi-fi"));
        assert!(is_wifi_interface("WI-FI"));
        assert!(is_wifi_interface("Wireless Network Connection"));
    }

    #[test]
    fn is_wifi_interface_matches_linux_names() {
        assert!(is_wifi_interface("wlan0"));
        assert!(is_wifi_interface("wlan1"));
        assert!(is_wifi_interface("wlp3s0"));
        assert!(is_wifi_interface("wlo1"));
        assert!(is_wifi_interface("wls1"));
    }

    #[test]
    fn is_wifi_interface_rejects_ethernet() {
        assert!(!is_wifi_interface("Ethernet"));
        assert!(!is_wifi_interface("eth0"));
        assert!(!is_wifi_interface("enp0s3"));
        assert!(!is_wifi_interface("en0"));
        assert!(!is_wifi_interface("tun0"));
        assert!(!is_wifi_interface("lo"));
    }

    #[test]
    fn is_wifi_interface_rejects_short_wl() {
        // `wl` alone is too short to be a real wireless interface name —
        // every real predictable name has at least one trailing character.
        assert!(!is_wifi_interface("wl"));
    }

    #[test]
    fn select_lan_candidates_drops_wifi_with_ethernet() {
        let ifs = vec![
            iface_v4("Ethernet", "192.168.1.5", 24),
            iface_v4("Wi-Fi", "10.0.0.146", 24),
        ];
        let got = select_lan_candidates(&ifs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "Ethernet");
    }

    #[test]
    fn select_lan_candidates_drops_wifi_linux() {
        let ifs = vec![
            iface_v4("eth0", "192.168.1.5", 24),
            iface_v4("wlan0", "192.168.5.10", 24),
            iface_v4("wlp3s0", "10.0.0.1", 24),
        ];
        let got = select_lan_candidates(&ifs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "eth0");
    }

    #[test]
    fn select_lan_candidates_empty_when_only_wifi() {
        let ifs = vec![iface_v4("Wi-Fi", "10.0.0.146", 24)];
        assert!(select_lan_candidates(&ifs).is_empty());
    }

    #[test]
    fn discover_all_still_includes_wifi() {
        // `--init custom 0.0.0.0` allowlist derivation must keep Wi-Fi —
        // it's only `--init lan` that excludes wireless.
        let ifs = vec![
            iface_v4("Ethernet", "192.168.1.5", 24),
            iface_v4("Wi-Fi", "10.0.0.146", 24),
        ];
        let got = filter_candidates(&ifs);
        assert_eq!(got.len(), 2);
    }
}
