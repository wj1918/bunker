//! Configuration types and loading for the proxy.

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// Default config.yaml embedded at compile time
pub const DEFAULT_CONFIG_YAML: &str = include_str!("../../config.yaml");

/// Override applied to `proxy.security.allowed_source_ips` by
/// `customize_default_config`. The shipped template's example lines below the
/// list are discarded when an override is in effect.
pub struct AllowlistOverride<'a> {
    /// The CIDR / IP strings written into the list, in order.
    pub entries: &'a [String],
    /// Optional comment line emitted as the first child of the list (without
    /// the leading `# `). Useful for explaining *why* the values were chosen.
    pub annotation: Option<&'a str>,
}

/// Produce a customized copy of `DEFAULT_CONFIG_YAML` with any of the listed
/// values substituted in-place. Comments and unrelated formatting in the
/// embedded template are preserved.
///
/// * `proxy_listen` — replaces `proxy.listen`.
/// * `dns_listen` — replaces `dns.listen`.
/// * `dns_upstream` — replaces the entire `dns.upstreams` list with a single
///   entry. Commented-out backup entries inside the block are discarded; the
///   singular `# upstream:` line outside the block is left alone.
/// * `allowed_source_ips` — replaces the entire
///   `proxy.security.allowed_source_ips` list. Example comment lines that
///   ship inside the block are discarded; surrounding comments are preserved.
///
/// The output is not parsed here — callers that care about validity should
/// run it through `serde_yaml_ng::from_str::<Config>`.
pub fn customize_default_config(
    proxy_listen: Option<&str>,
    dns_listen: Option<&str>,
    dns_upstream: Option<&str>,
    allowed_source_ips: Option<&AllowlistOverride>,
) -> String {
    let mut out = String::with_capacity(DEFAULT_CONFIG_YAML.len() + 64);
    let mut current_section: Option<&str> = None;
    let mut suppressing_upstreams = false;
    let mut suppressing_allowed_source_ips = false;

    for line in DEFAULT_CONFIG_YAML.lines() {
        // Track which top-level section we're in. A top-level key is a line
        // that starts at column 0 with `name:` (lowercase + underscore).
        if let Some(name) = top_level_section_name(line) {
            current_section = Some(name);
            suppressing_upstreams = false;
            suppressing_allowed_source_ips = false;
        }

        // If we just replaced an `upstreams:` block, swallow its continuation
        // lines (indented list items or commented-out items at indent >= 4).
        if suppressing_upstreams {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            if indent >= 4 && (trimmed.starts_with('-') || trimmed.starts_with('#')) {
                continue;
            }
            suppressing_upstreams = false;
        }

        // Same idea for the `allowed_source_ips:` block. Items are at
        // indent 6 (`      - "..."`) but the shipped example comments are at
        // indent 4 (`    # Example LAN deployment...`), so we accept both.
        // The blank line after the example block ends suppression naturally.
        if suppressing_allowed_source_ips {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            if indent >= 4 && (trimmed.starts_with('-') || trimmed.starts_with('#')) {
                continue;
            }
            suppressing_allowed_source_ips = false;
        }

        let section = current_section;

        if section == Some("proxy") {
            if let Some(new_value) = proxy_listen {
                if let Some(replaced) = replace_listen_line(line, new_value) {
                    out.push_str(&replaced);
                    out.push('\n');
                    continue;
                }
            }
            if let Some(override_) = allowed_source_ips {
                let trimmed = line.trim_start();
                let indent = line.len() - trimmed.len();
                if indent == 4 && trimmed.starts_with("allowed_source_ips:") {
                    out.push_str("    allowed_source_ips:\n");
                    if let Some(comment) = override_.annotation {
                        out.push_str("      # ");
                        out.push_str(comment);
                        out.push('\n');
                    }
                    for entry in override_.entries {
                        out.push_str("      - \"");
                        out.push_str(entry);
                        out.push_str("\"\n");
                    }
                    suppressing_allowed_source_ips = true;
                    continue;
                }
            }
        }

        if section == Some("dns") {
            if let Some(new_value) = dns_listen {
                if let Some(replaced) = replace_listen_line(line, new_value) {
                    out.push_str(&replaced);
                    out.push('\n');
                    continue;
                }
            }
            if let Some(new_value) = dns_upstream {
                let trimmed = line.trim_start();
                let indent = line.len() - trimmed.len();
                if indent == 2 && trimmed.starts_with("upstreams:") {
                    out.push_str("  upstreams:\n");
                    out.push_str("    - \"");
                    out.push_str(new_value);
                    out.push_str("\"\n");
                    suppressing_upstreams = true;
                    continue;
                }
            }
        }

        out.push_str(line);
        out.push('\n');
    }

    out
}

fn top_level_section_name(line: &str) -> Option<&str> {
    if line.is_empty() || line.starts_with(|c: char| c.is_whitespace() || c == '#') {
        return None;
    }
    let colon = line.find(':')?;
    let name = &line[..colon];
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
        Some(name)
    } else {
        None
    }
}

fn replace_listen_line(line: &str, new_value: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let indent = line.len() - trimmed.len();
    if indent != 2 || !trimmed.starts_with("listen:") {
        return None;
    }
    // Avoid matching e.g. `listening:` or `listen_addr:`.
    let after_key = trimmed["listen:".len()..].chars().next();
    if !matches!(after_key, Some(' ') | Some('\t') | None) {
        return None;
    }
    Some(format!("  listen: \"{}\"", new_value))
}

/// Main configuration struct.
///
/// Top level groups settings by responsibility:
///   * `proxy`   — proxy server (listen, security, pool, keepalive)
///   * `dns`     — DNS server (optional)
///   * `logging` — cross-cutting logging
///   * `app`     — cross-cutting UI / system
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
    // Read on Windows for the tray setup path; parsed everywhere else so
    // shared YAML files round-trip cleanly, but otherwise unused.
    #[cfg_attr(not(windows), allow(dead_code))]
    #[serde(default)]
    pub app: AppConfig,
}

// ============== Proxy Config ==============

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_enabled")]
    pub enabled: bool,
    #[serde(default = "default_proxy_listen")]
    pub listen: String,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub connection_pool: ConnectionPoolConfig,
    #[serde(default)]
    pub tcp_keepalive: TcpKeepaliveConfig,
}

fn default_proxy_enabled() -> bool {
    true
}

pub fn default_proxy_listen() -> String {
    "127.0.0.1:8080".to_string()
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            enabled: default_proxy_enabled(),
            listen: default_proxy_listen(),
            security: SecurityConfig::default(),
            connection_pool: ConnectionPoolConfig::default(),
            tcp_keepalive: TcpKeepaliveConfig::default(),
        }
    }
}

// ============== App Config ==============

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    // Read on Windows by the tray setup path; on other platforms it's parsed
    // (so the field is still recognized in shared config files) but unused.
    #[cfg_attr(not(windows), allow(dead_code))]
    #[serde(default = "default_tray_enabled")]
    pub tray_enabled: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            tray_enabled: default_tray_enabled(),
        }
    }
}

// ============== Connection Pool Config ==============

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPoolConfig {
    #[serde(default = "default_pool_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_connections_per_host")]
    pub max_connections_per_host: usize,
    /// Maximum total connections across all hosts (prevents memory exhaustion)
    #[serde(default = "default_max_total_connections")]
    pub max_total_connections: usize,
    #[serde(default = "default_pool_idle_timeout")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_pool_max_lifetime")]
    pub max_lifetime_seconds: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
}

fn default_pool_enabled() -> bool {
    true
}

fn default_max_connections_per_host() -> usize {
    10
}

fn default_max_total_connections() -> usize {
    1000 // Global limit across all hosts
}

fn default_pool_idle_timeout() -> u64 {
    60
}

fn default_pool_max_lifetime() -> u64 {
    300
}

fn default_connect_timeout() -> u64 {
    10
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        ConnectionPoolConfig {
            enabled: default_pool_enabled(),
            max_connections_per_host: default_max_connections_per_host(),
            max_total_connections: default_max_total_connections(),
            idle_timeout_seconds: default_pool_idle_timeout(),
            max_lifetime_seconds: default_pool_max_lifetime(),
            connect_timeout_seconds: default_connect_timeout(),
        }
    }
}

// ============== TCP Keepalive Config ==============

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TcpKeepaliveConfig {
    #[serde(default = "default_tcp_keepalive_enabled")]
    pub enabled: bool,
    #[serde(default = "default_tcp_keepalive_time")]
    pub time_seconds: u64,
    #[serde(default = "default_tcp_keepalive_interval")]
    pub interval_seconds: u64,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[serde(default = "default_tcp_keepalive_retries")]
    pub retries: u32,
}

fn default_tcp_keepalive_enabled() -> bool {
    true
}

fn default_tcp_keepalive_time() -> u64 {
    60 // Start probes after 60 seconds of idle
}

fn default_tcp_keepalive_interval() -> u64 {
    10 // Probe every 10 seconds
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn default_tcp_keepalive_retries() -> u32 {
    3 // Give up after 3 failed probes
}

impl Default for TcpKeepaliveConfig {
    fn default() -> Self {
        TcpKeepaliveConfig {
            enabled: default_tcp_keepalive_enabled(),
            time_seconds: default_tcp_keepalive_time(),
            interval_seconds: default_tcp_keepalive_interval(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            retries: default_tcp_keepalive_retries(),
        }
    }
}

// ============== DNS Config ==============

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default = "default_dns_listen")]
    pub listen: String,
    /// Single upstream (backward compatible) - use `upstreams` for multiple
    #[serde(default)]
    pub upstream: Option<String>,
    /// Multiple upstreams for failover (tried in order)
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub security: DnsSecurityConfig,
    #[serde(default)]
    pub cache: DnsCacheConfig,
    #[serde(default)]
    pub failover: DnsFailoverConfig,
}

impl DnsConfig {
    /// Get all upstream servers (merges single `upstream` with `upstreams` list)
    pub fn get_upstreams(&self) -> Vec<String> {
        let mut result = Vec::new();

        // Add single upstream first (backward compatibility)
        if let Some(ref upstream) = self.upstream {
            result.push(upstream.clone());
        }

        // Add upstreams list
        result.extend(self.upstreams.clone());

        // If empty, use default
        if result.is_empty() {
            result.push(default_dns_upstream());
        }

        result
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DnsFailoverConfig {
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_dns_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_dns_serve_stale")]
    pub serve_stale: bool,
}

fn default_dns_timeout_ms() -> u64 {
    2000 // 2 seconds per upstream
}

fn default_dns_max_retries() -> u32 {
    1 // Retry chain once
}

fn default_dns_serve_stale() -> bool {
    true // Return expired cache on total failure
}

impl Default for DnsFailoverConfig {
    fn default() -> Self {
        DnsFailoverConfig {
            timeout_ms: default_dns_timeout_ms(),
            max_retries: default_dns_max_retries(),
            serve_stale: default_dns_serve_stale(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DnsCacheConfig {
    #[serde(default = "default_dns_cache_enabled")]
    pub enabled: bool,
    #[serde(default = "default_dns_cache_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_dns_cache_min_ttl")]
    pub min_ttl_seconds: u64,
    #[serde(default = "default_dns_cache_max_ttl")]
    pub max_ttl_seconds: u64,
}

fn default_dns_cache_enabled() -> bool {
    true
}

fn default_dns_cache_max_entries() -> usize {
    10000
}

fn default_dns_cache_min_ttl() -> u64 {
    60 // Minimum 60 seconds even if DNS says 0
}

fn default_dns_cache_max_ttl() -> u64 {
    86400 // Maximum 24 hours
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        DnsCacheConfig {
            enabled: default_dns_cache_enabled(),
            max_entries: default_dns_cache_max_entries(),
            min_ttl_seconds: default_dns_cache_min_ttl(),
            max_ttl_seconds: default_dns_cache_max_ttl(),
        }
    }
}

// ============== Security Config ==============

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default = "default_block_private_ips")]
    pub block_private_ips: bool,
    #[serde(default)]
    pub blocked_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    #[serde(default)]
    pub allowed_source_ips: Vec<String>,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Maximum request body size in bytes (0 = unlimited, default 10MB)
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: u64,
    /// Header read timeout in seconds (0 = unlimited, default 30s)
    /// Protects against slowloris attacks
    #[serde(default = "default_header_read_timeout_seconds")]
    pub header_read_timeout_seconds: u64,
    /// Maximum requests per connection (0 = unlimited, default 1000)
    /// Protects against HTTP pipelining abuse on keep-alive connections
    #[serde(default = "default_max_requests_per_connection")]
    pub max_requests_per_connection: u32,
}

fn default_max_request_body_bytes() -> u64 {
    10 * 1024 * 1024 // 10MB
}

fn default_header_read_timeout_seconds() -> u64 {
    30 // 30 seconds default
}

fn default_max_requests_per_connection() -> u32 {
    1000 // 1000 requests per connection before forcing reconnect
}

fn default_max_connections() -> usize {
    1000 // 0 = unlimited
}

fn default_block_private_ips() -> bool {
    true
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            block_private_ips: true,
            blocked_hosts: vec![],
            allowed_ports: vec![],
            allowed_source_ips: vec![],
            rate_limit: RateLimitConfig::default(),
            max_connections: default_max_connections(),
            max_request_body_bytes: default_max_request_body_bytes(),
            header_read_timeout_seconds: default_header_read_timeout_seconds(),
            max_requests_per_connection: default_max_requests_per_connection(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_requests")]
    pub max_requests: u32,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    /// Maximum number of IPs to track (prevents memory exhaustion attacks)
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,
    /// Use /64 subnet for IPv6 rate limiting (prevents bypass via address rotation)
    #[serde(default = "default_ipv6_subnet_rate_limit")]
    pub ipv6_subnet_rate_limit: bool,
}

fn default_rate_limit_enabled() -> bool {
    true
}

fn default_max_requests() -> u32 {
    1000
}

fn default_window_seconds() -> u64 {
    60
}

fn default_max_tracked_ips() -> usize {
    100000 // 100K IPs max to prevent memory exhaustion
}

fn default_ipv6_subnet_rate_limit() -> bool {
    true // Enable /64 subnet tracking by default for IPv6
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            enabled: true,
            max_requests: default_max_requests(),
            window_seconds: 60,
            max_tracked_ips: default_max_tracked_ips(),
            ipv6_subnet_rate_limit: default_ipv6_subnet_rate_limit(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DnsSecurityConfig {
    #[serde(default = "default_dns_rate_limit_enabled")]
    pub rate_limit_enabled: bool,
    #[serde(default = "default_dns_max_qps")]
    pub max_qps: u32,
    #[serde(default = "default_block_any_queries")]
    pub block_any_queries: bool,
    #[serde(default = "default_block_zone_transfers")]
    pub block_zone_transfers: bool,
    #[serde(default = "default_verify_upstream")]
    pub verify_upstream_source: bool,
    /// Maximum number of IPs to track for DNS rate limiting
    #[serde(default = "default_dns_max_tracked_ips")]
    pub max_tracked_ips: usize,
    /// Use /64 subnet for IPv6 DNS rate limiting
    #[serde(default = "default_dns_ipv6_subnet_rate_limit")]
    pub ipv6_subnet_rate_limit: bool,
}

fn default_dns_max_tracked_ips() -> usize {
    50000 // 50K IPs for DNS
}

fn default_dns_ipv6_subnet_rate_limit() -> bool {
    true
}

fn default_dns_rate_limit_enabled() -> bool {
    true
}

fn default_dns_max_qps() -> u32 {
    20
}

fn default_block_any_queries() -> bool {
    true
}

fn default_block_zone_transfers() -> bool {
    true
}

fn default_verify_upstream() -> bool {
    true
}

impl Default for DnsSecurityConfig {
    fn default() -> Self {
        DnsSecurityConfig {
            rate_limit_enabled: true,
            max_qps: 20,
            block_any_queries: true,
            block_zone_transfers: true,
            verify_upstream_source: true,
            max_tracked_ips: default_dns_max_tracked_ips(),
            ipv6_subnet_rate_limit: default_dns_ipv6_subnet_rate_limit(),
        }
    }
}

// ============== Logging Config ==============

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogRotation {
    #[default]
    Daily,
    Hourly,
    Never,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_requests")]
    pub log_requests: bool,
    #[serde(default)]
    pub format: LogFormat,
    #[serde(default = "default_redact_sensitive")]
    pub redact_sensitive_headers: bool,
    #[serde(default = "default_sensitive_headers")]
    pub sensitive_headers: Vec<String>,
    /// File logging configuration
    #[serde(default)]
    pub file: Option<FileLoggingConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FileLoggingConfig {
    #[serde(default = "default_log_dir")]
    pub log_dir: String,
    #[serde(default = "default_log_file_prefix")]
    pub file_prefix: String,
    #[serde(default)]
    pub rotation: LogRotation,
    /// Days to keep old log files (0 = keep forever)
    #[serde(default = "default_max_age_days")]
    pub max_age_days: u64,
    /// Compress rotated log files with gzip
    #[serde(default = "default_compress")]
    pub compress: bool,
}

fn default_log_dir() -> String {
    "logs".to_string()
}

fn default_log_file_prefix() -> String {
    "proxy.log".to_string()
}

fn default_max_age_days() -> u64 {
    7
}

fn default_compress() -> bool {
    true
}

impl Default for FileLoggingConfig {
    fn default() -> Self {
        FileLoggingConfig {
            log_dir: default_log_dir(),
            file_prefix: default_log_file_prefix(),
            rotation: LogRotation::Daily,
            max_age_days: default_max_age_days(),
            compress: default_compress(),
        }
    }
}

fn default_log_requests() -> bool {
    true
}

fn default_redact_sensitive() -> bool {
    true
}

fn default_sensitive_headers() -> Vec<String> {
    vec![
        "authorization".to_string(),
        "proxy-authorization".to_string(),
        "cookie".to_string(),
        "set-cookie".to_string(),
        "x-api-key".to_string(),
        "x-auth-token".to_string(),
    ]
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            log_requests: true,
            format: LogFormat::Text,
            redact_sensitive_headers: true,
            sensitive_headers: default_sensitive_headers(),
            file: None,
        }
    }
}

// ============== Default Values ==============

pub fn default_dns_listen() -> String {
    "0.0.0.0:53".to_string()
}

pub fn default_dns_upstream() -> String {
    "8.8.8.8:53".to_string()
}

pub fn default_tray_enabled() -> bool {
    true
}

// ============== Config Loading ==============

/// Get the directory containing the executable
fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
}

/// Path to the per-user config: `<home>/.bunker/config.yaml`.
/// Windows uses `%USERPROFILE%`, Unix uses `$HOME`.
pub fn user_config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");

    home.map(|h| PathBuf::from(h).join(".bunker").join("config.yaml"))
}

/// Load configuration from file.
///
/// Returns `Ok(Some(config))` when a YAML file was found and parsed,
/// `Ok(None)` when no file was found at any of the searched locations. The
/// caller decides whether a missing file is acceptable — `--install` on
/// Windows treats it as "skip log-dir prep", while the runtime entrypoint
/// rejects it and tells the user to run `--init`.
///
/// Search order when `path` is `None`: `./config.yaml`, the per-user
/// config (`~/.bunker/config.yaml`), then `<exe-dir>/config.yaml`.
pub fn load_config(
    path: Option<&str>,
) -> Result<Option<Config>, Box<dyn std::error::Error + Send + Sync>> {
    let config_paths = if let Some(p) = path {
        vec![PathBuf::from(p)]
    } else {
        let mut paths = vec![PathBuf::from("config.yaml")];
        if let Some(p) = user_config_path() {
            paths.push(p);
        }
        if let Some(dir) = exe_dir() {
            paths.push(dir.join("config.yaml"));
        }
        paths
    };

    for config_path in config_paths {
        if config_path.exists() {
            println!("Loading config from: {}", config_path.display());
            let content = fs::read_to_string(&config_path)?;
            let config: Config = serde_yaml_ng::from_str(&content)?;
            return Ok(Some(config));
        }
    }

    Ok(None)
}

// ============== Unit Tests ==============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_proxy_listen() {
        assert_eq!(default_proxy_listen(), "127.0.0.1:8080");
    }

    #[test]
    fn test_default_dns_listen() {
        assert_eq!(default_dns_listen(), "0.0.0.0:53");
    }

    #[test]
    fn test_default_dns_upstream() {
        assert_eq!(default_dns_upstream(), "8.8.8.8:53");
    }

    #[test]
    fn test_default_tray_enabled() {
        assert!(default_tray_enabled());
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.proxy.enabled);
        assert_eq!(config.proxy.listen, "127.0.0.1:8080");
        assert!(config.dns.is_none());
        assert!(config.app.tray_enabled);
    }

    #[test]
    fn test_config_deserialization_full() {
        let yaml = r#"
proxy:
  listen: "192.168.1.1:8080"
app:
  tray_enabled: false
dns:
  listen: "192.168.1.1:53"
  upstream: "1.1.1.1:53"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.listen, "192.168.1.1:8080");
        assert!(!config.app.tray_enabled);
        assert!(config.dns.is_some());
        let dns = config.dns.unwrap();
        assert_eq!(dns.listen, "192.168.1.1:53");
        assert_eq!(dns.upstream, Some("1.1.1.1:53".to_string()));
    }

    #[test]
    fn test_config_deserialization_partial() {
        let yaml = r#"
proxy:
  listen: "127.0.0.1:3128"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.listen, "127.0.0.1:3128");
        assert!(config.app.tray_enabled); // default
        assert!(config.dns.is_none());
    }

    #[test]
    fn test_config_deserialization_empty() {
        let yaml = "";
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.listen, "127.0.0.1:8080"); // default
    }

    #[test]
    fn test_config_rejects_unknown_root_field() {
        let yaml = "unknown_field: 42\n";
        let result: Result<Config, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err(), "unknown top-level fields must be rejected");
    }

    #[test]
    fn test_config_rejects_legacy_flat_layout() {
        // Old shape (listen_addr at root) is no longer accepted.
        let yaml = "listen_addr: \"0.0.0.0:8080\"\n";
        let result: Result<Config, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err(), "legacy flat layout must be rejected");
    }

    #[test]
    fn test_dns_config_defaults() {
        let yaml = r#"
dns:
  listen: "0.0.0.0:5353"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let dns = config.dns.unwrap();
        assert_eq!(dns.listen, "0.0.0.0:5353");
        assert!(dns.upstream.is_none());
        assert_eq!(dns.get_upstreams(), vec!["8.8.8.8:53"]);
    }

    #[test]
    fn test_load_config_nonexistent_file() {
        let result = load_config(Some("/nonexistent/path/config.yaml"));
        assert!(result.is_ok());
        // Missing file is now reported as `None` rather than silently
        // returning defaults — the caller decides what to do about it.
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_connection_pool_config_defaults() {
        let config = ConnectionPoolConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_connections_per_host, 10);
        assert_eq!(config.idle_timeout_seconds, 60);
        assert_eq!(config.max_lifetime_seconds, 300);
        assert_eq!(config.connect_timeout_seconds, 10);
    }

    #[test]
    fn test_tcp_keepalive_config_defaults() {
        let config = TcpKeepaliveConfig::default();
        assert!(config.enabled);
        assert_eq!(config.time_seconds, 60);
        assert_eq!(config.interval_seconds, 10);
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RateLimitConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_requests, 1000);
        assert_eq!(config.window_seconds, 60);
    }

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert!(config.block_private_ips);
        assert!(config.blocked_hosts.is_empty());
        assert!(config.allowed_ports.is_empty());
        assert_eq!(config.max_request_body_bytes, 10 * 1024 * 1024); // 10MB default
        assert_eq!(config.header_read_timeout_seconds, 30); // 30s default
        assert_eq!(config.max_requests_per_connection, 1000); // 1000 requests per connection
    }

    #[test]
    fn test_security_config_deserialize() {
        let yaml = r#"
proxy:
  security:
    block_private_ips: false
    blocked_hosts:
      - "*.internal"
      - "evil.com"
    allowed_ports:
      - 80
      - 443
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!config.proxy.security.block_private_ips);
        assert_eq!(config.proxy.security.blocked_hosts.len(), 2);
        assert_eq!(config.proxy.security.allowed_ports, vec![80, 443]);
    }

    #[test]
    fn test_security_config_max_body_bytes() {
        let yaml = r#"
proxy:
  security:
    max_request_body_bytes: 5242880
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(
            config.proxy.security.max_request_body_bytes,
            5 * 1024 * 1024
        );
    }

    #[test]
    fn test_security_config_unlimited_body() {
        let yaml = r#"
proxy:
  security:
    max_request_body_bytes: 0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.security.max_request_body_bytes, 0);
    }

    #[test]
    fn test_security_config_header_timeout() {
        let yaml = r#"
proxy:
  security:
    header_read_timeout_seconds: 60
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.security.header_read_timeout_seconds, 60);
    }

    #[test]
    fn test_security_config_header_timeout_disabled() {
        let yaml = r#"
proxy:
  security:
    header_read_timeout_seconds: 0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.security.header_read_timeout_seconds, 0);
    }

    #[test]
    fn test_security_config_max_requests_per_connection() {
        let yaml = r#"
proxy:
  security:
    max_requests_per_connection: 500
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.security.max_requests_per_connection, 500);
    }

    #[test]
    fn test_security_config_max_requests_per_connection_unlimited() {
        let yaml = r#"
proxy:
  security:
    max_requests_per_connection: 0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.security.max_requests_per_connection, 0);
    }

    #[test]
    fn test_dns_get_upstreams_with_single_upstream() {
        let yaml = r#"
dns:
  listen: "0.0.0.0:53"
  upstream: "1.1.1.1:53"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let dns = config.dns.unwrap();
        let upstreams = dns.get_upstreams();
        assert_eq!(upstreams, vec!["1.1.1.1:53"]);
    }

    #[test]
    fn test_dns_get_upstreams_with_multiple() {
        let yaml = r#"
dns:
  listen: "0.0.0.0:53"
  upstreams:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let dns = config.dns.unwrap();
        let upstreams = dns.get_upstreams();
        assert_eq!(upstreams, vec!["8.8.8.8:53", "1.1.1.1:53"]);
    }

    #[test]
    fn test_dns_get_upstreams_with_both() {
        let yaml = r#"
dns:
  listen: "0.0.0.0:53"
  upstream: "1.1.1.1:53"
  upstreams:
    - "8.8.8.8:53"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let dns = config.dns.unwrap();
        let upstreams = dns.get_upstreams();
        // Single upstream should come first
        assert_eq!(upstreams, vec!["1.1.1.1:53", "8.8.8.8:53"]);
    }

    #[test]
    fn test_exe_dir() {
        let dir = exe_dir();
        // Should return Some when running from a binary
        assert!(dir.is_some());
    }

    #[test]
    fn test_load_config_default() {
        // With None, load_config searches the standard locations. We only
        // assert it doesn't error — the result can be Some or None depending
        // on whether the test runner happens to be sitting next to a
        // `config.yaml` (the project root does ship one).
        let result = load_config(None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dns_security_config_defaults() {
        let config = DnsSecurityConfig::default();
        assert!(config.rate_limit_enabled);
        assert_eq!(config.max_qps, 20);
        assert!(config.block_any_queries);
        assert!(config.block_zone_transfers);
        assert!(config.verify_upstream_source);
    }

    #[test]
    fn test_dns_cache_config_defaults() {
        let config = DnsCacheConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_entries, 10000);
        assert_eq!(config.min_ttl_seconds, 60);
        assert_eq!(config.max_ttl_seconds, 86400);
    }

    #[test]
    fn test_dns_failover_config_defaults() {
        let config = DnsFailoverConfig::default();
        assert_eq!(config.timeout_ms, 2000);
        assert_eq!(config.max_retries, 1);
        assert!(config.serve_stale);
    }

    #[test]
    fn test_logging_config_defaults() {
        let config = LoggingConfig::default();
        assert!(config.log_requests); // Logging enabled by default
        assert_eq!(config.format, LogFormat::Text);
        assert!(config.redact_sensitive_headers);
        assert!(!config.sensitive_headers.is_empty());
        assert!(config.file.is_none()); // No file logging by default
    }

    #[test]
    fn test_logging_config_deserialize() {
        let yaml = r#"
logging:
  log_requests: false
  redact_sensitive_headers: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!config.logging.log_requests);
        assert!(!config.logging.redact_sensitive_headers);
    }

    #[test]
    fn test_connection_pool_deserialize() {
        let yaml = r#"
proxy:
  connection_pool:
    enabled: false
    max_connections_per_host: 5
    idle_timeout_seconds: 30
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!config.proxy.connection_pool.enabled);
        assert_eq!(config.proxy.connection_pool.max_connections_per_host, 5);
        assert_eq!(config.proxy.connection_pool.idle_timeout_seconds, 30);
    }

    #[test]
    fn test_tcp_keepalive_deserialize() {
        let yaml = r#"
proxy:
  tcp_keepalive:
    enabled: false
    time_seconds: 120
    interval_seconds: 20
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!config.proxy.tcp_keepalive.enabled);
        assert_eq!(config.proxy.tcp_keepalive.time_seconds, 120);
        assert_eq!(config.proxy.tcp_keepalive.interval_seconds, 20);
    }

    #[test]
    fn test_dns_full_config() {
        let yaml = r#"
dns:
  listen: "[::]:53"
  upstreams:
    - "8.8.8.8:53"
    - "[2001:4860:4860::8888]:53"
  security:
    rate_limit_enabled: true
    max_qps: 50
    block_any_queries: false
  cache:
    enabled: true
    max_entries: 5000
  failover:
    timeout_ms: 5000
    max_retries: 3
    serve_stale: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let dns = config.dns.unwrap();
        assert_eq!(dns.listen, "[::]:53");
        assert!(dns.security.rate_limit_enabled);
        assert_eq!(dns.security.max_qps, 50);
        assert!(!dns.security.block_any_queries);
        assert_eq!(dns.cache.max_entries, 5000);
        assert_eq!(dns.failover.timeout_ms, 5000);
        assert!(!dns.failover.serve_stale);
    }

    // ============== Missing Coverage Tests ==============

    #[test]
    fn test_security_config_max_connections() {
        let config = SecurityConfig::default();
        assert_eq!(config.max_connections, 1000); // default

        let yaml = r#"
proxy:
  security:
    max_connections: 500
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.security.max_connections, 500);
    }

    #[test]
    fn test_security_config_allowed_source_ips() {
        let yaml = r#"
proxy:
  security:
    allowed_source_ips:
      - "192.168.1.0/24"
      - "10.0.0.1"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.security.allowed_source_ips.len(), 2);
        assert_eq!(
            config.proxy.security.allowed_source_ips[0],
            "192.168.1.0/24"
        );
        assert_eq!(config.proxy.security.allowed_source_ips[1], "10.0.0.1");
    }

    #[test]
    fn test_rate_limit_config_max_tracked_ips() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_tracked_ips, 100000); // default

        let yaml = r#"
proxy:
  security:
    rate_limit:
      max_tracked_ips: 50000
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.security.rate_limit.max_tracked_ips, 50000);
    }

    #[test]
    fn test_rate_limit_config_ipv6_subnet() {
        let config = RateLimitConfig::default();
        assert!(config.ipv6_subnet_rate_limit); // default true

        let yaml = r#"
proxy:
  security:
    rate_limit:
      ipv6_subnet_rate_limit: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!config.proxy.security.rate_limit.ipv6_subnet_rate_limit);
    }

    #[test]
    fn test_rate_limit_full_deserialize() {
        let yaml = r#"
proxy:
  security:
    rate_limit:
      enabled: true
      max_requests: 200
      window_seconds: 120
      max_tracked_ips: 10000
      ipv6_subnet_rate_limit: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.proxy.security.rate_limit.enabled);
        assert_eq!(config.proxy.security.rate_limit.max_requests, 200);
        assert_eq!(config.proxy.security.rate_limit.window_seconds, 120);
        assert_eq!(config.proxy.security.rate_limit.max_tracked_ips, 10000);
        assert!(!config.proxy.security.rate_limit.ipv6_subnet_rate_limit);
    }

    #[test]
    fn test_connection_pool_max_total_connections() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.max_total_connections, 1000); // default

        let yaml = r#"
proxy:
  connection_pool:
    max_total_connections: 500
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.connection_pool.max_total_connections, 500);
    }

    #[test]
    fn test_connection_pool_full_deserialize() {
        let yaml = r#"
proxy:
  connection_pool:
    enabled: true
    max_connections_per_host: 20
    max_total_connections: 2000
    idle_timeout_seconds: 120
    max_lifetime_seconds: 600
    connect_timeout_seconds: 30
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.proxy.connection_pool.enabled);
        assert_eq!(config.proxy.connection_pool.max_connections_per_host, 20);
        assert_eq!(config.proxy.connection_pool.max_total_connections, 2000);
        assert_eq!(config.proxy.connection_pool.idle_timeout_seconds, 120);
        assert_eq!(config.proxy.connection_pool.max_lifetime_seconds, 600);
        assert_eq!(config.proxy.connection_pool.connect_timeout_seconds, 30);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_tcp_keepalive_retries() {
        let config = TcpKeepaliveConfig::default();
        assert_eq!(config.retries, 3); // default

        let yaml = r#"
proxy:
  tcp_keepalive:
    retries: 5
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.proxy.tcp_keepalive.retries, 5);
    }

    #[test]
    fn test_dns_security_max_tracked_ips() {
        let config = DnsSecurityConfig::default();
        assert_eq!(config.max_tracked_ips, 50000); // default

        let yaml = r#"
dns:
  listen: "0.0.0.0:53"
  security:
    max_tracked_ips: 25000
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let dns = config.dns.unwrap();
        assert_eq!(dns.security.max_tracked_ips, 25000);
    }

    #[test]
    fn test_dns_security_ipv6_subnet() {
        let config = DnsSecurityConfig::default();
        assert!(config.ipv6_subnet_rate_limit); // default true

        let yaml = r#"
dns:
  listen: "0.0.0.0:53"
  security:
    ipv6_subnet_rate_limit: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let dns = config.dns.unwrap();
        assert!(!dns.security.ipv6_subnet_rate_limit);
    }

    #[test]
    fn test_dns_security_full_deserialize() {
        let yaml = r#"
dns:
  listen: "0.0.0.0:53"
  security:
    rate_limit_enabled: false
    max_qps: 100
    block_any_queries: false
    block_zone_transfers: false
    verify_upstream_source: false
    max_tracked_ips: 10000
    ipv6_subnet_rate_limit: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let dns = config.dns.unwrap();
        assert!(!dns.security.rate_limit_enabled);
        assert_eq!(dns.security.max_qps, 100);
        assert!(!dns.security.block_any_queries);
        assert!(!dns.security.block_zone_transfers);
        assert!(!dns.security.verify_upstream_source);
        assert_eq!(dns.security.max_tracked_ips, 10000);
        assert!(!dns.security.ipv6_subnet_rate_limit);
    }

    #[test]
    fn test_dns_cache_full_deserialize() {
        let yaml = r#"
dns:
  listen: "0.0.0.0:53"
  cache:
    enabled: false
    max_entries: 5000
    min_ttl_seconds: 30
    max_ttl_seconds: 3600
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let dns = config.dns.unwrap();
        assert!(!dns.cache.enabled);
        assert_eq!(dns.cache.max_entries, 5000);
        assert_eq!(dns.cache.min_ttl_seconds, 30);
        assert_eq!(dns.cache.max_ttl_seconds, 3600);
    }

    #[test]
    fn test_logging_format_json() {
        let yaml = r#"
logging:
  format: json
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.logging.format, LogFormat::Json);
    }

    #[test]
    fn test_logging_sensitive_headers_custom() {
        let yaml = r#"
logging:
  sensitive_headers:
    - "x-custom-secret"
    - "x-api-key"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.logging.sensitive_headers.len(), 2);
        assert_eq!(config.logging.sensitive_headers[0], "x-custom-secret");
    }

    #[test]
    fn test_file_logging_config_defaults() {
        let config = FileLoggingConfig::default();
        assert_eq!(config.log_dir, "logs");
        assert_eq!(config.file_prefix, "proxy.log");
        assert_eq!(config.rotation, LogRotation::Daily);
        assert_eq!(config.max_age_days, 7);
        assert!(config.compress);
    }

    #[test]
    fn test_file_logging_full_deserialize() {
        let yaml = r#"
logging:
  log_requests: true
  format: json
  file:
    log_dir: "/var/log/bunker"
    file_prefix: "bunker.log"
    rotation: hourly
    max_age_days: 30
    compress: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.logging.file.is_some());
        let file = config.logging.file.unwrap();
        assert_eq!(file.log_dir, "/var/log/bunker");
        assert_eq!(file.file_prefix, "bunker.log");
        assert_eq!(file.rotation, LogRotation::Hourly);
        assert_eq!(file.max_age_days, 30);
        assert!(!file.compress);
    }

    #[test]
    fn test_file_logging_rotation_never() {
        let yaml = r#"
logging:
  file:
    rotation: never
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let file = config.logging.file.unwrap();
        assert_eq!(file.rotation, LogRotation::Never);
    }

    #[test]
    fn test_full_config_all_sections() {
        let yaml = r#"
proxy:
  enabled: true
  listen: "0.0.0.0:3128"
  security:
    block_private_ips: true
    blocked_hosts:
      - "*.evil.com"
    allowed_ports:
      - 80
      - 443
      - 8443
    allowed_source_ips:
      - "10.0.0.0/8"
    rate_limit:
      enabled: true
      max_requests: 500
      window_seconds: 300
    max_connections: 2000
    max_request_body_bytes: 52428800
    header_read_timeout_seconds: 60
    max_requests_per_connection: 500
  connection_pool:
    enabled: true
    max_connections_per_host: 20
    max_total_connections: 5000
    idle_timeout_seconds: 120
    max_lifetime_seconds: 600
    connect_timeout_seconds: 15
  tcp_keepalive:
    enabled: true
    time_seconds: 30
    interval_seconds: 5
dns:
  listen: "0.0.0.0:5353"
  upstream: "1.1.1.1:53"
  upstreams:
    - "8.8.8.8:53"
  security:
    rate_limit_enabled: true
    max_qps: 50
  cache:
    enabled: true
    max_entries: 20000
  failover:
    timeout_ms: 3000
    max_retries: 2
    serve_stale: true
logging:
  log_requests: true
  format: json
  redact_sensitive_headers: true
  sensitive_headers:
    - "authorization"
  file:
    log_dir: "logs"
    file_prefix: "proxy.log"
    rotation: daily
    max_age_days: 14
    compress: true
app:
  tray_enabled: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();

        // Proxy
        assert!(config.proxy.enabled);
        assert_eq!(config.proxy.listen, "0.0.0.0:3128");
        assert!(config.proxy.security.block_private_ips);
        assert_eq!(config.proxy.security.blocked_hosts.len(), 1);
        assert_eq!(config.proxy.security.allowed_ports, vec![80, 443, 8443]);
        assert_eq!(config.proxy.security.allowed_source_ips.len(), 1);
        assert_eq!(config.proxy.security.rate_limit.max_requests, 500);
        assert_eq!(config.proxy.security.max_connections, 2000);
        assert_eq!(config.proxy.security.max_request_body_bytes, 52428800);
        assert_eq!(config.proxy.security.header_read_timeout_seconds, 60);
        assert_eq!(config.proxy.security.max_requests_per_connection, 500);
        assert!(config.proxy.connection_pool.enabled);
        assert_eq!(config.proxy.connection_pool.max_connections_per_host, 20);
        assert_eq!(config.proxy.connection_pool.max_total_connections, 5000);
        assert_eq!(config.proxy.connection_pool.idle_timeout_seconds, 120);
        assert!(config.proxy.tcp_keepalive.enabled);
        assert_eq!(config.proxy.tcp_keepalive.time_seconds, 30);
        assert_eq!(config.proxy.tcp_keepalive.interval_seconds, 5);

        // DNS
        let dns = config.dns.unwrap();
        assert_eq!(dns.listen, "0.0.0.0:5353");
        assert_eq!(dns.get_upstreams(), vec!["1.1.1.1:53", "8.8.8.8:53"]);
        assert_eq!(dns.security.max_qps, 50);
        assert_eq!(dns.cache.max_entries, 20000);
        assert_eq!(dns.failover.timeout_ms, 3000);

        // Logging
        assert!(config.logging.log_requests);
        assert_eq!(config.logging.format, LogFormat::Json);
        assert!(config.logging.file.is_some());
        let file = config.logging.file.unwrap();
        assert_eq!(file.max_age_days, 14);

        // App
        assert!(!config.app.tray_enabled);
    }

    #[test]
    fn test_embedded_default_yaml_parses() {
        // The shipped `config.yaml` (embedded as DEFAULT_CONFIG_YAML) must
        // round-trip through the strict deserializer.
        let _: Config = serde_yaml_ng::from_str(DEFAULT_CONFIG_YAML)
            .expect("embedded default config.yaml must parse");
    }

    #[test]
    fn test_customize_default_config_no_overrides_is_passthrough() {
        let out = customize_default_config(None, None, None, None);
        // Allow a trailing newline difference (we always write `\n` per line).
        assert_eq!(
            out.trim_end_matches('\n'),
            DEFAULT_CONFIG_YAML.trim_end_matches('\n')
        );
    }

    #[test]
    fn test_customize_default_config_proxy_listen() {
        let out = customize_default_config(Some("[::]:8080"), None, None, None);
        let cfg: Config = serde_yaml_ng::from_str(&out).expect("customized config must parse");
        assert_eq!(cfg.proxy.listen, "[::]:8080");
        // The DNS section should be untouched.
        let dns = cfg.dns.expect("dns section preserved");
        assert_eq!(dns.listen, "127.0.0.1:53");
    }

    #[test]
    fn test_customize_default_config_dns_listen() {
        let out = customize_default_config(None, Some("0.0.0.0:53"), None, None);
        let cfg: Config = serde_yaml_ng::from_str(&out).expect("customized config must parse");
        // The proxy section should not have been touched.
        assert_eq!(cfg.proxy.listen, "127.0.0.1:8080");
        let dns = cfg.dns.expect("dns section preserved");
        assert_eq!(dns.listen, "0.0.0.0:53");
    }

    #[test]
    fn test_customize_default_config_dns_upstream_replaces_block() {
        let out = customize_default_config(None, None, Some("9.9.9.9:53"), None);
        let cfg: Config = serde_yaml_ng::from_str(&out).expect("customized config must parse");
        let dns = cfg.dns.expect("dns section preserved");
        assert_eq!(dns.upstreams, vec!["9.9.9.9:53".to_string()]);
        // The default template ships with two upstreams; ensure they were
        // replaced rather than appended. (The string `8.8.8.8:53` still
        // appears inside the commented-out singular `# upstream:` line below
        // the block, which is fine.)
        assert!(!out.contains("- \"8.8.8.8:53\""));
        assert!(!out.contains("- \"1.1.1.1:53\""));
        assert!(out.contains("- \"9.9.9.9:53\""));
    }

    #[test]
    fn test_customize_default_config_all_overrides() {
        let out = customize_default_config(
            Some("[::]:8443"),
            Some("[::]:5353"),
            Some("[2001:4860:4860::8888]:53"),
            None,
        );
        let cfg: Config = serde_yaml_ng::from_str(&out).expect("customized config must parse");
        assert_eq!(cfg.proxy.listen, "[::]:8443");
        let dns = cfg.dns.expect("dns section preserved");
        assert_eq!(dns.listen, "[::]:5353");
        assert_eq!(dns.upstreams, vec!["[2001:4860:4860::8888]:53".to_string()]);
    }

    #[test]
    fn test_customize_default_config_preserves_comments() {
        // Pick a recognizable comment fragment from each top-level section and
        // confirm overrides don't accidentally strip it.
        let out = customize_default_config(
            Some("[::]:8080"),
            Some("[::]:53"),
            Some("9.9.9.9:53"),
            None,
        );
        assert!(out.contains("# ---- access control & SSRF protection ----"));
        assert!(out.contains("# Bind address."));
        assert!(out.contains("# Single upstream (kept for backward compatibility"));
        assert!(out.contains("# Logging (cross-cutting"));
    }

    #[test]
    fn test_customize_default_config_allowlist_replaces_block() {
        let entries = vec!["192.168.5.0/24".to_string()];
        let override_ = AllowlistOverride {
            entries: &entries,
            annotation: Some("Set by `bunker --init lan` from interface eth0."),
        };
        let out = customize_default_config(None, None, None, Some(&override_));
        let cfg: Config = serde_yaml_ng::from_str(&out).expect("customized config must parse");
        assert_eq!(cfg.proxy.security.allowed_source_ips, vec!["192.168.5.0/24"]);
        // Original loopback entries are gone.
        assert!(!out.contains("- \"127.0.0.1\""));
        assert!(!out.contains("- \"::1\""));
        // The example comment block below the list is gone too.
        assert!(!out.contains("# Example LAN deployment"));
        assert!(!out.contains("#  - \"192.168.1.0/24\""));
        // But the explanatory comments above the block are preserved.
        assert!(out.contains("# Only allow connections from these source IPs"));
        // And our annotation is rendered.
        assert!(out.contains("# Set by `bunker --init lan` from interface eth0."));
        // And sections below the allowlist are intact.
        assert!(out.contains("blocked_hosts:"));
    }

    #[test]
    fn test_customize_default_config_allowlist_multiple_entries() {
        let entries = vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()];
        let override_ = AllowlistOverride {
            entries: &entries,
            annotation: None,
        };
        let out = customize_default_config(None, None, None, Some(&override_));
        let cfg: Config = serde_yaml_ng::from_str(&out).expect("customized config must parse");
        assert_eq!(
            cfg.proxy.security.allowed_source_ips,
            vec!["192.168.1.0/24", "10.0.0.0/8"]
        );
    }

    #[test]
    fn test_customize_default_config_allowlist_with_other_overrides() {
        let entries = vec!["192.168.5.0/24".to_string()];
        let override_ = AllowlistOverride {
            entries: &entries,
            annotation: None,
        };
        let out = customize_default_config(
            Some("192.168.5.42:8080"),
            Some("192.168.5.42:53"),
            Some("9.9.9.9:53"),
            Some(&override_),
        );
        let cfg: Config = serde_yaml_ng::from_str(&out).expect("customized config must parse");
        assert_eq!(cfg.proxy.listen, "192.168.5.42:8080");
        assert_eq!(cfg.proxy.security.allowed_source_ips, vec!["192.168.5.0/24"]);
        let dns = cfg.dns.expect("dns section preserved");
        assert_eq!(dns.listen, "192.168.5.42:53");
        assert_eq!(dns.upstreams, vec!["9.9.9.9:53".to_string()]);
    }
}
