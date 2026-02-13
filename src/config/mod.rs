//! Configuration types and loading for the proxy.

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// Default config.yaml embedded at compile time
pub const DEFAULT_CONFIG_YAML: &str = include_str!("../../config.yaml");

/// Main configuration struct for the proxy
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default = "default_tray_enabled")]
    pub tray_enabled: bool,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub connection_pool: ConnectionPoolConfig,
    #[serde(default)]
    pub tcp_keepalive: TcpKeepaliveConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_addr: default_listen_addr(),
            dns: None,
            tray_enabled: true,
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            connection_pool: ConnectionPoolConfig::default(),
            tcp_keepalive: TcpKeepaliveConfig::default(),
        }
    }
}

// ============== Connection Pool Config ==============

#[derive(Debug, Deserialize, Clone)]
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
    100
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
            max_requests: 100,
            window_seconds: 60,
            max_tracked_ips: default_max_tracked_ips(),
            ipv6_subnet_rate_limit: default_ipv6_subnet_rate_limit(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
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

pub fn default_listen_addr() -> String {
    "0.0.0.0:8080".to_string()
}

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

/// Load configuration from file
pub fn load_config(path: Option<&str>) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    // Try to find config file
    let config_paths = if let Some(p) = path {
        vec![PathBuf::from(p)]
    } else {
        let mut paths = vec![
            PathBuf::from("config.yaml"),
        ];
        // Look next to the executable (handles Scoop installs and portable setups)
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
            return Ok(config);
        }
    }

    Ok(Config::default())
}

// ============== Unit Tests ==============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_listen_addr() {
        assert_eq!(default_listen_addr(), "0.0.0.0:8080");
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
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
        assert!(config.dns.is_none());
        assert!(config.tray_enabled);
    }

    #[test]
    fn test_config_deserialization_full() {
        let yaml = r#"
listen_addr: "192.168.1.1:8080"
tray_enabled: false
dns:
  listen: "192.168.1.1:53"
  upstream: "1.1.1.1:53"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.listen_addr, "192.168.1.1:8080");
        assert!(!config.tray_enabled);
        assert!(config.dns.is_some());
        let dns = config.dns.unwrap();
        assert_eq!(dns.listen, "192.168.1.1:53");
        assert_eq!(dns.upstream, Some("1.1.1.1:53".to_string()));
    }

    #[test]
    fn test_config_deserialization_partial() {
        let yaml = r#"
listen_addr: "127.0.0.1:3128"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:3128");
        assert!(config.tray_enabled); // default
        assert!(config.dns.is_none());
    }

    #[test]
    fn test_config_deserialization_empty() {
        let yaml = "";
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.listen_addr, "0.0.0.0:8080"); // default
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
        let config = result.unwrap();
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
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
        assert_eq!(config.max_requests, 100);
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
        assert!(!config.security.block_private_ips);
        assert_eq!(config.security.blocked_hosts.len(), 2);
        assert_eq!(config.security.allowed_ports, vec![80, 443]);
    }

    #[test]
    fn test_security_config_max_body_bytes() {
        let yaml = r#"
security:
  max_request_body_bytes: 5242880
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.security.max_request_body_bytes, 5 * 1024 * 1024); // 5MB
    }

    #[test]
    fn test_security_config_unlimited_body() {
        let yaml = r#"
security:
  max_request_body_bytes: 0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.security.max_request_body_bytes, 0); // Unlimited
    }

    #[test]
    fn test_security_config_header_timeout() {
        let yaml = r#"
security:
  header_read_timeout_seconds: 60
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.security.header_read_timeout_seconds, 60);
    }

    #[test]
    fn test_security_config_header_timeout_disabled() {
        let yaml = r#"
security:
  header_read_timeout_seconds: 0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.security.header_read_timeout_seconds, 0); // Disabled
    }

    #[test]
    fn test_security_config_max_requests_per_connection() {
        let yaml = r#"
security:
  max_requests_per_connection: 500
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.security.max_requests_per_connection, 500);
    }

    #[test]
    fn test_security_config_max_requests_per_connection_unlimited() {
        let yaml = r#"
security:
  max_requests_per_connection: 0
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.security.max_requests_per_connection, 0); // Unlimited
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
    fn test_config_dir() {
        let dir = config_dir();
        // Should return Some on most systems
        assert!(dir.is_some() || std::env::var("HOME").is_err());
    }

    #[test]
    fn test_load_config_default() {
        // Load with None should use defaults if no config file exists
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
connection_pool:
  enabled: false
  max_connections_per_host: 5
  idle_timeout_seconds: 30
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!config.connection_pool.enabled);
        assert_eq!(config.connection_pool.max_connections_per_host, 5);
        assert_eq!(config.connection_pool.idle_timeout_seconds, 30);
    }

    #[test]
    fn test_tcp_keepalive_deserialize() {
        let yaml = r#"
tcp_keepalive:
  enabled: false
  time_seconds: 120
  interval_seconds: 20
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!config.tcp_keepalive.enabled);
        assert_eq!(config.tcp_keepalive.time_seconds, 120);
        assert_eq!(config.tcp_keepalive.interval_seconds, 20);
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
security:
  max_connections: 500
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.security.max_connections, 500);
    }

    #[test]
    fn test_security_config_allowed_source_ips() {
        let yaml = r#"
security:
  allowed_source_ips:
    - "192.168.1.0/24"
    - "10.0.0.1"
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.security.allowed_source_ips.len(), 2);
        assert_eq!(config.security.allowed_source_ips[0], "192.168.1.0/24");
        assert_eq!(config.security.allowed_source_ips[1], "10.0.0.1");
    }

    #[test]
    fn test_rate_limit_config_max_tracked_ips() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_tracked_ips, 100000); // default

        let yaml = r#"
security:
  rate_limit:
    max_tracked_ips: 50000
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.security.rate_limit.max_tracked_ips, 50000);
    }

    #[test]
    fn test_rate_limit_config_ipv6_subnet() {
        let config = RateLimitConfig::default();
        assert!(config.ipv6_subnet_rate_limit); // default true

        let yaml = r#"
security:
  rate_limit:
    ipv6_subnet_rate_limit: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!config.security.rate_limit.ipv6_subnet_rate_limit);
    }

    #[test]
    fn test_rate_limit_full_deserialize() {
        let yaml = r#"
security:
  rate_limit:
    enabled: true
    max_requests: 200
    window_seconds: 120
    max_tracked_ips: 10000
    ipv6_subnet_rate_limit: false
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.security.rate_limit.enabled);
        assert_eq!(config.security.rate_limit.max_requests, 200);
        assert_eq!(config.security.rate_limit.window_seconds, 120);
        assert_eq!(config.security.rate_limit.max_tracked_ips, 10000);
        assert!(!config.security.rate_limit.ipv6_subnet_rate_limit);
    }

    #[test]
    fn test_connection_pool_max_total_connections() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.max_total_connections, 1000); // default

        let yaml = r#"
connection_pool:
  max_total_connections: 500
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.connection_pool.max_total_connections, 500);
    }

    #[test]
    fn test_connection_pool_full_deserialize() {
        let yaml = r#"
connection_pool:
  enabled: true
  max_connections_per_host: 20
  max_total_connections: 2000
  idle_timeout_seconds: 120
  max_lifetime_seconds: 600
  connect_timeout_seconds: 30
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.connection_pool.enabled);
        assert_eq!(config.connection_pool.max_connections_per_host, 20);
        assert_eq!(config.connection_pool.max_total_connections, 2000);
        assert_eq!(config.connection_pool.idle_timeout_seconds, 120);
        assert_eq!(config.connection_pool.max_lifetime_seconds, 600);
        assert_eq!(config.connection_pool.connect_timeout_seconds, 30);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_tcp_keepalive_retries() {
        let config = TcpKeepaliveConfig::default();
        assert_eq!(config.retries, 3); // default

        let yaml = r#"
tcp_keepalive:
  retries: 5
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.tcp_keepalive.retries, 5);
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
listen_addr: "0.0.0.0:3128"
tray_enabled: false
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
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();

        // Root
        assert_eq!(config.listen_addr, "0.0.0.0:3128");
        assert!(!config.tray_enabled);

        // DNS
        let dns = config.dns.unwrap();
        assert_eq!(dns.listen, "0.0.0.0:5353");
        assert_eq!(dns.get_upstreams(), vec!["1.1.1.1:53", "8.8.8.8:53"]);
        assert_eq!(dns.security.max_qps, 50);
        assert_eq!(dns.cache.max_entries, 20000);
        assert_eq!(dns.failover.timeout_ms, 3000);

        // Security
        assert!(config.security.block_private_ips);
        assert_eq!(config.security.blocked_hosts.len(), 1);
        assert_eq!(config.security.allowed_ports, vec![80, 443, 8443]);
        assert_eq!(config.security.allowed_source_ips.len(), 1);
        assert_eq!(config.security.rate_limit.max_requests, 500);
        assert_eq!(config.security.max_connections, 2000);
        assert_eq!(config.security.max_request_body_bytes, 52428800);
        assert_eq!(config.security.header_read_timeout_seconds, 60);
        assert_eq!(config.security.max_requests_per_connection, 500);

        // Connection Pool
        assert!(config.connection_pool.enabled);
        assert_eq!(config.connection_pool.max_connections_per_host, 20);
        assert_eq!(config.connection_pool.max_total_connections, 5000);
        assert_eq!(config.connection_pool.idle_timeout_seconds, 120);

        // TCP Keep-Alive
        assert!(config.tcp_keepalive.enabled);
        assert_eq!(config.tcp_keepalive.time_seconds, 30);
        assert_eq!(config.tcp_keepalive.interval_seconds, 5);

        // Logging
        assert!(config.logging.log_requests);
        assert_eq!(config.logging.format, LogFormat::Json);
        assert!(config.logging.file.is_some());
        let file = config.logging.file.unwrap();
        assert_eq!(file.max_age_days, 14);
    }
}
