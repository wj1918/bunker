//! Bunker - A lightweight HTTP/HTTPS and DNS proxy
//!
//! This is a generic HTTP/HTTPS forward proxy with an optional DNS server,
//! built with Rust using hyper 1.x. Supports both IPv4 and IPv6.

mod body;
mod config;
mod dns;
mod error;
mod helpers;
mod logging;
mod platform;
mod proxy;
mod security;
mod tokio_io;

use config::{
    default_dns_listen, default_dns_upstream, load_config, DnsCacheConfig, DnsConfig,
    DnsFailoverConfig, DnsSecurityConfig,
};
use dns::run_dns_server;
use helpers::create_tls_connector;
use proxy::{handle_client, SenderPool};
use security::{is_source_ip_allowed, RateLimiter};

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, warn};

#[cfg(windows)]
use std::sync::mpsc;

#[cfg(windows)]
use platform::windows_tray::{hide_window, setup_tray, show_window, TrayMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();

    // Parse command line arguments
    let mut config_path: Option<&str> = None;
    let mut cli_listen_addr: Option<String> = None;
    let mut cli_dns_addr: Option<String> = None;
    let mut cli_dns_upstream: Option<String> = None;
    let mut use_tray = true;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                config_path = args.get(i).map(|s| s.as_str());
            }
            "--dns" => {
                i += 1;
                cli_dns_addr = args.get(i).cloned();
            }
            "--dns-upstream" => {
                i += 1;
                cli_dns_upstream = args.get(i).cloned();
            }
            "--no-tray" => {
                use_tray = false;
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                return Ok(());
            }
            #[cfg(windows)]
            "--install" => {
                return install_startup(config_path);
            }
            #[cfg(windows)]
            "--uninstall" => {
                return uninstall_startup();
            }
            arg if !arg.starts_with('-') && cli_listen_addr.is_none() => {
                cli_listen_addr = Some(arg.to_string());
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_usage(&args[0]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Load config from file
    let mut config = load_config(config_path)?;

    // CLI arguments override config file
    if let Some(addr) = cli_listen_addr {
        config.listen_addr = addr;
    }
    if let Some(dns_addr) = cli_dns_addr {
        let dns = config.dns.get_or_insert(DnsConfig {
            listen: default_dns_listen(),
            upstream: None,
            upstreams: vec![default_dns_upstream()],
            security: DnsSecurityConfig::default(),
            cache: DnsCacheConfig::default(),
            failover: DnsFailoverConfig::default(),
        });
        dns.listen = dns_addr;
    }
    if let Some(upstream) = cli_dns_upstream {
        if let Some(dns) = config.dns.as_mut() {
            dns.upstream = None;
            dns.upstreams = vec![upstream];
        }
    }
    if !use_tray {
        config.tray_enabled = false;
    }

    // Initialize logging system
    let _log_guard = logging::init_logging(&config.logging);

    // Spawn log cleanup task if file logging enabled
    logging::spawn_log_cleanup_task(Arc::new(config.logging.clone()));

    tracing::debug!(config = ?config, "Configuration loaded");

    // Setup tray on Windows
    #[cfg(windows)]
    let tray_rx = if config.tray_enabled {
        let (tx, rx) = mpsc::channel::<TrayMessage>();
        if let Err(e) = setup_tray(tx) {
            eprintln!("Warning: Failed to setup system tray: {}", e);
            None
        } else {
            println!("System tray initialized");
            Some(rx)
        }
    } else {
        None
    };

    // Setup TLS connector for HTTPS connections to target servers
    let tls_connector = Arc::new(create_tls_connector()?);

    // Start DNS server if enabled
    if let Some(dns_config) = &config.dns {
        let dns_listen_addr: SocketAddr = dns_config.listen.parse()?;
        let upstreams = dns_config.get_upstreams();
        let dns_security = dns_config.security.clone();
        let dns_cache_config = dns_config.cache.clone();
        let dns_failover_config = dns_config.failover.clone();
        let dns_logging = config.logging.clone();
        let dns_allowed_ips = config.security.allowed_source_ips.clone();
        let upstreams_display = upstreams.clone();

        tokio::spawn(async move {
            if let Err(e) = run_dns_server(
                dns_listen_addr,
                upstreams,
                dns_security,
                dns_cache_config,
                dns_failover_config,
                dns_logging,
                dns_allowed_ips,
            )
            .await
            {
                error!(error = %e, "DNS server error");
            }
        });

        println!("DNS server listening on {}", dns_config.listen);
        if upstreams_display.len() == 1 {
            println!("DNS upstream: {}", upstreams_display[0]);
        } else {
            println!("DNS upstreams (failover): {:?}", upstreams_display);
            println!(
                "DNS failover: timeout={}ms, retries={}, serve_stale={}",
                dns_config.failover.timeout_ms,
                dns_config.failover.max_retries,
                dns_config.failover.serve_stale
            );
        }
        if dns_config.cache.enabled {
            println!(
                "DNS cache: enabled (max {} entries, TTL {}s-{}s)",
                dns_config.cache.max_entries,
                dns_config.cache.min_ttl_seconds,
                dns_config.cache.max_ttl_seconds
            );
        }
    }

    let listen_addr: SocketAddr = config.listen_addr.parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    println!("Forward proxy listening on http://{}", listen_addr);

    // Share configs across tasks
    let security_config = Arc::new(config.security.clone());
    let logging_config = Arc::new(config.logging.clone());
    let tcp_keepalive_config = Arc::new(config.tcp_keepalive.clone());

    // Log TCP keep-alive settings
    if config.tcp_keepalive.enabled {
        println!(
            "TCP keep-alive: enabled (time={}s, interval={}s)",
            config.tcp_keepalive.time_seconds, config.tcp_keepalive.interval_seconds
        );
    }

    // Create rate limiter
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(
        config.security.rate_limit.clone(),
    )));

    // Spawn cleanup task for rate limiter
    let rate_limiter_cleanup = Arc::clone(&rate_limiter);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            rate_limiter_cleanup.lock().await.cleanup();
        }
    });

    // Create sender pool for HTTP keep-alive
    let pool_config = config.connection_pool.clone();
    let sender_pool = Arc::new(Mutex::new(SenderPool::new(pool_config.clone())));
    if pool_config.enabled {
        println!(
            "Connection pool: enabled (max {} per host, idle {}s, lifetime {}s)",
            pool_config.max_connections_per_host,
            pool_config.idle_timeout_seconds,
            pool_config.max_lifetime_seconds
        );
    } else {
        println!("Connection pool: disabled");
    }

    // Spawn cleanup task for sender pool
    let pool_cleanup = Arc::clone(&sender_pool);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            pool_cleanup.lock().await.cleanup();
        }
    });

    // Create connection semaphore (0 = unlimited)
    let max_connections = config.security.max_connections;
    let connection_semaphore = if max_connections > 0 {
        println!(
            "Connection limit: {} max concurrent connections",
            max_connections
        );
        Some(Arc::new(tokio::sync::Semaphore::new(max_connections)))
    } else {
        println!("Connection limit: unlimited");
        None
    };

    // Handle tray messages in background
    #[cfg(windows)]
    if let Some(rx) = tray_rx {
        tokio::spawn(async move {
            loop {
                match rx.try_recv() {
                    Ok(TrayMessage::Quit) => {
                        println!("Quit requested from tray");
                        std::process::exit(0);
                    }
                    Ok(TrayMessage::Minimize) => {
                        println!("Minimize requested from tray");
                        hide_window();
                    }
                    Ok(TrayMessage::BringToFront) => {
                        println!("Bring to front requested from tray");
                        show_window();
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => break,
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });
    }

    // Pre-compute allowed source IPs for fast lookup
    let allowed_source_ips = config.security.allowed_source_ips.clone();
    let has_ip_allowlist = !allowed_source_ips.is_empty();
    if has_ip_allowlist {
        println!("Source IP allowlist: {:?}", allowed_source_ips);
    }

    loop {
        let (stream, client_addr) = listener.accept().await?;

        // Check source IP allowlist
        if has_ip_allowlist && !is_source_ip_allowed(&client_addr.ip(), &allowed_source_ips) {
            warn!(
                client = %client_addr.ip(),
                "Rejected: not in allowed source IPs"
            );
            drop(stream);
            continue;
        }

        // Check connection limit (semaphore)
        let permit = if let Some(ref sem) = connection_semaphore {
            match sem.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    warn!(
                        client = %client_addr,
                        max_connections = max_connections,
                        "Rejected: max connections reached"
                    );
                    drop(stream);
                    continue;
                }
            }
        } else {
            None
        };

        let tls_connector = Arc::clone(&tls_connector);
        let security = Arc::clone(&security_config);
        let logging = Arc::clone(&logging_config);
        let tcp_keepalive = Arc::clone(&tcp_keepalive_config);
        let limiter = Arc::clone(&rate_limiter);
        let pool = Arc::clone(&sender_pool);

        tokio::task::spawn(async move {
            // Permit is held for duration of connection, released on drop
            let _permit = permit;

            // Check rate limit before handling request
            {
                let mut limiter = limiter.lock().await;
                if !limiter.is_allowed(client_addr.ip()) {
                    warn!(
                        client = %client_addr.ip(),
                        max_requests = security.rate_limit.max_requests,
                        window_seconds = security.rate_limit.window_seconds,
                        "HTTP rate limit exceeded"
                    );
                    return;
                }
            }

            if let Err(err) =
                handle_client(stream, client_addr, tls_connector, security, logging, tcp_keepalive, pool)
                    .await
            {
                error!(client = %client_addr, error = ?err, "Error serving client");
            }
        });
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} [listen_addr] [options]", program);
    eprintln!();
    eprintln!("Generic HTTP/HTTPS forward proxy with optional DNS server.");
    eprintln!("Supports both IPv4 and IPv6.");
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  listen_addr             Address to listen on (e.g., 0.0.0.0:8080 or [::]:8080)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -c, --config <path>     Load config from YAML file");
    eprintln!("  --dns <addr>            Enable DNS server (e.g., 0.0.0.0:53 or [::]:53)");
    eprintln!("  --dns-upstream <addr>   Upstream DNS server (default: 8.8.8.8:53)");
    eprintln!("  --no-tray               Disable system tray (Windows only)");
    eprintln!("  --install               Add to Windows startup (Windows only)");
    eprintln!("  --uninstall             Remove from Windows startup (Windows only)");
    eprintln!("  -h, --help              Show this help message");
    eprintln!();
    eprintln!("Config file (config.yaml):");
    eprintln!("  listen_addr: \"0.0.0.0:8080\"    # or \"[::]:8080\" for IPv6");
    eprintln!("  tray_enabled: true");
    eprintln!("  dns:");
    eprintln!("    listen: \"0.0.0.0:53\"");
    eprintln!(
        "    upstream: \"8.8.8.8:53\"       # or \"[2001:4860:4860::8888]:53\" for IPv6"
    );
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} 0.0.0.0:8080                              # IPv4 only", program);
    eprintln!(
        "  {} [::]:8080                                 # IPv6 (also accepts IPv4)",
        program
    );
    eprintln!(
        "  {} 0.0.0.0:8080 --dns 0.0.0.0:53             # With DNS server",
        program
    );
    eprintln!(
        "  {} --config config.yaml                       # Use config file",
        program
    );
    eprintln!();
    eprintln!("Client usage:");
    eprintln!("  curl -x http://proxy:8080 http://example.com");
    eprintln!("  curl -x http://proxy:8080 https://example.com");
    #[cfg(windows)]
    {
        eprintln!();
        eprintln!("Windows startup:");
        eprintln!("  {} --install                                  # Add to Windows startup", program);
        eprintln!("  {} --install -c config.yaml                   # Add with config file", program);
        eprintln!("  {} --uninstall                                # Remove from Windows startup", program);
    }
}

// Windows Registry API declarations
#[cfg(windows)]
mod registry {
    pub const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
    pub const KEY_READ: u32 = 0x20019;
    pub const KEY_WRITE: u32 = 0x20006;
    pub const KEY_ALL_ACCESS: u32 = 0xF003F;
    pub const REG_SZ: u32 = 1;
    pub const ERROR_SUCCESS: u32 = 0;
    pub const ERROR_FILE_NOT_FOUND: u32 = 2;

    pub const REGISTRY_APP_NAME: &str = "Bunker";
    pub const RUN_KEY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    #[link(name = "advapi32")]
    extern "system" {
        pub fn RegOpenKeyExW(
            hkey: isize,
            lpsubkey: *const u16,
            uloptions: u32,
            samdesired: u32,
            phkresult: *mut isize,
        ) -> u32;

        pub fn RegCreateKeyExW(
            hkey: isize,
            lpsubkey: *const u16,
            reserved: u32,
            lpclass: *const u16,
            dwoptions: u32,
            samdesired: u32,
            lpsecurityattributes: *const std::ffi::c_void,
            phkresult: *mut isize,
            lpdwdisposition: *mut u32,
        ) -> u32;

        pub fn RegQueryValueExW(
            hkey: isize,
            lpvaluename: *const u16,
            lpreserved: *const u32,
            lptype: *mut u32,
            lpdata: *mut u8,
            lpcbdata: *mut u32,
        ) -> u32;

        pub fn RegSetValueExW(
            hkey: isize,
            lpvaluename: *const u16,
            reserved: u32,
            dwtype: u32,
            lpdata: *const u8,
            cbdata: u32,
        ) -> u32;

        pub fn RegDeleteValueW(hkey: isize, lpvaluename: *const u16) -> u32;

        pub fn RegCloseKey(hkey: isize) -> u32;
    }

    pub fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

/// Install Bunker to Windows startup (Registry Run key)
#[cfg(windows)]
fn install_startup(config_path: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use config::load_config;
    use registry::*;

    // Get absolute path of current executable
    let exe_path = std::env::current_exe()?;
    let exe_path = exe_path.to_string_lossy();
    // Remove \\?\ prefix if present
    let exe_path = exe_path.strip_prefix(r"\\?\").unwrap_or(&exe_path);

    // Get the directory containing the executable
    let exe_dir = std::path::Path::new(exe_path)
        .parent()
        .ok_or("Failed to get executable directory")?;

    // Determine working directory (use config file's directory if provided, otherwise exe directory)
    let (work_dir, cfg_abs_path) = if let Some(cfg_path) = config_path {
        let cfg_abs = std::fs::canonicalize(cfg_path)?;
        let cfg_abs_str = cfg_abs.to_string_lossy();
        let cfg_abs_str = cfg_abs_str.strip_prefix(r"\\?\").unwrap_or(&cfg_abs_str).to_string();
        let dir = std::path::Path::new(&cfg_abs_str)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| exe_dir.to_path_buf());
        (dir, Some(cfg_abs_str))
    } else {
        (exe_dir.to_path_buf(), None)
    };

    // Load and verify config file if specified
    if let Some(cfg_path) = config_path {
        let config = load_config(Some(cfg_path))?;

        // Create log directory if specified in config
        if let Some(file_config) = &config.logging.file {
            let log_dir_path = std::path::Path::new(&file_config.log_dir);
            let log_dir = if log_dir_path.is_absolute() {
                log_dir_path.to_path_buf()
            } else {
                // Relative path: resolve from config file's directory
                work_dir.join(log_dir_path)
            };

            if !log_dir.exists() {
                std::fs::create_dir_all(&log_dir)?;
                eprintln!("Created logs directory: {}", log_dir.display());
            }
        }
    }

    // Build the command string
    let work_dir_str = work_dir.to_string_lossy();
    let cmd_value = if let Some(cfg_abs) = cfg_abs_path {
        format!(
            r#"cmd /c cd /d "{}" && "{}" -c "{}""#,
            work_dir_str, exe_path, cfg_abs
        )
    } else {
        format!(
            r#"cmd /c cd /d "{}" && "{}""#,
            work_dir_str, exe_path
        )
    };

    // Add to registry using Win32 API
    unsafe {
        let key_path = to_wide(RUN_KEY_PATH);
        let value_name = to_wide(REGISTRY_APP_NAME);
        let command_wide = to_wide(&cmd_value);
        let mut hkey: isize = 0;
        let mut disposition: u32 = 0;

        let result = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_path.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_ALL_ACCESS,
            std::ptr::null(),
            &mut hkey,
            &mut disposition,
        );

        if result != ERROR_SUCCESS {
            return Err(format!("Failed to create registry key: error {}", result).into());
        }

        let data_size = (command_wide.len() * 2) as u32;
        let result = RegSetValueExW(
            hkey,
            value_name.as_ptr(),
            0,
            REG_SZ,
            command_wide.as_ptr() as *const u8,
            data_size,
        );

        RegCloseKey(hkey);

        if result != ERROR_SUCCESS {
            return Err(format!("Failed to set registry value: error {}", result).into());
        }
    }

    eprintln!("Bunker added to Windows startup.");
    eprintln!("Registry value: {}", cmd_value);
    Ok(())
}

/// Remove Bunker from Windows startup (Registry Run key)
#[cfg(windows)]
fn uninstall_startup() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use registry::*;

    unsafe {
        let key_path = to_wide(RUN_KEY_PATH);
        let value_name = to_wide(REGISTRY_APP_NAME);
        let mut hkey: isize = 0;

        // Check if entry exists first
        let result = RegOpenKeyExW(HKEY_CURRENT_USER, key_path.as_ptr(), 0, KEY_READ, &mut hkey);

        if result == ERROR_FILE_NOT_FOUND {
            eprintln!("Bunker is not in Windows startup.");
            return Ok(());
        }

        if result != ERROR_SUCCESS {
            return Err(format!("Failed to open registry key: error {}", result).into());
        }

        // Check if the value exists
        let mut data_type: u32 = 0;
        let mut data_size: u32 = 0;
        let result = RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            std::ptr::null(),
            &mut data_type,
            std::ptr::null_mut(),
            &mut data_size,
        );

        RegCloseKey(hkey);

        if result == ERROR_FILE_NOT_FOUND || data_size == 0 {
            eprintln!("Bunker is not in Windows startup.");
            return Ok(());
        }

        // Open with write access to delete
        let result = RegOpenKeyExW(HKEY_CURRENT_USER, key_path.as_ptr(), 0, KEY_WRITE, &mut hkey);

        if result != ERROR_SUCCESS {
            return Err(format!("Failed to open registry key for writing: error {}", result).into());
        }

        let result = RegDeleteValueW(hkey, value_name.as_ptr());
        RegCloseKey(hkey);

        if result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND {
            return Err(format!("Failed to delete registry value: error {}", result).into());
        }
    }

    eprintln!("Bunker removed from Windows startup.");
    Ok(())
}
