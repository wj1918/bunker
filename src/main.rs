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
    customize_default_config, load_config, user_config_path, AllowlistOverride, Config,
};
use dns::run_dns_server;
use helpers::create_tls_connector;
use platform::net_discovery::{
    assume_slash_24, discover_all_lan_interfaces, discover_lan_interface, interface_for_ipv4,
};
use proxy::{handle_client, SenderPool};
use security::{is_source_ip_allowed, RateLimiter};

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, error, warn};

#[cfg(windows)]
use std::sync::mpsc;

#[cfg(windows)]
use platform::windows_tray::{hide_window, setup_tray, show_window, TrayMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();

    // Parse command line arguments.
    //
    // Runtime CLI surface is intentionally minimal: only `-c <path>`, `--help`,
    // `--version`, and (on Windows) `--install` / `--uninstall`. Everything
    // else (bind address, allowlist, DNS, tray) is configured via the YAML
    // file. `--listen` / `--dns` / `--dns-upstream` are only valid in
    // combination with `--init`, where they shape the generated file.
    let mut config_path: Option<&str> = None;
    let mut cli_listen_addr: Option<String> = None;
    let mut cli_dns_addr: Option<String> = None;
    let mut cli_dns_upstream: Option<String> = None;
    let mut do_init = false;
    let mut init_mode = InitMode::Loopback;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                config_path = args.get(i).map(|s| s.as_str());
            }
            "--listen" => {
                i += 1;
                cli_listen_addr = args.get(i).cloned();
            }
            "--dns" => {
                i += 1;
                cli_dns_addr = args.get(i).cloned();
            }
            "--dns-upstream" => {
                i += 1;
                cli_dns_upstream = args.get(i).cloned();
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                return Ok(());
            }
            "-V" | "--version" => {
                println!("bunker {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--init" => {
                do_init = true;
                // Optional next-token mode: `loopback`, `lan`, or `custom`.
                // If the next token isn't one of those exact words we leave
                // it alone — the parser has no other positional slot now,
                // so a bad value will fall through to `Unknown argument`.
                if let Some(next) = args.get(i + 1) {
                    if let Some(mode) = InitMode::parse(next) {
                        init_mode = mode;
                        i += 1;
                    }
                }
            }
            #[cfg(windows)]
            "--install" => {
                return install_startup(config_path);
            }
            #[cfg(windows)]
            "--uninstall" => {
                return uninstall_startup();
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_usage(&args[0]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if do_init {
        return init_config(
            init_mode,
            cli_listen_addr.as_deref(),
            cli_dns_addr.as_deref(),
            cli_dns_upstream.as_deref(),
        );
    }

    // Reject `--listen` / `--dns` / `--dns-upstream` outside of `--init`.
    // Runtime configuration is sourced exclusively from the YAML file; CLI
    // overrides at runtime would mask config values and resurrect the
    // "bind widened but allowlist still loopback" trap.
    let mut init_only_flags = Vec::new();
    if cli_listen_addr.is_some() {
        init_only_flags.push("--listen");
    }
    if cli_dns_addr.is_some() {
        init_only_flags.push("--dns");
    }
    if cli_dns_upstream.is_some() {
        init_only_flags.push("--dns-upstream");
    }
    if !init_only_flags.is_empty() {
        eprintln!(
            "Error: {} only valid with --init.",
            init_only_flags.join(", ")
        );
        eprintln!("Runtime configuration comes from the YAML file. To change these values:");
        eprintln!("  - Edit ~/.bunker/config.yaml (or the file you pass to `-c`) and restart, or");
        eprintln!("  - Regenerate the file: bunker --init [mode] [those flags]");
        std::process::exit(1);
    }

    // Load config from file. With no overrides at runtime, the YAML file is
    // the sole source of truth — so we refuse to start without one, rather
    // than silently using built-in defaults that might surprise the user.
    let config = match load_config(config_path)? {
        Some(c) => c,
        None => {
            eprintln!("Error: no config file found.");
            eprintln!("Searched (in order):");
            if let Some(p) = config_path {
                eprintln!("  {}", p);
            } else {
                eprintln!("  ./config.yaml");
                if let Some(p) = user_config_path() {
                    eprintln!("  {}", p.display());
                }
                eprintln!("  <exe-dir>/config.yaml");
            }
            eprintln!("Run 'bunker --init' to create one.");
            std::process::exit(1);
        }
    };

    // Initialize logging system
    let _log_guard = logging::init_logging(&config.logging);

    // Spawn log cleanup task if file logging enabled
    logging::spawn_log_cleanup_task(Arc::new(config.logging.clone()));

    tracing::debug!(config = ?config, "Configuration loaded");

    // Setup tray on Windows
    #[cfg(windows)]
    let tray_rx = if config.app.tray_enabled {
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
        let dns_allowed_ips = config.proxy.security.allowed_source_ips.clone();
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

    // If the proxy is disabled, run in DNS-only mode (requires DNS enabled).
    if !config.proxy.enabled {
        if config.dns.is_none() {
            eprintln!("Error: proxy.enabled = false and dns is not configured — nothing to do.");
            std::process::exit(1);
        }
        println!("Proxy disabled — running in DNS-only mode. Press Ctrl-C to stop.");
        std::future::pending::<()>().await;
        unreachable!();
    }

    let listen_addr: SocketAddr = config.proxy.listen.parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    println!("Forward proxy listening on http://{}", listen_addr);

    // Share configs across tasks
    let security_config = Arc::new(config.proxy.security.clone());
    let logging_config = Arc::new(config.logging.clone());
    let tcp_keepalive_config = Arc::new(config.proxy.tcp_keepalive.clone());

    // Log TCP keep-alive settings
    if config.proxy.tcp_keepalive.enabled {
        println!(
            "TCP keep-alive: enabled (time={}s, interval={}s)",
            config.proxy.tcp_keepalive.time_seconds, config.proxy.tcp_keepalive.interval_seconds
        );
    }

    // Create rate limiter
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(
        config.proxy.security.rate_limit.clone(),
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
    let pool_config = config.proxy.connection_pool.clone();
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
    let max_connections = config.proxy.security.max_connections;
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

    // Handle tray messages in background (blocking thread — channel is std::sync::mpsc)
    #[cfg(windows)]
    if let Some(rx) = tray_rx {
        std::thread::spawn(move || {
            while let Ok(msg) = rx.recv() {
                match msg {
                    TrayMessage::Quit => {
                        println!("Quit requested from tray");
                        std::process::exit(0);
                    }
                    TrayMessage::Minimize => {
                        println!("Minimize requested from tray");
                        hide_window();
                    }
                    TrayMessage::BringToFront => {
                        println!("Bring to front requested from tray");
                        show_window();
                    }
                }
            }
        });
    }

    // Pre-compute allowed source IPs for fast lookup
    let allowed_source_ips = config.proxy.security.allowed_source_ips.clone();
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

            if let Err(err) = handle_client(
                stream,
                client_addr,
                tls_connector,
                security,
                logging,
                tcp_keepalive,
                pool,
            )
            .await
            {
                // Demote benign client-lifecycle errors (idle keep-alive timeout, peer FIN
                // mid-parse) to debug. Real proxy errors still log at error level.
                let benign = err
                    .downcast_ref::<hyper::Error>()
                    .map(|e| e.is_timeout() || e.is_incomplete_message())
                    .unwrap_or(false);
                if benign {
                    debug!(client = %client_addr, error = ?err, "Client connection closed");
                } else {
                    error!(client = %client_addr, error = ?err, "Error serving client");
                }
            }
        });
    }
}

/// Initialization preset chosen via `bunker --init [mode]`.
#[derive(Clone, Copy, Debug)]
enum InitMode {
    /// Default: bind 127.0.0.1, shipped allowlist (`127.0.0.1`, `::1`).
    Loopback,
    /// Auto-discover a single RFC 1918 interface, bind to its IP, set the
    /// allowlist to its subnet. Errors out on multi-NIC or no-NIC hosts.
    Lan,
    /// Require `--listen`/`--dns`/`--dns-upstream`. Derive the allowlist from
    /// the `--listen` address: matching interface → that interface's CIDR;
    /// wildcard → union of all detected LAN subnets; loopback → loopback
    /// allowlist; unmatched non-local IP → assumed /24.
    Custom,
}

impl InitMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "loopback" => Some(Self::Loopback),
            "lan" => Some(Self::Lan),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Lan => "lan",
            Self::Custom => "custom",
        }
    }
}

/// Concrete decisions reached by interpreting the mode and CLI overrides.
/// Drives both the YAML rewrite and the post-write summary.
struct InitPlan {
    proxy_listen: Option<String>,
    dns_listen: Option<String>,
    dns_upstream: Option<String>,
    allowed_source_ips: Option<Vec<String>>,
    allowlist_annotation: Option<String>,
}

impl InitPlan {
    fn has_overrides(&self) -> bool {
        self.proxy_listen.is_some()
            || self.dns_listen.is_some()
            || self.dns_upstream.is_some()
            || self.allowed_source_ips.is_some()
    }
}

/// Write the embedded default config.yaml to the per-user config dir
/// (`%USERPROFILE%\.bunker\config.yaml` on Windows, `$HOME/.bunker/config.yaml` on Unix),
/// customized according to `mode` and any explicit CLI overrides.
fn init_config(
    mode: InitMode,
    proxy_listen: Option<&str>,
    dns_listen: Option<&str>,
    dns_upstream: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Validate any overrides as SocketAddrs *before* touching disk, so a typo
    // surfaces immediately instead of producing a broken config.
    for (flag, value) in [
        ("--listen", proxy_listen),
        ("--dns", dns_listen),
        ("--dns-upstream", dns_upstream),
    ] {
        if let Some(v) = value {
            v.parse::<SocketAddr>()
                .map_err(|e| format!("Invalid value for {}: {} ({})", flag, v, e))?;
        }
    }

    let plan = build_init_plan(mode, proxy_listen, dns_listen, dns_upstream)?;

    let path = user_config_path()
        .ok_or("Could not determine home directory (USERPROFILE/HOME not set)")?;
    if path.exists() {
        eprintln!("Config already exists at: {}", path.display());
        eprintln!("Remove or rename it first if you want to regenerate.");
        std::process::exit(1);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let allowlist_override = plan
        .allowed_source_ips
        .as_ref()
        .map(|entries| AllowlistOverride {
            entries: entries.as_slice(),
            annotation: plan.allowlist_annotation.as_deref(),
        });

    let yaml = customize_default_config(
        plan.proxy_listen.as_deref(),
        plan.dns_listen.as_deref(),
        plan.dns_upstream.as_deref(),
        allowlist_override.as_ref(),
    );

    // Round-trip through the strict deserializer so we never write a file the
    // proxy itself would refuse to load.
    serde_yaml_ng::from_str::<Config>(&yaml)
        .map_err(|e| format!("Generated config failed to parse: {}", e))?;

    std::fs::write(&path, &yaml)?;
    eprintln!("Created config at: {}", path.display());
    eprintln!("Init mode: {}", mode.as_str());
    if plan.has_overrides() {
        eprintln!("Applied overrides:");
        if let Some(v) = plan.proxy_listen.as_ref() {
            eprintln!("  proxy.listen        = {}", v);
        }
        if let Some(v) = plan.dns_listen.as_ref() {
            eprintln!("  dns.listen          = {}", v);
        }
        if let Some(v) = plan.dns_upstream.as_ref() {
            eprintln!("  dns.upstreams       = [{}]", v);
        }
        if let Some(entries) = plan.allowed_source_ips.as_ref() {
            eprintln!("  allowed_source_ips  = {:?}", entries);
        }
    }
    eprintln!("Edit it to match your environment, then run:");
    eprintln!("  bunker");
    Ok(())
}

fn build_init_plan(
    mode: InitMode,
    cli_proxy_listen: Option<&str>,
    cli_dns_listen: Option<&str>,
    cli_dns_upstream: Option<&str>,
) -> Result<InitPlan, Box<dyn std::error::Error + Send + Sync>> {
    match mode {
        InitMode::Loopback => Ok(InitPlan {
            proxy_listen: cli_proxy_listen.map(String::from),
            dns_listen: cli_dns_listen.map(String::from),
            dns_upstream: cli_dns_upstream.map(String::from),
            allowed_source_ips: None,
            allowlist_annotation: None,
        }),
        InitMode::Lan => {
            let iface = discover_lan_interface().map_err(|e| -> Box<
                dyn std::error::Error + Send + Sync,
            > { format!("{}", e).into() })?;
            let bind_proxy = format!("{}:8080", iface.ip);
            let bind_dns = format!("{}:53", iface.ip);
            let annotation = format!(
                "Set by `bunker --init lan` from interface {} ({}).",
                iface.name, iface.ip
            );
            Ok(InitPlan {
                proxy_listen: Some(cli_proxy_listen.map(String::from).unwrap_or(bind_proxy)),
                dns_listen: Some(cli_dns_listen.map(String::from).unwrap_or(bind_dns)),
                dns_upstream: cli_dns_upstream.map(String::from),
                allowed_source_ips: Some(vec![iface.cidr]),
                allowlist_annotation: Some(annotation),
            })
        }
        InitMode::Custom => {
            let listen = cli_proxy_listen.ok_or(
                "custom mode requires --listen <addr> (e.g. --listen 192.168.5.42:8080)",
            )?;
            let dns = cli_dns_listen
                .ok_or("custom mode requires --dns <addr> (e.g. --dns 192.168.5.42:53)")?;
            let upstream = cli_dns_upstream
                .ok_or("custom mode requires --dns-upstream <addr> (e.g. --dns-upstream 9.9.9.9:53)")?;
            let listen_sa: SocketAddr = listen.parse().expect("validated upstream");
            let (entries, annotation) = derive_custom_allowlist(listen_sa);
            Ok(InitPlan {
                proxy_listen: Some(listen.to_string()),
                dns_listen: Some(dns.to_string()),
                dns_upstream: Some(upstream.to_string()),
                allowed_source_ips: Some(entries),
                allowlist_annotation: Some(annotation),
            })
        }
    }
}

/// Pick an allowlist for `--init custom` based on the listen address. Never
/// errors — every input shape produces some sensible config (per spec: edge
/// cases should not block init).
fn derive_custom_allowlist(listen: SocketAddr) -> (Vec<String>, String) {
    let ip = listen.ip();

    // Wildcard bind: union of all detected LAN subnets, or loopback fallback.
    if ip.is_unspecified() {
        let candidates = discover_all_lan_interfaces();
        if candidates.is_empty() {
            return (
                vec!["127.0.0.1".to_string(), "::1".to_string()],
                "Set by `bunker --init custom` (wildcard bind, no LAN interface detected — \
                 only loopback can reach this listener)."
                    .to_string(),
            );
        }
        let cidrs: Vec<String> = candidates.into_iter().map(|c| c.cidr).collect();
        return (
            cidrs,
            "Set by `bunker --init custom` from wildcard bind (all detected LAN subnets)."
                .to_string(),
        );
    }

    // Loopback bind: mirror the loopback preset.
    if ip.is_loopback() {
        return (
            vec!["127.0.0.1".to_string(), "::1".to_string()],
            "Set by `bunker --init custom` (loopback bind).".to_string(),
        );
    }

    // IPv4: prefer a matching local interface; otherwise assume /24.
    if let IpAddr::V4(v4) = ip {
        if let Some(iface) = interface_for_ipv4(v4) {
            let annotation = format!(
                "Set by `bunker --init custom` from interface {} ({}).",
                iface.name, iface.ip
            );
            return (vec![iface.cidr], annotation);
        }
        if let Some(cidr) = assume_slash_24(ip) {
            let annotation = format!(
                "Set by `bunker --init custom` (assumed /24 around {} — narrow or widen \
                 to match your actual network).",
                v4
            );
            return (vec![cidr], annotation);
        }
    }

    // IPv6 non-loopback with no derivation hook: fall back to loopback so the
    // file is at least safe. The user can widen it manually.
    (
        vec!["127.0.0.1".to_string(), "::1".to_string()],
        "Set by `bunker --init custom` (no automatic derivation for this listen address — \
         edit the file to match your network)."
            .to_string(),
    )
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} [options]", program);
    eprintln!();
    eprintln!("Generic HTTP/HTTPS forward proxy with optional DNS server.");
    eprintln!("Supports both IPv4 and IPv6.");
    eprintln!();
    eprintln!("Runtime: configuration is loaded from a YAML file. There are no CLI");
    eprintln!("overrides at runtime — edit the file (or pass `-c <path>`) to change");
    eprintln!("settings, then restart.");
    eprintln!();
    eprintln!("Runtime options:");
    eprintln!("  -c, --config <path>     Load config from YAML file");
    eprintln!("                          (default search order: ./config.yaml,");
    eprintln!("                          ~/.bunker/config.yaml, <exe-dir>/config.yaml)");
    eprintln!("  -h, --help              Show this help message");
    eprintln!("  -V, --version           Print version and exit");
    #[cfg(windows)]
    {
        eprintln!("  --install               Add to Windows startup");
        eprintln!("  --uninstall             Remove from Windows startup");
    }
    eprintln!();
    eprintln!("Init: write a config file (refuses to overwrite an existing one).");
    eprintln!();
    eprintln!("Init options:");
    eprintln!(
        "  --init [mode]           Create config at ~/.bunker/config.yaml. Modes:"
    );
    eprintln!("                            loopback  (default) bind 127.0.0.1; loopback allowlist");
    eprintln!("                            lan                 auto-discover LAN interface; bind");
    eprintln!("                                                to its IP; allowlist = its subnet");
    eprintln!("                            custom              requires --listen/--dns/");
    eprintln!("                                                --dns-upstream; allowlist derived");
    eprintln!("                                                from --listen address");
    eprintln!("  --listen <addr>         Proxy listen address (with --init only)");
    eprintln!("  --dns <addr>            DNS server listen address (with --init only)");
    eprintln!("  --dns-upstream <addr>   Upstream DNS server (with --init only)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {}                                           # run with config file", program);
    eprintln!("  {} -c /path/to/config.yaml                   # run with explicit config", program);
    eprintln!("  {} --init                                    # write loopback default config", program);
    eprintln!("  {} --init lan                                # auto-discover LAN interface", program);
    eprintln!(
        "  {} --init custom --listen 192.168.1.5:8080 --dns 192.168.1.5:53 --dns-upstream 9.9.9.9:53",
        program
    );
    eprintln!();
    eprintln!("Client usage:");
    eprintln!("  curl -x http://proxy:8080 http://example.com");
    eprintln!("  curl -x http://proxy:8080 https://example.com");
    #[cfg(windows)]
    {
        eprintln!();
        eprintln!("Windows startup examples:");
        eprintln!(
            "  {} --install                                 # add to Windows startup",
            program
        );
        eprintln!(
            "  {} --install -c config.yaml                  # add with explicit config",
            program
        );
        eprintln!(
            "  {} --uninstall                               # remove from Windows startup",
            program
        );
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
fn install_startup(
    config_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        let cfg_abs_str = cfg_abs_str
            .strip_prefix(r"\\?\")
            .unwrap_or(&cfg_abs_str)
            .to_string();
        let dir = std::path::Path::new(&cfg_abs_str)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| exe_dir.to_path_buf());
        (dir, Some(cfg_abs_str))
    } else {
        (exe_dir.to_path_buf(), None)
    };

    // Load and verify config file if specified. A missing file is reported
    // as `None` from `load_config`; here we just skip the log-dir pre-create
    // step in that case rather than erroring — the runtime entrypoint will
    // surface the missing-file error on the next launch.
    if let Some(cfg_path) = config_path {
        if let Some(config) = load_config(Some(cfg_path))? {
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
    }

    // Build the command string
    let work_dir_str = work_dir.to_string_lossy();
    let cmd_value = if let Some(cfg_abs) = cfg_abs_path {
        format!(
            r#"cmd /c cd /d "{}" && "{}" -c "{}""#,
            work_dir_str, exe_path, cfg_abs
        )
    } else {
        format!(r#"cmd /c cd /d "{}" && "{}""#, work_dir_str, exe_path)
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
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key_path.as_ptr(),
            0,
            KEY_WRITE,
            &mut hkey,
        );

        if result != ERROR_SUCCESS {
            return Err(
                format!("Failed to open registry key for writing: error {}", result).into(),
            );
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
