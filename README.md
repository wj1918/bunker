# Bunker

A lightweight HTTP/HTTPS forward proxy with built-in DNS server, written in Rust.

## Features

- **HTTP Forward Proxy** - Proxy HTTP requests with connection pooling
- **HTTPS Tunneling** - Transparent CONNECT tunneling for HTTPS/SSH/TLS traffic
- **DNS Server** - Optional DNS forwarding with caching and failover
- **Lightweight** - Single binary (~4.8 MB), minimal resource usage
- **Secure** - SSRF protection, rate limiting, IP allowlists
- **Windows Optimized** - System tray icon, auto-start support

## Quick Start

Bunker automatically loads `config.yaml` from the current directory or the executable's directory. Just run:

```powershell
bunker
```

Or specify a config file or CLI arguments:

```powershell
bunker -c C:\path\to\config.yaml
bunker 192.168.1.1:8080 --dns 192.168.1.1:53
```

---

## Windows Setup

### Step 1: Install

**Option A: Install via [Scoop](https://scoop.sh)**

```powershell
scoop bucket add bunker https://github.com/wj1918/bunker
scoop install bunker
```

Scoop places `bunker.exe` and `config.yaml` together in its app directory. The config is automatically persisted across updates. Skip to [Step 2](#step-2-configure-configyaml) to edit the config — Scoop users can open it with:

```powershell
notepad "$(scoop prefix bunker)\config.yaml"
```

**Option B: Download from [GitHub Releases](https://github.com/wj1918/bunker/releases)**

```powershell
mkdir C:\Bunker
cd C:\Bunker

# Download the latest release
$VERSION = "v0.1.0"
Invoke-WebRequest -Uri "https://github.com/wj1918/bunker/releases/download/$VERSION/bunker-$VERSION-x86_64-pc-windows-msvc.zip" -OutFile bunker.zip
```

Verify download integrity before extracting:

```powershell
# Compare against SHA256SUMS.txt from the release page
(Get-FileHash bunker.zip -Algorithm SHA256).Hash
```

Extract and clean up:

```powershell
Expand-Archive bunker.zip -DestinationPath .
Remove-Item bunker.zip
```

The zip contains `bunker.exe`, a sample `config.yaml`, and `README.md`.

**Option C: Build from source**

```powershell
git clone https://github.com/wj1918/bunker.git
cd bunker
cargo build --release

mkdir C:\Bunker
copy target\release\bunker.exe C:\Bunker\
copy config.yaml C:\Bunker\
```

### Step 2: Configure `config.yaml`

Edit the config file (for Option B/C: `C:\Bunker\config.yaml`):

```yaml
# Server listen address (use your Windows machine's LAN IP)
listen_addr: "192.168.1.1:8080"

# Enable system tray icon
tray_enabled: true

# DNS server (optional)
dns:
  listen: "192.168.1.1:53"
  upstreams:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
  cache:
    enabled: true
    max_entries: 10000
  failover:
    timeout_ms: 2000
    serve_stale: true

# Security settings
security:
  block_private_ips: true

  # Restrict access to your LAN clients only
  allowed_source_ips:
    - "192.168.1.0/24"

  rate_limit:
    enabled: true
    max_requests: 100
    window_seconds: 60

  max_connections: 1000
  header_read_timeout_seconds: 30

# Connection pooling
connection_pool:
  enabled: true
  idle_timeout_seconds: 60
  max_connections_per_host: 10

# TCP keep-alive
tcp_keepalive:
  enabled: true
  time_seconds: 60

# Logging
logging:
  log_requests: true
  format: text
  redact_sensitive_headers: true
  file:
    log_dir: "C:\\Bunker\\logs"
    rotation: daily
    max_age_days: 7
    compress: true
```

### Step 3: Windows Firewall

Open **PowerShell as Administrator**:

```powershell
# Allow HTTP Proxy (TCP 8080)
New-NetFirewallRule -DisplayName "Bunker HTTP Proxy" `
    -Direction Inbound -Protocol TCP -LocalPort 8080 `
    -Action Allow -Profile Private,Domain

# Allow DNS Server (UDP 53) - only if using DNS feature
New-NetFirewallRule -DisplayName "Bunker DNS Server" `
    -Direction Inbound -Protocol UDP -LocalPort 53 `
    -Action Allow -Profile Private,Domain
```

Verify: `Get-NetFirewallRule -DisplayName "Bunker*" | Select-Object DisplayName, Enabled, Profile`

Remove: `Get-NetFirewallRule -DisplayName "Bunker*" | Remove-NetFirewallRule`

### Step 4: Run Bunker

Scoop users (Option A) can run bunker from anywhere — the shim and config auto-detection handle everything:

```powershell
bunker
```

For Option B/C, run from the install directory:

```powershell
cd C:\Bunker
.\bunker.exe
```

Bunker auto-detects `config.yaml` in the current directory or the executable's directory. To use a different config:

```powershell
.\bunker.exe -c C:\path\to\config.yaml
```

Other options:

```powershell
.\bunker.exe --install     # Auto-start at Windows login
.\bunker.exe --uninstall   # Remove auto-start
.\bunker.exe --no-tray     # Run without system tray (headless)
```

### Step 5: Verify

```powershell
# Check if listening
netstat -an | findstr ":8080"
netstat -an | findstr ":53"

# Test proxy locally
curl -x http://192.168.1.1:8080 http://httpbin.org/ip

# Test DNS locally
nslookup google.com 192.168.1.1
```

---

## Linux Client Setup

Configure Linux machines to use the Bunker proxy server running on Windows.

### Proxy Configuration

Add to `~/.bashrc` or `~/.zshrc`, then run `source ~/.bashrc`:

```bash
export http_proxy=http://192.168.1.1:8080
export https_proxy=http://192.168.1.1:8080
export HTTP_PROXY=http://192.168.1.1:8080
export HTTPS_PROXY=http://192.168.1.1:8080
export no_proxy=localhost,127.0.0.1,192.168.1.0/24
```

This covers most CLI tools (curl, wget, git, pip, etc). Some applications need their own config:

<details>
<summary>Per-application proxy settings</summary>

**Git SSH (via CONNECT tunnel)** — add to `~/.ssh/config`:

```
Host github.com gitlab.com bitbucket.org
    ProxyCommand nc -X connect -x 192.168.1.1:8080 %h %p
```

**apt (Debian/Ubuntu):**

```bash
sudo tee /etc/apt/apt.conf.d/proxy.conf << 'EOF'
Acquire::http::Proxy "http://192.168.1.1:8080";
Acquire::https::Proxy "http://192.168.1.1:8080";
EOF
```

**yum/dnf** — add to `/etc/yum.conf` or `/etc/dnf/dnf.conf`:

```ini
proxy=http://192.168.1.1:8080
```

**Docker** — add to `~/.docker/config.json`:

```json
{
  "proxies": {
    "default": {
      "httpProxy": "http://192.168.1.1:8080",
      "httpsProxy": "http://192.168.1.1:8080",
      "noProxy": "localhost,127.0.0.1,192.168.1.0/24"
    }
  }
}
```

</details>

### DNS Configuration

Point your Linux DNS to the Bunker server.

**systemd-resolved (Ubuntu 18+, Fedora, Arch):**

```bash
# Edit /etc/systemd/resolved.conf
sudo sed -i 's/^#DNS=.*/DNS=192.168.1.1/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
```

**NetworkManager:**

```bash
nmcli con mod "Wired connection 1" ipv4.dns "192.168.1.1"
nmcli con mod "Wired connection 1" ipv4.ignore-auto-dns yes
nmcli con down "Wired connection 1" && nmcli con up "Wired connection 1"
```

**Manual (temporary):**

```bash
sudo sh -c 'echo "nameserver 192.168.1.1" > /etc/resolv.conf'
```

### Verify Client

```bash
# Test proxy
curl -x http://192.168.1.1:8080 https://httpbin.org/ip

# Test DNS
dig @192.168.1.1 google.com
```

---

## Security Features

| Feature | Description |
|---------|-------------|
| SSRF Protection | Blocks requests to private IPs (127.x, 10.x, 172.16-31.x, 192.168.x) |
| DNS Rebinding Protection | Validates all resolved IPs before connecting |
| Rate Limiting | Per-IP request limits with IPv6 /64 subnet support |
| Connection Limits | Configurable max concurrent connections |
| IP Allowlist | Restrict proxy access to specific IPs/CIDRs |
| Header Sanitization | Redacts sensitive headers in logs |
| Slowloris Protection | Header read timeout |
| Request Size Limits | Configurable max request body size |

> **Note**: Bunker does not implement proxy authentication. Access control is managed via IP allowlists and network-level security.

---

## Supported Protocols

| Protocol | Support | Method |
|----------|---------|--------|
| HTTP | Yes | Direct proxy |
| HTTPS | Yes | CONNECT tunnel |
| SSH/SFTP | Yes | CONNECT tunnel |
| WebSocket (wss://) | Yes | CONNECT tunnel |
| Any TLS/TCP | Yes | CONNECT tunnel |
| DNS (UDP) | Yes | Built-in server |
| SOCKS5 | No | Not supported |
| HTTP/2 | No | Not supported |

---

## Troubleshooting

### Windows Server

**Proxy not accessible from LAN:**

```powershell
Get-NetFirewallRule -DisplayName "Bunker*" | Format-List
netstat -an | findstr ":8080"
Get-NetConnectionProfile
```

**DNS not responding:**

```powershell
netstat -an | findstr ":53"
nslookup google.com 127.0.0.1
```

### Linux Client

**Proxy connection refused:**

```bash
ping 192.168.1.1
nc -zv 192.168.1.1 8080
env | grep -i proxy
```

**DNS not resolving:**

```bash
dig @192.168.1.1 google.com
cat /etc/resolv.conf
resolvectl status
```

**Git SSH not working through proxy:**

```bash
ssh -vvv -o ProxyCommand="nc -X connect -x 192.168.1.1:8080 %h %p" git@github.com
# If nc doesn't support -X flag: sudo apt install netcat-openbsd
```

---

## Architecture

```
Linux Clients                     Windows Server (Bunker)
─────────────                     ───────────────────────
                                  ┌─────────────────────────────────┐
┌─────────┐                       │         Bunker Proxy            │
│ Browser │──HTTP/HTTPS──────────►│                                 │
│  curl   │                       │  ┌──────────┐   ┌───────────┐  │
│  wget   │                       │  │ Security │──►│   HTTP    │──┼──► Internet
└─────────┘                       │  │  Layer   │   │  Handler  │  │
                                  │  └──────────┘   └───────────┘  │
┌─────────┐                       │        │                       │
│   Git   │──SSH (CONNECT)───────►│        ▼        ┌───────────┐  │
│   SSH   │                       │  ┌──────────┐   │  CONNECT  │──┼──► Target
└─────────┘                       │  │ Allowlist│──►│  Tunnel   │  │
                                  │  └──────────┘   └───────────┘  │
┌─────────┐                       │                                │
│  Apps   │──DNS Query───────────►│  ┌──────────┐   ┌───────────┐  │
│(resolv) │                       │  │  Cache   │◄─►│    DNS    │──┼──► Upstream
└─────────┘                       │  │  (TTL)   │   │  Server   │  │     DNS
                                  │  └──────────┘   └───────────┘  │
                                  └─────────────────────────────────┘
```

---

## Building

### Requirements

- Rust 1.70+
- Windows: MSVC toolchain

### Commands

```powershell
cargo build --release    # Release build
cargo build              # Debug build
cargo test               # Run tests
cargo check              # Syntax check only
```

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
