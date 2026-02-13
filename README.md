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

```powershell
# Run with config file
.\bunker.exe --config config.yaml

# Or run with CLI arguments
.\bunker.exe 192.168.1.1:8080 --dns 192.168.1.1:53
```

---

## Windows Server Setup

### Step 1: Install

**Option A: Download from [GitHub Releases](https://github.com/wj1918/bunker/releases)**

```powershell
mkdir C:\Bunker
cd C:\Bunker

# Download the latest release (replace VERSION with actual version, e.g., v0.1.0)
$VERSION = "v0.1.0"
Invoke-WebRequest -Uri "https://github.com/wj1918/bunker/releases/download/$VERSION/bunker-$VERSION-x86_64-pc-windows-msvc.zip" -OutFile bunker.zip

# Extract and clean up
Expand-Archive bunker.zip -DestinationPath .
Remove-Item bunker.zip
```

The zip contains `bunker.exe`, a sample `config.yaml`, and `README.md`.

**Verify download integrity:**

```powershell
# Compare against SHA256SUMS.txt from the release page
(Get-FileHash bunker.exe -Algorithm SHA256).Hash
```

**Option B: Build from source**

```powershell
git clone https://github.com/wj1918/bunker.git
cd bunker
cargo build --release

mkdir C:\Bunker
copy target\release\bunker.exe C:\Bunker\
copy config.yaml C:\Bunker\
```

### Step 2: Configure `config.yaml`

Edit `C:\Bunker\config.yaml`:

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

### Step 3: Windows Firewall Configuration

Open **PowerShell as Administrator** and run:

```powershell
# Allow HTTP Proxy (TCP 8080)
New-NetFirewallRule -DisplayName "Bunker HTTP Proxy" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8080 `
    -Action Allow `
    -Profile Private,Domain `
    -Description "Bunker proxy server for HTTP/HTTPS forwarding"

# Allow DNS Server (UDP 53) - only if using DNS feature
New-NetFirewallRule -DisplayName "Bunker DNS Server" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 53 `
    -Action Allow `
    -Profile Private,Domain `
    -Description "Bunker DNS server for LAN clients"
```

**For Public network profile** (more restrictive environments):

```powershell
# Use GPO-based rules for Public profile
New-NetFirewallRule -DisplayName "Bunker HTTP Proxy (Public)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8080 `
    -Action Allow `
    -Profile Public `
    -PolicyStore PersistentStore

New-NetFirewallRule -DisplayName "Bunker DNS Server (Public)" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 53 `
    -Action Allow `
    -Profile Public `
    -PolicyStore PersistentStore
```

**Verify firewall rules:**

```powershell
Get-NetFirewallRule -DisplayName "Bunker*" |
    Select-Object DisplayName, Enabled, Action, Profile
```

**Remove rules (if needed):**

```powershell
Get-NetFirewallRule -DisplayName "Bunker*" | Remove-NetFirewallRule
```

### Step 4: Run Bunker

**Manual start:**

```powershell
cd C:\Bunker
.\bunker.exe --config config.yaml
```

**Run at Windows startup (auto-start):**

```powershell
# Register for auto-start
.\bunker.exe --install

# Remove from auto-start
.\bunker.exe --uninstall
```

**Run without system tray (headless/service mode):**

```powershell
.\bunker.exe --config config.yaml --no-tray
```

### Step 5: Verify Server is Running

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

#### Environment Variables (Session)

```bash
# Set for current session
export http_proxy=http://192.168.1.1:8080
export https_proxy=http://192.168.1.1:8080
export HTTP_PROXY=http://192.168.1.1:8080
export HTTPS_PROXY=http://192.168.1.1:8080
export no_proxy=localhost,127.0.0.1,192.168.1.0/24
```

#### Permanent Configuration

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# Bunker proxy settings
export http_proxy=http://192.168.1.1:8080
export https_proxy=http://192.168.1.1:8080
export HTTP_PROXY=http://192.168.1.1:8080
export HTTPS_PROXY=http://192.168.1.1:8080
export no_proxy=localhost,127.0.0.1,192.168.1.0/24
```

Apply changes:

```bash
source ~/.bashrc
```

#### Per-Application Configuration

**Git (HTTPS repositories):**

```bash
git config --global http.proxy http://192.168.1.1:8080
git config --global https.proxy http://192.168.1.1:8080

# Remove proxy config
git config --global --unset http.proxy
git config --global --unset https.proxy
```

**Git (SSH repositories via CONNECT tunnel):**

Add to `~/.ssh/config`:

```
Host github.com gitlab.com bitbucket.org
    ProxyCommand nc -X connect -x 192.168.1.1:8080 %h %p
```

Or using `corkscrew`:

```bash
sudo apt install corkscrew
```

```
Host github.com
    ProxyCommand corkscrew 192.168.1.1 8080 %h %p
```

**npm:**

```bash
npm config set proxy http://192.168.1.1:8080
npm config set https-proxy http://192.168.1.1:8080

# Remove
npm config delete proxy
npm config delete https-proxy
```

**apt (Debian/Ubuntu):**

```bash
sudo tee /etc/apt/apt.conf.d/proxy.conf << 'EOF'
Acquire::http::Proxy "http://192.168.1.1:8080";
Acquire::https::Proxy "http://192.168.1.1:8080";
EOF
```

**yum/dnf (RHEL/CentOS/Fedora):**

Add to `/etc/yum.conf` or `/etc/dnf/dnf.conf`:

```ini
proxy=http://192.168.1.1:8080
```

**Docker:**

```bash
mkdir -p ~/.docker
cat > ~/.docker/config.json << 'EOF'
{
  "proxies": {
    "default": {
      "httpProxy": "http://192.168.1.1:8080",
      "httpsProxy": "http://192.168.1.1:8080",
      "noProxy": "localhost,127.0.0.1,192.168.1.0/24"
    }
  }
}
EOF
```

**wget:**

Add to `~/.wgetrc`:

```
http_proxy = http://192.168.1.1:8080
https_proxy = http://192.168.1.1:8080
use_proxy = on
```

**curl:**

Add to `~/.curlrc`:

```
proxy = http://192.168.1.1:8080
```

### DNS Client Configuration

Configure Linux to use Bunker's DNS server.

#### systemd-resolved (Ubuntu 18+, Fedora, Arch)

```bash
# Edit resolved.conf
sudo nano /etc/systemd/resolved.conf
```

Add:

```ini
[Resolve]
DNS=192.168.1.1
FallbackDNS=8.8.8.8
```

Apply:

```bash
sudo systemctl restart systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

Verify:

```bash
resolvectl status
resolvectl query google.com
```

#### NetworkManager (Desktop Linux)

```bash
# List connections
nmcli con show

# Set DNS for your connection (replace "Wired connection 1" with your connection name)
nmcli con mod "Wired connection 1" ipv4.dns "192.168.1.1"
nmcli con mod "Wired connection 1" ipv4.ignore-auto-dns yes

# Reconnect to apply
nmcli con down "Wired connection 1" && nmcli con up "Wired connection 1"
```

#### netplan (Ubuntu Server)

Edit `/etc/netplan/01-netcfg.yaml`:

```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
      nameservers:
        addresses: [192.168.1.1]
```

Apply:

```bash
sudo netplan apply
```

#### Manual (Temporary)

```bash
sudo sh -c 'echo "nameserver 192.168.1.1" > /etc/resolv.conf'
```

### Verify Client Configuration

```bash
# Test proxy connection
curl -x http://192.168.1.1:8080 http://httpbin.org/ip
curl -x http://192.168.1.1:8080 https://httpbin.org/ip

# Test DNS resolution
nslookup google.com 192.168.1.1
dig @192.168.1.1 google.com

# Test SSH through proxy
ssh -T git@github.com

# Test Git clone
git clone https://github.com/rust-lang/rust.git --depth 1
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
| HTTP | ✅ | Direct proxy |
| HTTPS | ✅ | CONNECT tunnel |
| SSH/SFTP | ✅ | CONNECT tunnel |
| WebSocket (wss://) | ✅ | CONNECT tunnel |
| Any TLS/TCP | ✅ | CONNECT tunnel |
| DNS (UDP) | ✅ | Built-in server |
| SOCKS5 | ❌ | Not supported |
| HTTP/2 | ❌ | Not supported |

---

## Troubleshooting

### Windows Server

**Proxy not accessible from LAN:**

```powershell
# Check Windows Firewall rules
Get-NetFirewallRule -DisplayName "Bunker*" | Format-List

# Check if listening on correct interface
netstat -an | findstr ":8080"

# Verify network profile
Get-NetConnectionProfile
```

**DNS not responding:**

```powershell
# Check UDP 53 is open
netstat -an | findstr ":53"

# Test locally
nslookup google.com 127.0.0.1
```

### Linux Client

**Proxy connection refused:**

```bash
# Test connectivity to Windows server
ping 192.168.1.1
nc -zv 192.168.1.1 8080

# Check environment variables
env | grep -i proxy
```

**DNS not resolving:**

```bash
# Test direct DNS query
dig @192.168.1.1 google.com

# Check resolv.conf
cat /etc/resolv.conf

# Check systemd-resolved status
resolvectl status
```

**Git SSH not working through proxy:**

```bash
# Test SSH proxy connection
ssh -vvv -o ProxyCommand="nc -X connect -x 192.168.1.1:8080 %h %p" git@github.com

# Verify nc supports -X flag (may need netcat-openbsd)
sudo apt install netcat-openbsd
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

```bash
cargo build --release    # Release build
cargo build              # Debug build
cargo test               # Run tests
cargo check              # Syntax check only
```

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
