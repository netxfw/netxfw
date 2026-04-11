# netxfw — The eXtensible eBPF Firewall

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![BPF License](https://img.shields.io/badge/BPF-Dual%20BSD/GPL-purple.svg)](bpf/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/netxfw/netxfw)](https://goreportcard.com/report/github.com/netxfw/netxfw)
[![Release](https://img.shields.io/github/v/release/netxfw/netxfw)](https://github.com/netxfw/netxfw/releases)
[![Chinese README](https://img.shields.io/badge/README-中文-red.svg)](README.md)

> **Lightweight · High-Performance · Extensible**
> A next-generation Linux host firewall based on eBPF/XDP.

`netxfw` is a high-performance firewall built using modern Linux kernel eBPF technology. It processes packets directly at the network driver layer (XDP), allowing it to block large-scale DDoS attacks, brute-force attempts, and illegal scans with minimal CPU overhead.

---

## 📋 Table of Contents

- [🚀 Quick Start](#-quick-start)
- [⚡ Quick Command Reference](#-quick-command-reference)
- [✨ Key Features](#-key-features)
- [⚙️ Configuration](#️-configuration)
- [🏗️ Architecture](#️-architecture)
- [🔧 Maintenance & Updates](#-maintenance--updates)
- [📚 Documentation](#-documentation)

---

## 🚀 Quick Start

### 1. Installation

#### Method A: Binary Download (Recommended)
Download the latest version from the [Releases](https://github.com/netxfw/netxfw/releases) page:

- **x86_64 (amd64)**:
  ```bash
  wget https://github.com/netxfw/netxfw/releases/latest/download/netxfw_Linux_x86_64.tar.gz
  ```
- **ARM64 (aarch64)**:
  ```bash
  wget https://github.com/netxfw/netxfw/releases/latest/download/netxfw_Linux_arm64.tar.gz
  ```

**Install**:
```bash
tar -zxvf netxfw_Linux_*.tar.gz
sudo mv netxfw /usr/local/bin/
```

#### Method B: Build from Source

**Requirements**:
- Linux Kernel >= 6.x
- Go >= 1.24 (the repository currently declares `go 1.24.0` and `toolchain go1.24.12`)

**Install Build Tools**:
```bash
# Debian/Ubuntu
sudo apt-get install -y clang llvm libelf-dev libbpf-dev make
```

**Build**:
```bash
git clone https://github.com/netxfw/netxfw.git
cd netxfw
make generate
make
```

### 2. Running

#### 🚀 XDP Modes & Adaptive Fallback
`netxfw` supports multiple XDP modes and automatically attempts loading based on hardware/driver support, ordered by performance:
- **Offloaded (`xdp_hw`)**: Hardware offload mode, executes directly on NIC SOC, no host CPU usage, best performance.
- **Native (`xdp_drv`)**: Native driver mode, processes at driver receive path, excellent performance.
- **Generic (`xdp_skb`)**: Generic mode, emulated by kernel (after SKB), no driver support required, best compatibility (for cloud servers/VMs).

```bash
# Load with default configuration and adaptive mode selection
sudo netxfw system load
```

---

## ⚡ Quick Command Reference

### Basic Operations

```bash
# System Management
sudo netxfw system load                   # Load XDP program
sudo netxfw system unload                 # Unload XDP program
sudo netxfw system status                 # View running status
sudo netxfw system reload                 # Hot reload configuration

# Monitoring
sudo netxfw status                        # View firewall status
sudo netxfw conntrack                     # View connection tracking table
sudo netxfw perf show                     # View performance statistics

# Whitelist Management
sudo netxfw allow 192.168.1.100           # Add IP to whitelist
sudo netxfw allow add 10.0.0.1            # Add IP to whitelist (subcommand form)
sudo netxfw allow list                    # List whitelist
sudo netxfw allow port list               # List IP+Port allow rules

# Blacklist Management
sudo netxfw deny 192.168.1.100            # Add IP to static blacklist
sudo netxfw deny add 10.0.0.1 --ttl 1h    # Add to dynamic blacklist (expires in 1 hour)
sudo netxfw deny list                     # List all blacklists
sudo netxfw deny list --dynamic           # List dynamic blacklist only
sudo netxfw deny port list                # List IP+Port deny rules

# Dynamic Blacklist Management (supports alias: dyn)
sudo netxfw dynamic add 192.168.1.100 --ttl 1h   # Add dynamic blacklist entry
sudo netxfw dyn del 192.168.1.100                # Delete dynamic entry (using alias)
sudo netxfw dynamic list                         # List dynamic blacklist

# Rule Management
sudo netxfw rule add 192.168.1.0/24 deny           # Add rule
sudo netxfw rule list                              # List rules
sudo netxfw rule del 192.168.1.0/24                # Delete rule (supports delete/remove aliases)
sudo netxfw rule export rules.toml                 # Export rules
sudo netxfw rule import all rules.toml             # Import rules

# Port Rule Management (IP+Port level control)
sudo netxfw allow 192.168.1.100:8080     # Allow specific IP+Port
sudo netxfw deny 10.0.0.1:443            # Deny specific IP+Port
sudo netxfw rule add 192.168.1.100:8080 allow            # Add IP+Port allow rule
sudo netxfw rule add 10.0.0.1:443 deny                   # Add IP+Port deny rule
sudo netxfw rule del 192.168.1.100:8080                  # Delete IP+Port rule

# Open Port Management (Global port whitelist)
sudo netxfw port add 80                  # Open port 80
sudo netxfw port add 443                 # Open port 443
sudo netxfw port add 8080-8090           # Open port range
sudo netxfw port del 8080                # Remove port (supports delete/remove aliases)

# Rate Limiting
sudo netxfw limit add 0.0.0.0/0 1000 2000                 # Add rate limit rule
sudo netxfw limit list                                     # List rate limit rules
```

### Shell Auto-Completion

```bash
# Bash
netxfw completion bash > /etc/bash_completion.d/netxfw
source ~/.bashrc

# Zsh
netxfw completion zsh > "${fpath[1]}/_netxfw"

# Fish
netxfw completion fish > ~/.config/fish/completions/netxfw.fish
```

---

## ✨ Key Features

### Performance
- 🚀 **Extreme Performance**: Discard malicious packets directly at the XDP layer, bypassing the kernel network stack for minimal CPU usage.
- 🌍 **Full Protocol Support**: Native support for IPv4 and IPv6, including CIDR-based blocking.
- ⚡ **Dynamic Block List**: High-speed single IP matching using `LRU_HASH`, designed for rapidly changing malicious IPs.
- 💾 **Memory Optimization**: Uses sync.Pool object pooling to reduce GC pressure in high-frequency operations, improving performance by 30-50%.

### Security
- 🛡️ **Fine-grained Rules**: Supports IP+Port level Allow/Deny rules for complex business requirements.
- 🤖 **Auto-Blocking**: When an IP triggers rate limit thresholds, the system automatically adds it to the dynamic block list for millisecond-level kernel-space blocking. Supports configurable expiry and automatic eviction using LRU.
- 🛡️ **Security Hardening**:
  - **Bogon Filtering**: Automatically identifies and drops traffic from reserved or private IP ranges.
  - **Strict TCP Validation**: Validates TCP flag combinations to defend against Null/Xmas scans.
  - **Fragmentation Protection**: Configurable dropping of IP fragments to prevent fragmentation attacks.
  - **SYN Flood Defense**: Apply rate limits specifically to SYN packets to protect legitimate traffic.

### High Availability
- ⚡ **Zero-Downtime Hot Reload**: Adjust Map capacities and reload programs at runtime with state migration to ensure zero service interruption.
  - **Incremental Update**: When Map capacity is unchanged, directly update existing Maps to avoid full migration for millisecond-level reloads.
  - **Full Migration**: When capacity changes, automatically migrate old Map data to new Maps, ensuring connection tracking and rules are preserved.

### Traffic Control
- 🌊 **Traffic Shaping**: Built-in Token Bucket-based IP-level and ICMP rate limiting. Features **O(1) Configuration Caching** to avoid complex lookups for every packet.
- 🧠 **Stateful Inspection (Conntrack)**: Built-in efficient connection tracking engine that automatically allows return traffic for established connections.

### Extensibility
- 🧩 **Plugin Architecture (SDK)**:
  - **Plugin SDK**: Standardized Go interface (`sdk.Plugin`) for easy firewall extension.
  - **CEL Rule Engine**: Integrated Google CEL for complex JSON/KV parsing and regex matching (`JSON()`, `KV()`, `Match()`).
  - **Dynamic Loading**: Support for dynamic loading of third-party plugins via eBPF Tail Calls. See [Plugin Development Guide](docs/06-plugin-development/06-01_plugins_en.md).
  - **Inter-Plugin Communication (IPC)**:
    - **EventBus**: Pub/Sub event bus for decoupled communication (e.g. Log Engine -> AI Analysis).
    - **KV Store**: Shared in-memory key-value store (`sdk.Store`) for sharing runtime context (e.g. Threat Intel, Trust Scores).

### Management & Monitoring
- 📊 **Observability**: Built-in Web UI and Prometheus exporter for real-time monitoring of drop rates and active connections.
- 🏗️ **Modular Design**: Structured BPF code (Filter, Ratelimit, Conntrack, Protocols) for clarity and maintainability.
- 🛠️ **CLI-Driven Control**: Minimalist CLI for dynamic rule and plugin management without service restarts.
- 🔄 **Manual Update**: Supports one-click binary upgrades via `netxfw system update`.
- 💾 **Rule Import/Export**: Supports multiple formats (JSON, TOML, CSV, Binary) for rule backup and migration.

---

## ⚙️ Configuration

### Auto-Blocking Configuration

Enable Auto-Blocking in your configuration file (default: `/etc/netxfw/config.toml`):

```yaml
rate_limit:
  enabled: true
  auto_block: true          # Enable automatic blocking
  auto_block_expiry: "5m"   # Duration of the block (s, m, h)
  rules:
    - ip: "0.0.0.0/0"
      rate: 1000            # Packets per second limit
      burst: 2000           # Maximum burst allowed
```

### BPF Map Capacity Configuration

Adjust Map capacity based on your memory environment:

```yaml
capacity:
  whitelist: 10000          # Whitelist capacity
  blacklist: 50000          # Static blacklist capacity
  dynamic_blacklist: 20000  # Dynamic blacklist capacity
  conntrack: 100000         # Connection tracking table capacity
```

### Log Engine Configuration

The Log Engine analyzes log files in real-time and automatically executes defense actions:

```yaml
log_engine:
  enabled: true             # Enable log engine
  workers: 4                # Concurrent processing workers
  files:                    # Log files to monitor
    - "/var/log/nginx/access.log"
    - "/var/log/auth.log"
    - "/var/log/syslog"
  rules:
    # SSH brute-force defense: block after 5 failures in 60s
    - id: "ssh_bruteforce"
      path: "/var/log/auth.log"
      action: "dynblack"    # Dynamic block (default 5 minutes)
      is: ["Failed password"]
      threshold: 5
      interval: 60

    # Block malicious scrapers
    - id: "block_scrapers"
      path: "/var/log/nginx/access.log"
      action: "dynblack:1h" # Block for 1 hour
      or:
        - "Go-http-client"
        - "python-requests"
        - "curl/"

    # Nginx 404/500 high-frequency scanning
    - id: "nginx_scan"
      path: "/var/log/nginx/access.log"
      action: "dynblack"
      expression: |
        (Fields()[8] == "404" || Fields()[8] == "500") &&
        Contains(Fields()[6], "admin") &&
        Count(30) > 10
```

**Log Engine Actions**:

| Action Value | String Form | Description |
|--------------|-------------|-------------|
| `0` | `log` | Log alert only, no blocking |
| `1` | `dynblack` | Dynamic block (default expiry) |
| `1` | `dynblack:1h` | Dynamic block with specified duration (e.g. 10m, 1h, 30s) |
| `2` | `lock` / `deny` | Permanent block (requires manual removal) |

> **Note**: Actions support both numeric form (`0/1/2`) and string form; both are equivalent.

For more configuration options, see [Log Engine Documentation](docs/05-advanced-features/05-03_log_engine_en.md).

---

## 🏗️ Architecture

`netxfw` separates the control plane and data plane:

### Data Plane (eBPF/XDP/TC)
- **XDP**: High-speed packet filtering (unified IPv4/IPv6 LPM matching, conntrack checks) at the driver layer.
- **TC (Egress)**: Updates connection tracking state for outbound traffic.
- **Optimization**: Uses `Per-CPU Maps` for statistics to reduce multi-core contention.

### Control Plane (Go)
- **Manager**: Handles BPF program loading, pinning, and lifecycle management.
- **State Migrator**: Seamlessly migrates BPF Map data during hot reloads.
- **Web / CLI / API**: User interaction interfaces.
- **Metrics**: Exposes Prometheus metrics.

For a clearer view of the current layout, target layering, and migration state, see the [appendix architecture document](docs/10-appendix/10-01_architecture_en.md).

---

## 🔧 Maintenance & Updates

### Manual Update (Default)
For system stability, `netxfw` does not update automatically by default. You can check for and install the latest version at any time using:
```bash
sudo netxfw system update
```

### Enable Auto-Update (Optional)
If you prefer automatic daily updates for experimental purposes, you can explicitly enable it via the installation script:
```bash
curl -sSL https://raw.githubusercontent.com/netxfw/netxfw/main/scripts/deploy.sh | sudo bash -s -- --enable-auto-update
```

### Uninstallation

```bash
# Unload the firewall and remove BPF programs
sudo netxfw system unload
```

---

## 📚 Documentation

### Core Documentation
- [Documentation Index](docs/index.md)
- [Documentation Structure](docs/document-structure_en.md)
- [Architecture Appendix](docs/10-appendix/10-01_architecture_en.md)
- [CLI Manual](docs/03-quick-start/03-01_cli_en.md)
- [Rule Import/Export](docs/03-quick-start/03-02_rule_import_export_en.md)
- [Plugin Development Guide](docs/06-plugin-development/06-01_plugins_en.md)

### Configuration & Optimization
- [Configuration Reference](docs/04-configuration/04-03_configuration_reference_en.md)
- [BPF Map Capacity Configuration](docs/04-configuration/04-02_bpf_map_capacity_en.md)
- [Performance Tuning Guide](docs/04-configuration/04-01_performance_tuning_en.md)
- [Security Best Practices](docs/02-installation/02-01_security_best_practices_en.md)
- [Troubleshooting Guide](docs/08-troubleshooting/08-01_troubleshooting_en.md)

### Advanced Features
- [Real IP / Cloud Support](docs/05-advanced-features/05-01_realip_en.md)
- [Interface-Specific Agent Mode](docs/05-advanced-features/05-02_interface_specific_agent_en.md)
- [Log Engine](docs/05-advanced-features/05-03_log_engine_en.md)
- [Dynamic Modules](docs/05-advanced-features/05-04_dynamic_modules_en.md)
- [Health Check](docs/05-advanced-features/05-05_health_check_en.md)
- [Performance Monitoring](docs/05-advanced-features/05-06_performance_monitoring_en.md)

### Development & Testing
- [Contributing Guide](CONTRIBUTING_en.md)
- [Testing Appendix](docs/10-appendix/10-05_testing_en.md)
- [Evaluation Appendix](docs/10-appendix/10-06_evaluation_en.md)
- [Changelog](CHANGELOG_en.md)

### API & Appendices
- [API Reference](docs/09-api-reference/09-03_api_reference_en.md)
- [OpenAPI Specification](docs/09-api-reference/openapi.yaml)
- [Performance Benchmarks](docs/07-performance-tuning/07-01_benchmarks_en.md)
- [Architecture Diagrams](docs/10-appendix/10-02_architecture_diagrams_en.md)
- [Packet Filter Flow](docs/10-appendix/10-03_packet_filter_flow_en.md)
- [Full Documentation Map](docs/01-getting-started/01-01_document_index_en.md)

---

## 📄 License

This project uses a dual-license structure:

- **Go User-Space Code**: [Apache-2.0](LICENSE)
- **BPF Kernel Code**: [Dual BSD/GPL](bpf/LICENSE) (`BSD-2-Clause OR GPL-2.0-only`)

See [NOTICE](NOTICE) for details on the license structure.
