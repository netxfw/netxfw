# netxfw — The eXtensible eBPF Firewall

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/livp123/netxfw)](https://goreportcard.com/report/github.com/livp123/netxfw)
[![Release](https://img.shields.io/github/v/release/livp123/netxfw)](https://github.com/livp123/netxfw/releases)
[![Chinese README](https://img.shields.io/badge/README-中文-red.svg)](README.md)

> **Lightweight · High-Performance · Extensible**
> A next-generation Linux host firewall based on eBPF/XDP.

`netxfw` is a high-performance firewall built using modern Linux kernel eBPF technology. It processes packets directly at the network driver layer (XDP), allowing it to block large-scale DDoS attacks, brute-force attempts, and illegal scans with minimal CPU overhead.

---

## ✨ Key Features

- 🚀 **Extreme Performance**: Discard malicious packets directly at the XDP layer, bypassing the kernel network stack for minimal CPU usage.
- 🌍 **Full Protocol Support**: Native support for IPv4 and IPv6, including CIDR-based blocking.
- 🧠 **Stateful Inspection (Conntrack)**: Built-in efficient connection tracking engine that automatically allows return traffic for established connections.
- 🛡️ **Fine-grained Rules**: Supports IP+Port level Allow/Deny rules for complex business requirements.
- ⚡ **Dynamic Block List**: High-speed single IP matching using `LRU_HASH`, designed for rapidly changing malicious IPs.
- 🤖 **Auto-Blocking**: **A powerful tool against DDoS**. When an IP triggers rate limit thresholds, the system automatically adds it to the dynamic block list for millisecond-level kernel-space blocking. Supports configurable expiry and automatic eviction using LRU.
- ⚡ **Zero-Downtime Hot Reload**: Adjust Map capacities and reload programs at runtime with state migration to ensure zero service interruption.
- 🌊 **Traffic Shaping**: Built-in Token Bucket-based IP-level and ICMP rate limiting. Features **O(1) Configuration Caching** to avoid complex lookups for every packet.
- 🛡️ **Security Hardening**:
    - **Bogon Filtering**: Automatically identifies and drops traffic from reserved or private IP ranges.
    - **Strict TCP Validation**: Validates TCP flag combinations to defend against Null/Xmas scans.
    - **Fragmentation Protection**: Configurable dropping of IP fragments to prevent fragmentation attacks.
    - **SYN Flood Defense**: Apply rate limits specifically to SYN packets to protect legitimate traffic.
- 📊 **Observability**: Built-in Web UI (default port 11811) and Prometheus Exporter for real-time monitoring of drop rates and active connections.
- 🧩 **Plugin Architecture**: Support for dynamic loading of third-party plugins via eBPF Tail Calls. See [Plugin Development Guide](docs/plugins/plugins.md) for details.
- 🏗️ **Modular Design**: Structured BPF code (Filter, Ratelimit, Conntrack, Protocols) for clarity and maintainability.
- 🛠️ **CLI-Driven Control**: Minimalist CLI for dynamic rule and plugin management without service restarts.

---

## ⚙️ Configuration

Enable Auto-Blocking in your configuration file (default: `/etc/netxfw/config.yaml`):

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

---

## 🏗️ Architecture

`netxfw` separates the control plane and data plane:
1. **Data Plane (eBPF/XDP/TC)**:
    - **XDP**: High-speed packet filtering (Unified IPv4/IPv6 LPM matching, Conntrack checks) at the driver layer.
    - **TC (Egress)**: Updates connection tracking state for outbound traffic.
    - **Optimization**: Uses `Per-CPU Maps` for statistics to eliminate multi-core contention.
2. **Control Plane (Go)**:
    - **Manager**: Handles BPF program loading, pinning, and lifecycle management.
    - **State Migrator**: Seamlessly migrates BPF Map data during hot reloads.
    - **Web UI**: Minimalist visualization for real-time stats and Top 20 active connections.
    - **CLI/API**: User interaction interfaces.
    - **Metrics**: Exposes Prometheus metrics.

---

## 🚀 Quick Start

### 1. Installation

#### Method A: Binary Download (Recommended)
Download the latest version from the [Releases](https://github.com/livp123/netxfw/releases) page:

- **x86_64 (amd64)**:
  ```bash
  wget https://github.com/livp123/netxfw/releases/download/v0.2.2/netxfw_Linux_x86_64.tar.gz
  ```
- **ARM64 (aarch64)**:
  ```bash
  wget https://github.com/livp123/netxfw/releases/download/v0.2.2/netxfw_Linux_arm64.tar.gz
  ```

**Install**:
```bash
tar -zxvf netxfw_Linux_*.tar.gz
sudo mv netxfw /usr/local/bin/
```

#### Method B: Build from Source

**Requirements**:
- Linux Kernel >= 5.4 (5.10+ recommended)
- Go >= 1.21

**Install Build Tools**:
```bash
# Debian/Ubuntu
sudo apt-get install -y clang llvm libelf-dev libbpf-dev make
```

**Build**:
```bash
git clone https://github.com/livp123/netxfw.git
cd netxfw
make generate
make
```

### 2. Running

```bash
# Load the firewall with default configuration
sudo ./netxfw system load
```

---

## 📚 Documentation

- [Architecture Design](docs/architecture.md)
- [CLI Manual](docs/cli/cli_en.md)
- [Plugin Development Guide](docs/plugins/plugins_en.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)

## 📄 License
This project is licensed under the [MIT License](LICENSE).
