---
layout: default
title: NetXFW - eBPF Firewall
---

# netxfw — Scalable eBPF Firewall

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![BPF License](https://img.shields.io/badge/BPF-Dual%20BSD/GPL-purple.svg)](bpf/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/netxfw/netxfw)](https://goreportcard.com/report/github.com/netxfw/netxfw)
[![Release](https://img.shields.io/github/v/release/netxfw/netxfw)](https://github.com/netxfw/netxfw/releases)

> **Lightweight · High Performance · Easy to Extend**
> Next-generation Linux host firewall based on eBPF/XDP.

`netxfw` is a high-performance firewall built using modern Linux kernel eBPF technology. It processes packets directly at the network driver layer (XDP), enabling it to block large-scale DDoS attacks, brute force attacks, and illegal scans with extremely low CPU overhead.

---

## 📋 Documentation Navigation

### 🚀 Getting Started
- [README (Chinese)](../../README.md) - Project overview and quick start
- [README (English)](../../README_en.md) - Project overview and quick start

### 📚 Core Documents

| Document | Chinese | English |
|----------|---------|---------|
| Architecture Design | [Architecture Overview](../10-appendix/10-01_architecture.md) | [Architecture](../10-appendix/10-01_architecture_en.md) |
| CLI Reference | [CLI Commands](../03-quick-start/03-01_cli.md) | [CLI Commands](../03-quick-start/03-01_cli_en.md) |
| Plugin Development | [Plugin Development Guide](../06-plugin-development/06-01_plugins.md) | [Plugin Guide](../06-plugin-development/06-01_plugins_en.md) |
| Rule Import/Export | [Rule Import/Export](../03-quick-start/03-02_rule_import_export.md) | [Rule Import/Export](../03-quick-start/03-02_rule_import_export_en.md) |
| Performance Benchmarks | [Performance Benchmarks](../07-performance-tuning/07-01_benchmarks.md) | [Benchmarks](../07-performance-tuning/07-01_benchmarks_en.md) |
| BPF Map Capacity | [Capacity Configuration](../04-configuration/04-02_bpf_map_capacity.md) | [Capacity Config](../04-configuration/04-02_bpf_map_capacity_en.md) |
| Log Engine | [Log Engine](../05-advanced-features/05-03_log_engine.md) | [Log Engine](../05-advanced-features/05-03_log_engine_en.md) |
| Troubleshooting | [Troubleshooting Guide](../08-troubleshooting/08-01_troubleshooting.md) | [Troubleshooting](../08-troubleshooting/08-01_troubleshooting_en.md) |
| Performance Tuning | [Performance Tuning Guide](../04-configuration/04-01_performance_tuning.md) | [Performance Tuning](../04-configuration/04-01_performance_tuning_en.md) |
| Security Best Practices | [Security Best Practices](../02-installation/02-01_security_best_practices.md) | [Security Best Practices](../02-installation/02-01_security_best_practices_en.md) |

---

## ✨ Core Features

- 🚀 **Ultimate Performance**: Directly drop malicious packets at the network card driver layer (XDP)
- 🌍 **Full Protocol Support**: Native support for IPv4 and IPv6
- ⚡ **Dynamic Blacklist**: High-speed matching based on LRU_HASH
- 🛡️ **Automatic Blocking**: Automatic blocking when rate limit threshold is triggered
- ⚡ **Lossless Hot Reload**: Adjust configuration at runtime with zero business interruption

---

## 🚀 Quick Start

```bash
# Download and install
wget https://github.com/netxfw/netxfw/releases/latest/download/netxfw_Linux_x86_64.tar.gz
tar -zxvf netxfw_Linux_*.tar.gz
sudo mv netxfw /usr/local/bin/

# Load firewall
sudo netxfw system load

# Basic commands
sudo netxfw allow 192.168.1.100    # Whitelist
sudo netxfw deny 10.0.0.1          # Blacklist
sudo netxfw port add 80            # Open port
sudo netxfw status                 # Check status
```

---

## 🔗 Related Links

- [GitHub Repository](https://github.com/netxfw/netxfw)
- [Releases Download](https://github.com/netxfw/netxfw/releases)
- [Issue Feedback](https://github.com/netxfw/netxfw/issues)