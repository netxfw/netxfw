# CLI Manual

`netxfw` provides a simple command-line interface for managing the firewall and IP rule lists.

## Global Flags

The following flags are available on most subcommands:

| Flag | Short | Description |
|---|---|---|
| `--config <path>` | `-c` | Path to config file (default: `/etc/netxfw/config.yaml`) |
| `--interface <name>` | `-i` | Network interface to target |
| `--mode <dp\|agent>` | - | Operation mode: `dp` (Data Plane) / `agent` (Control Plane) |

---

## Command Overview

### Quick Commands

| Command | Arguments | Description |
|---|---|---|
| `enable` | None | Enable and start the firewall |
| `disable` | None | Disable and stop the firewall |
| `status` | None | Show system status |
| `reload` | None | Reload configuration and sync to BPF maps |
| `reset` | None | Reset firewall (clear all rules, preserve SSH) |
| `init` | None | Initialize configuration file |
| `test` | None | Test configuration validity |
| `version` | None | Show version information |
| `list` | None | List all blocked IPs |
| `clear` | None | Clear the entire blacklist |
| `del <ip>` | IP/CIDR | Delete IP from whitelist or blacklist |

### allow — Whitelist Management

| Command | Arguments | Description |
|---|---|---|
| `allow <ip>` | IP/CIDR | Quickly whitelist an IP (backward compatible) |
| `allow add <ip>` | IP/CIDR | Add IP to whitelist |
| `allow list` | None | List whitelist IPs |
| `allow port list` | None | List IP+Port allow rules |

### deny — Blacklist Management

| Command | Arguments | Description |
|---|---|---|
| `deny <ip> [--ttl]` | IP/CIDR [--ttl] | Add IP to blacklist (backward compatible) |
| `deny add <ip> [--ttl]` | IP/CIDR [--ttl] | Add IP to blacklist |
| `deny list` | None | List blacklist (static + dynamic) |
| `deny list --static` | None | List static blacklist only |
| `deny list --dynamic` | None | List dynamic blacklist only |
| `deny port list` | None | List IP+Port deny rules |

### dynamic — Dynamic Blacklist Management

| Command | Arguments | Description |
|---|---|---|
| `dynamic add <ip> --ttl <duration>` | IP, TTL | Add to dynamic blacklist (with expiry) |
| `dynamic del <ip>` | IP/CIDR | Remove from dynamic blacklist |
| `dynamic list` | None | List all dynamic blacklist entries |
| `dyn ...` | - | Alias for `dynamic` |

### system — System Management

| Command | Flags | Description |
|---|---|---|
| `system on [iface...]` | positional args | Load XDP program (alias for `load`) |
| `system off [iface...]` | positional args | Unload XDP program (alias for `unload`) |
| `system load` | `-i <iface>` | Load XDP driver onto interface |
| `system unload` | `-i <iface>` | Unload XDP driver |
| `system reload` | `-i <iface>` | Hot-reload XDP program (lossless) |
| `system daemon` | `-c -i` | Start background daemon process |
| `system status` | `-c -i` | Show runtime status and statistics |
| `system init` | `-c` | Initialize default configuration file |
| `system test` | `-c` | Test configuration validity |
| `system update` | None | Check and install updates from GitHub |
| `system sync to-config` | `-c -i` | Dump BPF maps → config file (persist) |
| `system sync to-map` | `-c -i` | Load config file → BPF maps |

### rule — Rule Management

| Command | Arguments | Description |
|---|---|---|
| `rule add <ip> [port] <allow\|deny>` | IP, port, action | Add IP or IP+Port rule |
| `rule del <ip>` | IP/CIDR | Remove a rule (`delete`/`remove` alias) |
| `rule list` | optional filters | List all rules |
| `rule import <type> <file>` | type, file | Bulk import rules (TXT/JSON/YAML) |
| `rule export <file> [--format]` | file, format | Export rules (JSON/YAML/CSV) |
| `rule clear` | None | Clear the blacklist |

### limit — Rate Limiting

| Command | Arguments | Description |
|---|---|---|
| `limit add <ip> <rate> <burst>` | IP, pps, burst | Set PPS rate limit for an IP |
| `limit remove <ip>` | IP | Remove a rate limit rule |
| `limit list` | None | List all rate limit rules |

### security — Security Policies

| Command | Arguments | Description |
|---|---|---|
| `security fragments <true\|false>` | bool | Enable/disable dropping fragmented packets |
| `security strict-tcp <true\|false>` | bool | Enable/disable strict TCP flag validation |
| `security syn-limit <true\|false>` | bool | Enable/disable SYN flood protection |
| `security bogon <true\|false>` | bool | Enable/disable bogon IP filtering |
| `security auto-block <true\|false>` | bool | Enable/disable auto-blocking |
| `security auto-block-expiry <seconds>` | int | Set auto-block expiry duration |

### port — Port Management

| Command | Arguments | Description |
|---|---|---|
| `port add <port>` | port number | Add port to global allow list |
| `port remove <port>` | port number | Remove port from allow list |

### perf — Performance Monitoring

| Command | Flags | Description |
|---|---|---|
| `perf show` | `-c -i` | Show all performance statistics |
| `perf latency` | `-c -i` | Show BPF map operation latency |
| `perf cache` | `-c -i` | Show cache hit rate statistics |
| `perf traffic` | `-c -i` | Show real-time traffic (PPS/BPS/drops) |
| `perf reset` | `-c -i` | Reset all performance counters |

### Other

| Command | Arguments | Description |
|---|---|---|
| `conntrack` | None | Show active kernel connection tracking table |
| `version` | `[--short]` | Show version and SDK status |
| `web` | None | Show Web UI information |

---

## Detailed Reference

### 1. XDP Program Management

`netxfw` provides several ways to load and unload the XDP program:

| Action | Command |
|---|---|
| Load XDP | `netxfw system on eth0` or `netxfw system load -i eth0` |
| Unload XDP | `netxfw system off eth0` or `netxfw system unload -i eth0` |
| Unload all | `netxfw system off` |
| Hot-reload | `netxfw system reload -i eth0` |

```bash
# Load onto a specific interface
sudo netxfw system on eth0

# Load onto multiple interfaces
sudo netxfw system on eth0 eth1 eth2

# Use default interfaces from config
sudo netxfw system on

# Unload all interfaces
sudo netxfw system off

# Hot-reload: applies new config without dropping connections
sudo netxfw system reload -i eth0
```

### 2. System Status (system status)

Displays runtime status, statistics, and resource utilization.

```bash
# Show system status (all interfaces)
sudo netxfw system status

# Use a custom config file
sudo netxfw system status -c /etc/netxfw/config.yaml

# Show stats for a specific interface
sudo netxfw system status -i eth0
```

**Output includes**: traffic rates, pass/drop counters, conntrack health, BPF map usage, protocol distribution, policy configuration, attached interfaces.

### 3. Whitelist Management (allow)

Manage whitelist IP list with subcommands and backward compatibility.

```bash
# Backward compatible: quick whitelist
sudo netxfw allow 1.2.3.4

# Subcommand: add to whitelist
sudo netxfw allow add 1.2.3.4

# Subcommand: add with port
sudo netxfw allow add 1.2.3.4:443

# Subcommand: list whitelist
sudo netxfw allow list

# Subcommand: list IP+Port allow rules
sudo netxfw allow port list

# Remove from whitelist
sudo netxfw unallow 1.2.3.4
```

### 4. Blacklist Management (deny)

Manage blacklist IP list with support for static and dynamic blacklists (with TTL).

```bash
# Backward compatible: add to static blacklist
sudo netxfw deny 1.2.3.4

# Backward compatible: add to dynamic blacklist (with TTL)
sudo netxfw deny 1.2.3.4 --ttl 1h

# Subcommand: add to static blacklist
sudo netxfw deny add 1.2.3.4

# Subcommand: add to dynamic blacklist (with TTL)
sudo netxfw deny add 1.2.3.4 --ttl 1h

# Subcommand: list all blacklist (static + dynamic)
sudo netxfw deny list

# Subcommand: list static blacklist only
sudo netxfw deny list --static

# Subcommand: list dynamic blacklist only
sudo netxfw deny list --dynamic

# Subcommand: list IP+Port deny rules
sudo netxfw deny port list
```

**TTL Format Support**: `1h` (1 hour), `30m` (30 minutes), `1d` (1 day), `24h` (24 hours)

### 5. Dynamic Blacklist Management (dynamic)

Dedicated management for dynamic blacklist (LRU Hash with auto-expiry).

```bash
# Add to dynamic blacklist (TTL required)
sudo netxfw dynamic add 192.168.1.100 --ttl 1h

# Using dyn alias
sudo netxfw dyn add 10.0.0.1 --ttl 24h

# Remove from dynamic blacklist
sudo netxfw dynamic del 192.168.1.100

# Using delete alias
sudo netxfw dynamic delete 192.168.1.100

# List all dynamic blacklist entries
sudo netxfw dynamic list
```

**Output Example**:
```
📋 Dynamic blacklist entries (2 total):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🚫 172.16.1.1/32 (expires: 2026-02-28 16:07:51)
  🚫 10.10.10.10/32 (expires: 2026-02-28 14:56:48)
```

### 6. Quick Commands (block/unlock/clear)

Fast-path commands for emergency situations — no subcommand required:

```bash
# Block an IP immediately
sudo netxfw block 1.2.3.4

# Block an entire subnet
sudo netxfw block 192.168.100.0/24

# Unblock an IP
sudo netxfw unlock 1.2.3.4

# Clear the entire blacklist
sudo netxfw clear
```

### 7. Rule Management (rule)

Fine-grained access control for IPs, CIDRs, and IP+Port combinations.

```bash
# Whitelist an IP (allow all traffic)
sudo netxfw rule add 1.2.3.4 allow

# Blacklist an IP (block all traffic)
sudo netxfw rule add 5.6.7.8 deny

# Block a specific IP:port
sudo netxfw rule add 5.6.7.8 80 deny

# List all rules
sudo netxfw rule list

# Remove a rule (supports del/delete/remove aliases)
sudo netxfw rule del 1.2.3.4
sudo netxfw rule delete 1.2.3.4
sudo netxfw rule remove 1.2.3.4
```

### 8. Bulk Import (rule import)

Import rules from text or structured files.

```bash
# Import blacklist (one IP/CIDR per line)
sudo netxfw rule import deny blacklist.txt

# Import whitelist
sudo netxfw rule import allow whitelist.txt

# Import all rules from JSON/YAML
sudo netxfw rule import all rules.json
sudo netxfw rule import all rules.yaml

# Import blacklist from bin.zst file (binary compressed format)
sudo netxfw rule import binary rules.deny.bin.zst
```

**Text format**: one IP or CIDR per line, `#` comments supported.

**JSON format**:
```json
{
  "blacklist": [{"type": "blacklist", "ip": "10.0.0.1"}],
  "whitelist": [{"type": "whitelist", "ip": "127.0.0.1/32"}],
  "ipport_rules": [{"type": "ipport", "ip": "192.168.1.1", "port": 80, "action": "allow"}]
}
```

**Binary format (.bin.zst)**:
- High-performance binary format with zstd compression
- Supports blacklist rules only
- Ideal for large-scale rule storage and fast migration
- File extension must be `.bin.zst`

### 6. Rule Export (rule export)

```bash
# Export as JSON (default)
sudo netxfw rule export rules.json

# Export as YAML
sudo netxfw rule export rules.yaml --format yaml

# Export as CSV
sudo netxfw rule export rules.csv --format csv

# Export as Binary format (blacklist only, zstd compressed)
sudo netxfw rule export rules.deny.bin.zst --format binary

# Auto-detect format (based on file extension)
sudo netxfw rule export rules.json
sudo netxfw rule export rules.yaml
sudo netxfw rule export rules.csv
sudo netxfw rule export rules.deny.bin.zst
```

**Format Comparison**:

| Format | Pros | Cons | Use Cases |
|--------|------|------|-----------|
| **Text** | Simple, human-readable, easy to edit | Limited functionality, single rule type only | Quick addition of few IPs |
| **JSON/YAML** | Structured, includes all rule types, readable | Larger file size, slower parsing | Config backup, version control |
| **CSV** | Tabular format, easy to edit in Excel | Large file size, no complex structure support | Data exchange, reporting |
| **Binary** | High performance, high compression ratio, fast parsing | Not human-readable, blacklist only | Large-scale rule storage, fast migration |

### 7. Rate Limiting (limit)

XDP-layer PPS rate limiting per IP or subnet. Supports IPv4, IPv6, and CIDR.

```bash
# Limit to 1000 pps, burst up to 2000
sudo netxfw limit add 1.2.3.4 1000 2000

# Limit an IPv6 address
sudo netxfw limit add 2001:db8::1 500 1000

# Limit a subnet
sudo netxfw limit add 192.168.1.0/24 5000 10000

# List active rate limits
sudo netxfw limit list

# Remove a rate limit
sudo netxfw limit remove 1.2.3.4
```

### 8. Security Policies (security)

Dynamically adjust firewall security behavior. Changes take effect immediately without a reload.

```bash
# Disable dropping of fragmented packets
sudo netxfw security fragments false

# Enable strict TCP flag validation
sudo netxfw security strict-tcp true

# Enable SYN flood protection
sudo netxfw security syn-limit true

# Enable bogon IP filtering
sudo netxfw security bogon true

# Enable auto-block for rate-limit violators
sudo netxfw security auto-block true

# Set auto-block expiry to 10 minutes
sudo netxfw security auto-block-expiry 600
```

### 9. Port Management (port)

Manage the global list of allowed source/destination ports.

```bash
# Allow a port globally
sudo netxfw port add 8080

# Remove a port from the allow list
sudo netxfw port remove 8080
```

### 10. Configuration Sync (system sync)

Bidirectional synchronization between BPF maps (runtime) and `config.yaml` (disk).

```bash
# Persist runtime state to config file (Memory → Disk)
sudo netxfw system sync to-config

# Reload config file into runtime BPF maps (Disk → Memory)
sudo netxfw system sync to-map
```

### 11. Performance Monitoring (perf)

```bash
sudo netxfw perf show       # All performance statistics
sudo netxfw perf latency    # BPF map operation latency
sudo netxfw perf cache      # Cache hit rates
sudo netxfw perf traffic    # Real-time PPS/BPS/drop rates
sudo netxfw perf reset      # Reset all counters
```

### 12. Daemon Mode (system daemon)

```bash
# Start with interfaces from config
sudo netxfw system daemon

# Start on a specific interface
sudo netxfw system daemon -i eth0

# Start with a custom config and interface
sudo netxfw system daemon -c /etc/netxfw/config.yaml -i eth0
```

> **PID File Behavior**:
> - With specific interfaces: `/var/run/netxfw_<interface>.pid` (supports multiple parallel instances)
> - Without specifying an interface: `/var/run/netxfw.pid`

### 13. Version (version)

```bash
netxfw version           # Detailed version and runtime SDK status
netxfw version --short   # Version string only (for scripting)
```

### 14. Config Init, Test & Update

```bash
# Initialize a fresh default config
sudo netxfw system init

# Validate the current config file
sudo netxfw system test

# Check for and install the latest update
sudo netxfw system update
```
