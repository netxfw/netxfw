# CLI Manual

`netxfw` provides a simple command-line interface for managing firewall services and manipulating IP lock lists.

## Command Overview

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `daemon` | None | Starts the daemon process, responsible for metrics collection, rule cleanup, and API service |
| `load xdp` | None | Loads BPF programs and attaches them to all physical network interfaces |
| `unload xdp` | None | Unloads BPF programs and cleans up pinned Maps |
| `reload xdp` | None | Hot-reloads configuration and updates BPF programs losslessly |
| `plugin load` | `<path> <index>` | Dynamically loads a BPF plugin to the specified index (2-15) |
| `plugin remove`| `<index>` | Removes the BPF plugin at the specified index |
| `conntrack` | None | Views the current active connection tracking table in the kernel |
| `rule add` | `<IP> [port] <allow/deny>` | Adds an IP or IP+Port rule |
| `rule list` | `rules / conntrack` | Lists rules or connections |
| `limit add` | `<IP> <rate> <burst>` | Sets PPS rate limit for a specific IP |
| `limit remove`| `<IP>` | Removes a rate limit rule |
| `limit list` | None | Lists all rate limit rules |
| `lock` | `<IP>` | Shortcut: Globally bans a specific IP |
| `allow` | `<IP> [port]` | Shortcut: Adds an IP to the whitelist |
| `system sync` | `to-config / to-map` | Syncs memory rules to config file, or loads rules from config to memory |
| `rule import` | `deny <file>` | Batch imports IP blacklist from a file |
| `web` | `start / stop` | Manages the Web Console service |

---

## Detailed Description

### 1. Daemon (daemon)
The core running mode of `netxfw`. In `daemon` mode, the program will:
- Monitor kernel BPF Map status.
- Automatically clean up expired dynamic rules.
- Expose Prometheus metrics (default :9100).
- Start the Web API for CLI and Web UI calls.

```bash
sudo netxfw daemon
```

### 2. Rule Management (rule)
Supports fine-grained access control.
- **Add Rule**:
  ```bash
  # Allow all traffic from 1.2.3.4
  sudo netxfw rule add 1.2.3.4 allow
  # Block traffic from 5.6.7.8 to port 80
  sudo netxfw rule add 5.6.7.8 80 deny
  ```
- **List Rules**:
  ```bash
  sudo netxfw rule list rules
  ```

### 3. Connection Tracking (conntrack)
View stateful connections in the kernel in real-time. This is very useful for troubleshooting network connectivity issues.

```bash
sudo netxfw conntrack
```
**Output Example:**
```text
Source          Port  Destination     Port  Protocol
--------------------------------------------------------------------------------
192.168.1.100   54321 1.1.1.1         443   TCP
```

### 4. Quick Lock & Unlock (lock/unlock)
Shortcut commands for emergency situations.

```bash
# Block immediately
sudo netxfw lock 1.2.3.4
# Unlock immediately
sudo netxfw unlock 1.2.3.4
```

### 5. Traffic Control (limit)
Apply PPS (Packets Per Second) rate limiting to specific IPs or subnets at the XDP layer. Supports IPv4 and IPv6.

- **Enable Global Rate Limiting**:
  ```bash
  sudo netxfw system ratelimit true
  ```
- **Add Rate Limit Rule**:
  ```bash
  # Limit 1.2.3.4 to 100 pps, with a burst of 200 packets
  sudo netxfw limit add 1.2.3.4 100 200

  # Limit IPv6 address ::1 to 500 pps
  sudo netxfw limit add ::1 500 1000

  # Limit subnet 192.168.1.0/24
  sudo netxfw limit add 192.168.1.0/24 1000 2000
  ```
- **View Rate Limit Status**:
  ```bash
  sudo netxfw limit list
  ```
- **Remove Rate Limit Rule**:
  ```bash
  sudo netxfw limit remove 1.2.3.4
  ```

### 6. Hot Reload (reload)
Use this command to reload losslessly after modifying `/etc/netxfw/config.yaml` (e.g., adjusting Map capacity or default policies).

```bash
sudo netxfw reload xdp
```
This command automatically migrates data from old Maps to new Maps, ensuring existing connections are not interrupted.

### 7. Configuration Sync (sync)
Supports bidirectional synchronization between memory state (BPF Maps) and the configuration file (`config.yaml`), ensuring operational consistency.

- **Sync to Config** (Memory -> Disk):
  Writes dynamic rules (blacklist, rate limits, etc.) from current BPF Maps to `config.yaml` for persistence.
  ```bash
  sudo netxfw system sync to-config
  ```

- **Sync to Memory** (Disk -> Memory):
  Reloads rules from `config.yaml` into BPF Maps (similar to hot reload, but without restarting BPF programs).
  ```bash
  sudo netxfw system sync to-map
  ```

### 8. Batch Import (import)
Supports batch importing IP blacklist rules from a text file. Supports IPv4 and IPv6, and automatically identifies and handles CIDR subnets.

```bash
# Import blacklist from blacklist.txt
sudo netxfw rule import deny blacklist.txt
```
**File Format Example**:
```text
# One IP or subnet per line
1.2.3.4
192.168.0.0/24
2001:db8::1
```

### 9. Plugin Management (plugin)
Allows dynamic extension of packet processing logic without stopping the firewall.
- **Load Plugin**:
  ```bash
  # Load compiled plugin to index 2
  sudo netxfw plugin load ./my_plugin.o 2
  ```
- **Remove Plugin**:
  ```bash
  sudo netxfw plugin remove 2
  ```
See [Plugin Development Guide](../plugins/plugins.md) for details.
