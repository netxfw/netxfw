# Configuration Reference

This document provides detailed explanation of the NetXFW TOML configuration file structure and each configuration item.

## Configuration File Location

| Mode | Configuration File Path |
|------|-------------------------|
| Agent Mode | `/etc/netxfw/config-agent.toml` |
| DP Mode | `/etc/netxfw/config-dp.toml` |
| Default Path | `/etc/netxfw/config.toml` |

## Configuration File Structure

```
1. Core Configuration
   ├── Base Configuration
   ├── Network Interfaces
   ├── Protocol Security
   ├── ICMP Rate Limiting
   ├── Cleanup & Expiry
   ├── Debug
   └── File Paths

2. Security Rules
   ├── Whitelist
   ├── Port Configuration
   ├── IP-Port Rules
   ├── Rate Limit
   └── Connection Tracking

3. XDP Configuration
   ├── Capacity
   ├── Module Configuration
   └── BPF Plugin

4. Services
   ├── Web API Server
   └── Metrics

5. Logging
   ├── Log Engine
   └── Application Logging

6. Advanced
   ├── Cluster
   ├── Cloud Environment
   ├── AI Assistant
   └── MCP Server
```

---

## 1. Core Configuration

### 1.1 Base Configuration

```toml
[base]
default_deny = true          # Default deny policy
allow_return_traffic = true  # Allow return traffic
allow_icmp = true            # Allow ICMP
persist_rules = true         # Persist rules
backup_keep = 3              # Config backup count
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `default_deny` | bool | `true` | Drop all traffic not explicitly allowed |
| `allow_return_traffic` | bool | `true` | Allow return traffic for established connections (stateless) |
| `allow_icmp` | bool | `true` | Allow Ping and other ICMP messages |
| `persist_rules` | bool | `true` | Save rules on shutdown, reload on startup |
| `backup_keep` | int | `3` | Number of config backup files to keep (0 = no backup) |

### 1.2 Network Interfaces

```toml
interfaces = []              # Network interface list
enable_af_xdp = false        # Enable AF_XDP
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `interfaces` | []string | `[]` | Network interfaces to attach XDP program (empty = all) |
| `enable_af_xdp` | bool | `false` | Use AF_XDP socket for packet processing |

### 1.3 Protocol Security

```toml
strict_protocol = true       # Strict protocol check
drop_fragments = true        # Drop fragments
strict_tcp = false           # Strict TCP check
syn_limit = true             # SYN rate limit
bogon_filter = true          # Bogon filter
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `strict_protocol` | bool | `true` | Reject packets with invalid protocol headers |
| `drop_fragments` | bool | `true` | Drop IP fragments (prevents fragmentation attacks) |
| `strict_tcp` | bool | `false` | Enforce TCP header validation |
| `syn_limit` | bool | `true` | Limit SYN packets (prevents SYN flood) |
| `bogon_filter` | bool | `true` | Filter bogon/martian IP addresses |

### 1.4 ICMP Rate Limiting

```toml
icmp_rate = 10               # ICMP rate
icmp_burst = 50              # ICMP burst
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `icmp_rate` | uint64 | `10` | Maximum ICMP packets per second per destination |
| `icmp_burst` | uint64 | `50` | Maximum ICMP packets allowed in a burst |

### 1.5 Cleanup & Expiry

```toml
enable_expiry = true         # Enable expiry
cleanup_interval = "1m"      # Cleanup interval
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable_expiry` | bool | `true` | Automatically expire entries based on timestamp |
| `cleanup_interval` | string | `"1m"` | Interval for cleaning up expired entries |

### 1.6 Debug

```toml
enable_pprof = false         # Enable pprof
pprof_port = 6060            # pprof port
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable_pprof` | bool | `false` | Enable Go profiling HTTP server |
| `pprof_port` | int | `6060` | pprof HTTP server port |

### 1.7 File Paths

```toml
lock_list_file = "/etc/netxfw/deny_list.txt"
lock_list_binary = "/etc/netxfw/deny_list.bin.zst"
bpf_pin_path = ""
lock_list_merge_threshold = 0
lock_list_v4_mask = 24
lock_list_v6_mask = 64
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `lock_list_file` | string | `/etc/netxfw/deny_list.txt` | Deny list file path (text format) |
| `lock_list_binary` | string | `/etc/netxfw/deny_list.bin.zst` | Deny list file path (compressed binary) |
| `bpf_pin_path` | string | `""` | BPF map pin path (empty = default) |
| `lock_list_merge_threshold` | int | `0` | Minimum entries to trigger subnet merging |
| `lock_list_v4_mask` | int | `24` | Subnet mask for IPv4 lock list aggregation |
| `lock_list_v6_mask` | int | `64` | Subnet mask for IPv6 lock list aggregation |

---

## 2. Security Rules

### 2.1 Whitelist

```toml
whitelist = ["192.168.1.0/24", "10.0.0.1"]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `whitelist` | []string | `[]` | Allowed IP addresses or networks (CIDR format) |

### 2.2 Port Configuration

```toml
[port]
allowed_ports = [22, 80, 443]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allowed_ports` | []uint16 | `[]` | List of ports allowed for incoming connections |

### 2.3 IP-Port Rules

```toml
ip_port_rules = [
    { ip = "0.0.0.0", port = 22, action = 1 },
    { ip = "192.168.1.100", port = 3306, action = 0 },
]
```

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | IP address or CIDR |
| `port` | uint16 | Port number |
| `action` | uint8 | Action: `0` = Deny, `1` = Allow |

### 2.4 Rate Limit

```toml
[rate_limit]
enabled = false
auto_block = true
auto_block_expiry = "10m"
rules = [
    { ip = "0.0.0.0/0", rate = 1000, burst = 2000 },
]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable per-client rate limiting |
| `auto_block` | bool | `true` | Automatically block IPs exceeding rate limits |
| `auto_block_expiry` | string | `"10m"` | Duration for auto-blocked IPs |
| `rules` | []RateLimitRule | `[]` | Rate limit rules list |

**RateLimitRule Structure:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | IP address or CIDR |
| `rate` | uint64 | Requests per second allowed |
| `burst` | uint64 | Burst requests allowed |

### 2.5 Connection Tracking

```toml
[conntrack]
enabled = true
max_entries = 10000
tcp_timeout = "1h"
udp_timeout = "5m"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable TCP/UDP connection tracking |
| `max_entries` | int | `10000` | Maximum number of tracked connections |
| `tcp_timeout` | string | `"1h"` | Inactive TCP connection timeout |
| `udp_timeout` | string | `"5m"` | Inactive UDP flow timeout |

---

## 3. XDP Configuration

### 3.1 Capacity

```toml
[capacity]
lock_list = 20000
dyn_lock_list = 2000
whitelist = 30
ip_port_rules = 30
allowed_ports = 30
rate_limits = 1000
drop_reason_stats = 1000000
pass_reason_stats = 1000000
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `lock_list` | int | `20000` | Maximum entries in deny list |
| `dyn_lock_list` | int | `2000` | Maximum entries in dynamic deny list |
| `whitelist` | int | `30` | Maximum entries in whitelist |
| `ip_port_rules` | int | `30` | Maximum IP-port rules |
| `allowed_ports` | int | `30` | Maximum allowed ports |
| `rate_limits` | int | `1000` | Maximum rate limit entries |
| `drop_reason_stats` | int | `1000000` | Maximum drop reason statistics |
| `pass_reason_stats` | int | `1000000` | Maximum pass reason statistics |

### 3.2 Module Configuration

```toml
modules = [
    { name = "sanity", enabled = true, priority = 1 },
    { name = "critical_blacklist", enabled = true, priority = 2 },
    { name = "whitelist", enabled = true, priority = 3 },
    { name = "blacklist", enabled = true, priority = 4 },
    { name = "dynamic_blacklist", enabled = true, priority = 5 },
    { name = "ratelimit", enabled = true, priority = 6 },
    { name = "conntrack", enabled = true, priority = 7 },
    { name = "ip_port_rules", enabled = true, priority = 8 },
    { name = "icmp", enabled = true, priority = 9 },
    { name = "return_traffic", enabled = true, priority = 10 },
]
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Module name |
| `enabled` | bool | Whether enabled |
| `priority` | int | Execution priority (lower = higher priority) |

**Built-in Modules:**

| Module | Priority | Description |
|--------|----------|-------------|
| `sanity` | 1 | Packet integrity check |
| `critical_blacklist` | 2 | Critical blacklist check |
| `whitelist` | 3 | Whitelist check |
| `blacklist` | 4 | Blacklist check |
| `dynamic_blacklist` | 5 | Dynamic blacklist check |
| `ratelimit` | 6 | Rate limiting |
| `conntrack` | 7 | Connection tracking |
| `ip_port_rules` | 8 | IP-port rules |
| `icmp` | 9 | ICMP handling |
| `return_traffic` | 10 | Return traffic handling |

### 3.3 BPF Plugin

```toml
[bpf_plugin]
enabled = false
plugins = []
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable external BPF program loading |
| `plugins` | []PluginConfig | `[]` | BPF plugin configuration list |

---

## 4. Services

### 4.1 Web API Server

```toml
[web]
enabled = false
port = 11811
token = ""
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable HTTP API server |
| `port` | int | `11811` | HTTP API server port |
| `token` | string | `""` | Bearer token for API authentication |

### 4.2 Metrics

```toml
[metrics]
enabled = false
server_enabled = false
port = 11812
push_enabled = false
push_gateway_addr = ""
push_interval = "15s"
textfile_enabled = false
textfile_path = ""
top_n = 10
threshold_critical = 90
threshold_high = 75
threshold_medium = 50
stats_interval = "1s"
avg_packet_size = 500
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable metrics collection |
| `server_enabled` | bool | `false` | Start HTTP metrics endpoint |
| `port` | int | `11812` | Metrics server port |
| `push_enabled` | bool | `false` | Push metrics to Pushgateway |
| `push_gateway_addr` | string | `""` | Prometheus Pushgateway URL |
| `push_interval` | string | `"15s"` | Push metrics interval |
| `textfile_enabled` | bool | `false` | Read metrics from text files |
| `textfile_path` | string | `""` | Text file directory |
| `top_n` | int | `10` | Top IP statistics count |
| `threshold_critical` | int | `90` | Critical alert threshold |
| `threshold_high` | int | `75` | High alert threshold |
| `threshold_medium` | int | `50` | Medium alert threshold |
| `stats_interval` | string | `"1s"` | Statistics update interval |
| `avg_packet_size` | int | `500` | Average packet size estimate |

---

## 5. Logging

### 5.1 Log Engine

```toml
[log_engine]
enabled = false
workers = 4
rules = []
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable structured logging |
| `workers` | int | `4` | Number of log processing workers |
| `rules` | []LogEngineRule | `[]` | Log filtering and processing rules |

### 5.2 Application Logging

```toml
[logging]
enabled = false
path = "/var/log/netxfw/agent.log"
max_size = 10
max_backups = 3
max_age = 30
compress = true
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable file-based logging |
| `path` | string | `/var/log/netxfw/agent.log` | Log file path |
| `max_size` | int | `10` | Maximum log file size before rotation (MB) |
| `max_backups` | int | `3` | Number of backup files to keep |
| `max_age` | int | `30` | Maximum days to keep backup files |
| `compress` | bool | `true` | Compress rotated log files |

---

## 6. Advanced

### 6.1 Cluster

```toml
[cluster]
enabled = false
configpath = "cluster.toml"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable cluster mode |
| `configpath` | string | `"cluster.toml"` | Cluster configuration file path |

### 6.2 Cloud Environment

```toml
[cloud]
enabled = false
provider = "other"

[cloud.proxy_protocol]
enabled = false
trusted_lb_ranges = []
cache_ttl = "5m"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable cloud environment features |
| `provider` | string | `"other"` | Cloud provider (alibaba/aws/huawei/tencent/other) |

**Proxy Protocol Configuration:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Parse PROXY protocol header |
| `trusted_lb_ranges` | []string | `[]` | Trusted load balancer IP ranges |
| `cache_ttl` | string | `"5m"` | Real IP cache duration |

### 6.3 AI Assistant

```toml
[ai]
enabled = false
port = 11813
api_key = ""
model = ""
base_url = ""
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable AI assistant features |
| `port` | int | `11813` | AI assistant HTTP server port |
| `api_key` | string | `""` | AI service API key |
| `model` | string | `""` | AI model to use |
| `base_url` | string | `""` | AI service base URL |

### 6.4 MCP Server

```toml
[mcp]
enabled = false
port = 11814
mode = "sse"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable MCP server |
| `port` | int | `11814` | MCP server port |
| `mode` | string | `"sse"` | Communication mode (stdio/sse) |

---

## Configuration File Backup

When `backup_keep > 0`, modifying the configuration file automatically creates a backup:

```
/etc/netxfw/config.toml                    # Current config
/etc/netxfw/config.toml.bak.20240101-120000  # Backup file
```

### Backup Commands

```bash
# List all backups
ls -la /etc/netxfw/*.bak.*

# Restore backup
cp /etc/netxfw/config.toml.bak.20240101-120000 /etc/netxfw/config.toml
```

---

## Configuration Validation

```bash
# Validate configuration file syntax
netxfw validate /etc/netxfw/config.toml

# Show current configuration
netxfw config show
```

---

## Complete Configuration Example

See [04-03_configuration_reference.md](./04-03_configuration_reference.md) for a complete example.
