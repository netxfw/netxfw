# BPF Map Capacity Configuration Guide

## Overview

NetXFW uses multiple BPF Maps to store firewall rules, connection tracking, and statistics data. Proper capacity configuration balances memory usage and performance.

## Map Types

| Map Name | Type | Description | Auto Eviction |
|----------|------|-------------|---------------|
| `conntrack_map` | LRU_HASH | Connection tracking | ✅ LRU |
| `static_blacklist` | LPM_TRIE | Static blacklist (alias: lock_list) | ❌ |
| `dynamic_blacklist` | LRU_HASH | Dynamic blacklist (alias: dyn_lock_list) | ✅ LRU + TTL |
| `critical_blacklist` | HASH | Critical blocking | ❌ |
| `whitelist` | LPM_TRIE | Whitelist | ❌ |
| `rule_map` | LPM_TRIE | IP+Port rules (merged allowed_ports + ip_port_rules) | ❌ |
| `ratelimit_map` | LRU_HASH | Rate limiting | ✅ LRU |
| `top_drop_map` | LRU_HASH | Drop statistics (alias: drop_reason_stats) | ✅ LRU |
| `top_pass_map` | LRU_HASH | Pass statistics (alias: pass_reason_stats) | ✅ LRU |
| `stats_global_map` | PERCPU_ARRAY | Global statistics | ❌ |
| `global_config` | ARRAY | Global configuration | ❌ |
| `jmp_table` | PROG_ARRAY | Tail call table | ❌ |
| `xsk_map` | XSKMAP | AF_XDP socket | ❌ |

## Default Map Sizes (BPF Code Definitions)

```c
#define CT_MAP_SIZE            100000    // Connection tracking entries
#define RATELIMIT_MAP_SIZE     100000    // Rate limit entries
#define STATIC_BLACKLIST_SIZE  2000000   // Static blacklist entries
#define DYNAMIC_BLACKLIST_SIZE 1000000   // Dynamic blacklist entries
#define CRITICAL_BLACKLIST_SIZE 10000    // Critical blacklist entries
#define WHITELIST_SIZE         100000    // Whitelist entries
#define RULE_MAP_SIZE          100000    // IP+Port rule entries
#define STATS_GLOBAL_SIZE      64        // Global stats slots
#define TOP_STATS_SIZE         1024      // Top stats entries
#define GLOBAL_CONFIG_SIZE     32        // Global config slots
```

## Configuration File Mapping

In `config.yaml`, configure through `capacity` and `conntrack` sections:

```yaml
conntrack:
  enabled: true
  max_entries: 100000      # conntrack_map size
  tcp_timeout: "1h"
  udp_timeout: "5m"

capacity:
  lock_list: 2000000       # static_blacklist size
  dyn_lock_list: 2000000   # dynamic_blacklist size
  whitelist: 65536         # whitelist size
  ip_port_rules: 65536     # rule_map size
  rate_limits: 1000        # ratelimit_map size
  drop_reason_stats: 1000000   # top_drop_map size
  pass_reason_stats: 1000000   # top_pass_map size
```

## Default Configuration (High-End Server)

For servers with 16+ cores, 32GB+ memory:

```yaml
conntrack:
  enabled: true
  max_entries: 100000
  tcp_timeout: "1h"
  udp_timeout: "5m"

capacity:
  lock_list: 2000000           # Static blacklist
  dyn_lock_list: 2000000       # Dynamic blacklist
  whitelist: 65536             # Whitelist
  ip_port_rules: 65536         # IP+Port rules
  rate_limits: 1000            # Rate limits
  drop_reason_stats: 1000000   # Drop statistics
  pass_reason_stats: 1000000   # Pass statistics
```

**Memory Estimate**: ~211 MB

## Medium Configuration (4-8 Cores, 8GB Memory)

```yaml
conntrack:
  enabled: true
  max_entries: 50000
  tcp_timeout: "30m"
  udp_timeout: "2m"

capacity:
  lock_list: 500000
  dyn_lock_list: 500000
  whitelist: 65536
  ip_port_rules: 65536
  rate_limits: 10000
  drop_reason_stats: 100000
  pass_reason_stats: 100000
```

**Memory Estimate**: ~60 MB

## Minimal Configuration (512MB Memory)

For low-end servers, embedded devices:

```yaml
base:
  default_deny: true
  allow_return_traffic: false
  allow_icmp: true
  persist_rules: true
  cleanup_interval: "30s"
  enable_pprof: false

conntrack:
  enabled: true
  max_entries: 50000
  tcp_timeout: "30m"
  udp_timeout: "2m"

capacity:
  lock_list: 20000           # Static blacklist
  dyn_lock_list: 20000       # Dynamic blacklist
  whitelist: 30              # Whitelist
  ip_port_rules: 50          # IP+Port rules
  rate_limits: 1000          # Rate limits
  drop_reason_stats: 5000    # Drop statistics
  pass_reason_stats: 5000    # Pass statistics

rate_limit:
  enabled: true
  auto_block: true
  auto_block_expiry: "5m"

metrics:
  enabled: false
```

**Memory Estimate**: ~8 MB

## Memory Calculation Formula

Estimated memory usage per map:

| Map Type | Size per Entry | Formula |
|----------|---------------|---------|
| LPM_TRIE | ~80-120 bytes | entries × 100 bytes |
| LRU_HASH | ~64-96 bytes | entries × 80 bytes |
| HASH | ~64-96 bytes | entries × 80 bytes |
| PERCPU_ARRAY | Multiplied by CPU cores | slots × struct size × CPU count |

### Example Calculation (High-End Configuration)

```
conntrack_map:     100,000 × 80B = 8 MB
static_blacklist:  2,000,000 × 100B = 200 MB
dynamic_blacklist: 2,000,000 × 80B = 160 MB
whitelist:         65,536 × 100B = 6.5 MB
rule_map:          65,536 × 100B = 6.5 MB
ratelimit_map:     1,000 × 80B = 80 KB
top_drop_map:      1,000,000 × 64B = 64 MB
top_pass_map:      1,000,000 × 64B = 64 MB
-----------------------------------------
Total: ~509 MB (theoretical maximum)
```

**Note**: LRU Hash Maps use lazy allocation, actual memory depends on entries used.

## Configuration Recommendations

### By Scenario

| Scenario | conntrack | blacklist | whitelist | rule_map |
|----------|-----------|-----------|-----------|----------|
| Web Server | 50,000 | 100,000 | 100 | 1,000 |
| API Gateway | 100,000 | 500,000 | 50 | 500 |
| DDoS Protection | 200,000 | 2,000,000 | 200 | 100 |
| Internal Firewall | 20,000 | 10,000 | 500 | 2,000 |

### Tuning Principles

1. **conntrack**: Set based on concurrent connections, typically 1.5-2x max concurrent
2. **blacklist**: Set based on attack scale, DDoS protection needs larger values
3. **whitelist**: Usually small, tens to hundreds of entries
4. **rule_map**: Set based on IP+Port rule count
5. **top_stats**: For analysis, recommend 1000-10000

## Hot Reload Considerations

When modifying `capacity` configuration and running `netxfw reload`:

- **Capacity increase**: Requires reloading XDP program, creates new Maps
- **Capacity decrease**: Also requires reload, data will be truncated
- **Capacity unchanged**: Only updates rules, no Map rebuild needed

```bash
# Hot reload after configuration change
sudo netxfw reload

# Or use system reload for zero-downtime update
sudo netxfw system reload -i eth0
```

## Related Documentation

- [Architecture Overview](./02-02_architecture_en.md) - System architecture
- [Config Management](./07-01_config_management_unification_en.md) - Configuration reference
- [Performance Benchmarks](./performance/06-02_benchmarks_en.md) - Performance testing
