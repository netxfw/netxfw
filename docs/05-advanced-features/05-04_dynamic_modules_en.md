# Dynamic Module Ordering

## Overview

NetXFW supports runtime dynamic adjustment of XDP module execution order without recompiling BPF programs. By defining module priorities in the configuration file, the system automatically builds the execution chain, enabling flexible firewall policies.

## Architecture Design

### Core Mechanism

```
┌─────────────────────────────────────────────────────────────┐
│                    Configuration (config.toml)               │
│  modules:                                                    │
│    - name: "sanity"        priority: 0                       │
│    - name: "critical_blacklist" priority: 10                 │
│    - name: "whitelist"     priority: 20                      │
│    ...                                                       │
└──────────────────────────┬──────────────────────────────────┘
                           │ SyncModules()
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    chain_map (ARRAY)                         │
│  ┌─────────┬───────────────────────────────────────────┐    │
│  │ Key     │ Value (jmp_table index)                   │    │
│  ├─────────┼───────────────────────────────────────────┤    │
│  │ 0 (ENTRY)│ → 20 (sanity's jmp_idx)                  │    │
│  │ 1 (SANITY)│ → 21 (critical's jmp_idx)               │    │
│  │ 2 (CRITICAL)│ → 22 (whitelist's jmp_idx)            │    │
│  │ ...     │                                           │    │
│  └─────────┴───────────────────────────────────────────┘    │
└──────────────────────────┬──────────────────────────────────┘
                           │ bpf_tail_call()
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    jmp_table (PROG_ARRAY)                    │
│  ┌─────────┬───────────────────────────────────────────┐    │
│  │ Index   │ BPF Program                               │    │
│  ├─────────┼───────────────────────────────────────────┤    │
│  │ 20      │ xdp_sanity                                │    │
│  │ 21      │ xdp_critical                              │    │
│  │ 22      │ xdp_whitelist                             │    │
│  │ ...     │                                           │    │
│  │ 0       │ xdp_ipv4 (protocol handler)               │    │
│  │ 1       │ xdp_ipv6 (protocol handler)               │    │
│  │ 2-15    │ Plugin slots (reserved)                   │    │
│  └─────────┴───────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### BPF Layer Implementation

Each module implements chain calling via `tail_call_next()`:

```c
// bpf/wrappers.bpf.c
static __always_inline int tail_call_next(struct xdp_md *ctx, __u32 current_mod_id) {
    __u32 key = current_mod_id;
    __u32 *next_prog_idx = bpf_map_lookup_elem(&chain_map, &key);
    if (next_prog_idx) {
        bpf_tail_call(ctx, &jmp_table, *next_prog_idx);
    }
    return XDP_PASS;  // Chain end, pass
}

// Module example
SEC("xdp/sanity")
int xdp_sanity(struct xdp_md *ctx) {
    // ... processing logic ...
    return tail_call_next(ctx, MOD_ID_SANITY);  // Jump to next
}
```

### Go Layer Chain Building

```go
// internal/datapath/xdp/plugins/lifecycle.go
func (m *Manager) SyncModules(configs []types.ModuleConfig) error {
    // 1. Sort by priority
    sort.Slice(sorted, func(i, j int) bool {
        return sorted[i].Priority < sorted[j].Priority
    })
    
    // 2. Build chain
    for i, cfg := range sorted {
        progIdx := startIdx + uint32(i)
        
        // Update jmp_table
        m.jmpTable.Update(progIdx, def.Program, ebpf.UpdateAny)
        
        // Link previous module to this one
        m.chainMap.Update(previousModID, progIdx, ebpf.UpdateAny)
        
        previousModID = def.ID
    }
    
    // 3. Terminate chain
    m.chainMap.Delete(previousModID)
}
```

## Available Modules

| Module Name | ID | Description | Suggested Priority |
|-------------|-----|-------------|-------------------|
| `sanity` | 1 | Basic validation: Bogon filter, fragment check, TCP flags validation, Land attack detection | 0 |
| `critical_blacklist` | 2 | Critical blacklist: Highest priority blocking, never auto-evict | 10 |
| `whitelist` | 3 | Whitelist: Globally allowed IPs/CIDRs | 20 |
| `blacklist` | 4 | Static blacklist: Manual/CIDR blocking, persistent | 30 |
| `dynamic_blacklist` | 5 | Dynamic blacklist: Auto-blocking with TTL auto-expiry | 35 |
| `ratelimit` | 6 | Rate limiting: DoS/DDoS attack prevention | 40 |
| `conntrack` | 7 | Connection tracking: Maintain connection state | 50 |
| `ip_port_rules` | 8 | IP+Port rules: Fine-grained access control | 60 |
| `icmp` | 9 | ICMP rate limiting | 70 |
| `return_traffic` | 10 | Return traffic pass: Stateless return check | 80 |

## Configuration Examples

### Default Configuration

```yaml
# config.toml
modules:
  - name: "sanity"
    enabled: true
    priority: 0
  - name: "critical_blacklist"
    enabled: true
    priority: 10
  - name: "whitelist"
    enabled: true
    priority: 20
  - name: "blacklist"
    enabled: true
    priority: 30
  - name: "dynamic_blacklist"
    enabled: true
    priority: 35
  - name: "ratelimit"
    enabled: true
    priority: 40
  - name: "conntrack"
    enabled: true
    priority: 50
  - name: "ip_port_rules"
    enabled: true
    priority: 60
  - name: "icmp"
    enabled: true
    priority: 70
  - name: "return_traffic"
    enabled: true
    priority: 80
```

### High Security Mode

Prioritize security checks, delay pass:

```yaml
modules:
  - name: "sanity"
    enabled: true
    priority: 0
  - name: "critical_blacklist"
    enabled: true
    priority: 10
  - name: "blacklist"
    enabled: true
    priority: 20
  - name: "dynamic_blacklist"
    enabled: true
    priority: 30
  - name: "ratelimit"
    enabled: true
    priority: 40
  - name: "whitelist"
    enabled: true
    priority: 50
  - name: "conntrack"
    enabled: true
    priority: 60
  - name: "ip_port_rules"
    enabled: true
    priority: 70
  - name: "icmp"
    enabled: true
    priority: 80
  - name: "return_traffic"
    enabled: true
    priority: 90
```

### High Performance Mode

Prioritize passing known safe traffic:

```yaml
modules:
  - name: "sanity"
    enabled: true
    priority: 0
  - name: "whitelist"
    enabled: true
    priority: 10
  - name: "conntrack"
    enabled: true
    priority: 20
  - name: "return_traffic"
    enabled: true
    priority: 30
  - name: "critical_blacklist"
    enabled: true
    priority: 40
  - name: "blacklist"
    enabled: true
    priority: 50
  - name: "dynamic_blacklist"
    enabled: true
    priority: 60
  - name: "ratelimit"
    enabled: true
    priority: 70
  - name: "ip_port_rules"
    enabled: true
    priority: 80
  - name: "icmp"
    enabled: false
```

## Module Dependencies

Some modules have implicit dependencies, pay attention to order when configuring:

```
sanity (must be first)
    │
    ▼
critical_blacklist
    │
    ▼
whitelist ←───┐
    │         │
    ▼         │
blacklist     │ conntrack should be before return_traffic
    │         │
    ▼         │
dynamic_blacklist
    │
    ▼
ratelimit
    │
    ▼
conntrack ─────┘
    │
    ▼
ip_port_rules
    │
    ▼
icmp
    │
    ▼
return_traffic (usually last)
```

### Dependency Rules

| Module | Depends On | Description |
|--------|------------|-------------|
| `return_traffic` | `conntrack` | Return traffic check depends on connection state |
| `dynamic_blacklist` | `blacklist` | Dynamic blacklist should be checked after static |
| `whitelist` | - | Should be before blacklist to ensure whitelist priority |

## Hot Reload

After modifying module configuration, send signal to trigger hot reload:

```bash
# Send SIGHUP signal
sudo kill -HUP $(cat /var/run/netxfw.pid)

# Or use CLI
sudo netxfw system reload
```

## Performance Considerations

### Tail Call Overhead

BPF `tail_call` is zero-overhead jump:
- No user/kernel space switching
- No register save/restore
- Direct jump to next BPF program

### Index Allocation

```
┌─────────────────────────────────────────┐
│          jmp_table Index Allocation      │
├─────────────────────────────────────────┤
│ 0-1    │ Protocol handlers (ipv4/ipv6)   │
│ 2-15   │ Plugin slots (user-defined)     │
│ 16-19  │ Reserved                        │
│ 20+    │ Built-in modules                │
└─────────────────────────────────────────┘
```

## API Interface

### Get Current Module Order

```bash
GET /api/modules
```

Response example:

```json
{
  "modules": [
    {"name": "sanity", "enabled": true, "priority": 0},
    {"name": "critical_blacklist", "enabled": true, "priority": 10},
    {"name": "whitelist", "enabled": true, "priority": 20}
  ]
}
```

### Update Module Order

```bash
POST /api/modules
Content-Type: application/json

{
  "modules": [
    {"name": "sanity", "enabled": true, "priority": 0},
    {"name": "whitelist", "enabled": true, "priority": 10}
  ]
}
```

## Troubleshooting

### Module Not Taking Effect

1. Check if module is enabled:
   ```bash
   sudo netxfw system status | grep modules
   ```

2. Check chain_map content:
   ```bash
   sudo bpftool map dump name chain_map
   ```

3. Check jmp_table content:
   ```bash
   sudo bpftool map dump name jmp_table
   ```

### Module Order Error

Check logs to confirm chain building process:

```bash
sudo journalctl -u netxfw -f | grep "Module Linked"
```

Expected output:

```
Module Linked: sanity (ID: 1) -> JmpIdx: 20
Module Linked: critical_blacklist (ID: 2) -> JmpIdx: 21
Module Linked: whitelist (ID: 3) -> JmpIdx: 22
...
```

## Best Practices

1. **Keep sanity module with lowest priority**: Basic validation should execute before all other modules
2. **Whitelist before blacklist**: Ensure trusted traffic is not mistakenly blocked
3. **conntrack before return_traffic**: Ensure connection state is established
4. **Disable unused modules**: Reduce processing overhead
5. **Test configuration changes**: Validate in test environment before production
