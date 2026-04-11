# Health Check System

## Overview

NetXFW provides a comprehensive health check system for monitoring BPF Map status, service running status, and resource usage. Through API interfaces and command-line tools, operators can understand the system health status in real-time.

## Architecture Design

```
┌─────────────────────────────────────────────────────────────┐
│                   Health Check System Architecture           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   HealthChecker                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │ Map Health  │  │ Service     │  │ Resource    │  │   │
│  │  │ Check       │  │ Status      │  │ Monitoring  │  │   │
│  │  │ - Capacity  │  │ - Uptime    │  │ - CPU Usage │  │   │
│  │  │ - Entries   │  │ - Errors    │  │ - Memory    │  │   │
│  │  │ - Trends    │  │ - Restarts  │  │ - Network   │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  Health Status Output                │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │ HTTP API    │  │ CLI Command │  │ Prometheus  │  │   │
│  │  │ /health     │  │ netxfw      │  │ Metrics     │  │   │
│  │  │ /health/maps│  │ health      │  │             │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## BPF Map Health Check

### Check Metrics

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `entries` | Current entry count | - |
| `max_entries` | Maximum capacity | - |
| `usage_pct` | Usage percentage | Warning: 80%, Critical: 95% |
| `status` | Health status | ok/warning/critical |

### Status Determination

```go
// internal/xdp/health_check.go
const (
    statusOK          = "ok"          // Usage < 80%
    statusWarning     = "warning"     // Usage 80% - 95%
    statusCritical    = "critical"    // Usage > 95%
    statusUnavailable = "unavailable" // Map unavailable
)
```

### Monitored Maps

| Map Name | Type | Description | Default Capacity |
|----------|------|-------------|------------------|
| `conntrack_map` | LRU_HASH | Connection tracking | 100,000 |
| `static_blacklist` | LPM_TRIE | Static blacklist | 2,000,000 |
| `dynamic_blacklist` | LRU_HASH | Dynamic blacklist | 1,000,000 |
| `critical_blacklist` | HASH | Critical blacklist | 10,000 |
| `whitelist` | LPM_TRIE | Whitelist | 100,000 |
| `rule_map` | LPM_TRIE | IP+Port rules | 100,000 |
| `ratelimit_map` | LRU_HASH | Rate limiting | 100,000 |

## API Interface

### Basic Health Check

```bash
GET /healthz
```

Response example:

```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Detailed Health Check

```bash
GET /health
```

Response example:

```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime": "2h30m15s",
  "version": "1.0.0",
  "checks": {
    "bpf_maps": "ok",
    "xdp_attached": "ok",
    "config_loaded": "ok"
  }
}
```

### Map Health Check

```bash
GET /health/maps
```

Response example:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime": "2h30m15s",
  "overall_status": "ok",
  "total_maps": 7,
  "healthy_maps": 6,
  "warning_maps": 1,
  "critical_maps": 0,
  "total_entries": 150000,
  "total_capacity": 3400000,
  "bpf_maps": {
    "conntrack_map": {
      "name": "conntrack_map",
      "type": "LRU_HASH",
      "entries": 45000,
      "max_entries": 100000,
      "usage_pct": 45,
      "status": "ok",
      "message": "Normal operation"
    },
    "static_blacklist": {
      "name": "static_blacklist",
      "type": "LPM_TRIE",
      "entries": 85000,
      "max_entries": 100000,
      "usage_pct": 85,
      "status": "warning",
      "message": "Approaching capacity limit"
    },
    "dynamic_blacklist": {
      "name": "dynamic_blacklist",
      "type": "LRU_HASH",
      "entries": 20000,
      "max_entries": 1000000,
      "usage_pct": 2,
      "status": "ok",
      "message": "Normal operation"
    }
  }
}
```

### Single Map Health Check

```bash
GET /health/map?name=conntrack_map
```

Response example:

```json
{
  "name": "conntrack_map",
  "type": "LRU_HASH",
  "entries": 45000,
  "max_entries": 100000,
  "usage_pct": 45,
  "status": "ok",
  "message": "Normal operation",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## CLI Commands

### View Health Status

```bash
sudo netxfw system health
```

Output example:

```
NetXFW Health Status
====================

Timestamp: 2024-01-15 10:30:00
Uptime: 2h30m15s
Overall Status: ok

BPF Maps Summary:
  Total Maps:    7
  Healthy:       6
  Warning:       1
  Critical:      0
  Total Entries: 150,000 / 3,400,000 (4.4%)

Map Details:
  ┌────────────────────┬───────────┬───────────┬─────────┬─────────┐
  │ Map                │ Type      │ Usage     │ Status  │ Message │
  ├────────────────────┼───────────┼───────────┼─────────┼─────────┤
  │ conntrack_map      │ LRU_HASH  │ 45,000    │ ok      │ Normal  │
  │ static_blacklist   │ LPM_TRIE  │ 85,000    │ warning │ Near    │
  │                    │           │           │         │ limit   │
  │ dynamic_blacklist  │ LRU_HASH  │ 20,000    │ ok      │ Normal  │
  │ critical_blacklist │ HASH      │ 150       │ ok      │ Normal  │
  │ whitelist          │ LPM_TRIE  │ 500       │ ok      │ Normal  │
  │ rule_map           │ LPM_TRIE  │ 1,200     │ ok      │ Normal  │
  │ ratelimit_map      │ LRU_HASH  │ 350       │ ok      │ Normal  │
  └────────────────────┴───────────┴───────────┴─────────┴─────────┘
```

### View Specific Map Status

```bash
sudo netxfw system health --map conntrack_map
```

## Prometheus Integration

### Health Metrics

```
# Map usage percentage
netxfw_map_usage_pct{map="conntrack_map"} 45
netxfw_map_usage_pct{map="static_blacklist"} 85

# Map entry count
netxfw_map_entries{map="conntrack_map"} 45000
netxfw_map_max_entries{map="conntrack_map"} 100000

# Health status (0=unavailable, 1=ok, 2=warning, 3=critical)
netxfw_map_health_status{map="conntrack_map"} 1

# Overall health status
netxfw_health_status 1
```

### Alert Rules Example

```yaml
groups:
  - name: netxfw
    rules:
      - alert: NetXFWMapUsageWarning
        expr: netxfw_map_usage_pct > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "NetXFW Map usage warning"
          description: "Map {{ $labels.map }} usage is {{ $value }}%"

      - alert: NetXFWMapUsageCritical
        expr: netxfw_map_usage_pct > 95
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "NetXFW Map usage critical"
          description: "Map {{ $labels.map }} usage is {{ $value }}%"

      - alert: NetXFWUnhealthy
        expr: netxfw_health_status > 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "NetXFW is unhealthy"
          description: "NetXFW health status is {{ $value }}"
```

## Threshold Configuration

### Custom Thresholds

```go
// Set custom thresholds in code
healthChecker := xdp.NewHealthChecker(manager)
healthChecker.SetThresholds(
    70,  // Warning threshold: 70%
    90,  // Critical threshold: 90%
)
```

### Configuration File

```yaml
# config.toml
health:
  check_interval: "30s"
  warning_threshold: 80
  critical_threshold: 95
  auto_cleanup: true
  cleanup_threshold: 90
```

## Auto Recovery

### Map Capacity Alert Handling

When Map usage exceeds threshold, system can automatically perform cleanup:

```yaml
health:
  auto_cleanup: true
  cleanup_actions:
    - map: "dynamic_blacklist"
      action: "expire_old_entries"
    - map: "conntrack_map"
      action: "expire_idle_connections"
```

### Manual Cleanup

```bash
# Cleanup expired entries
sudo netxfw system cleanup --expire

# Cleanup dynamic blacklist
sudo netxfw dynamic cleanup

# Cleanup connection tracking
sudo netxfw conntrack cleanup
```

## Best Practices

### 1. Regular Monitoring

```bash
# Add to cron
*/5 * * * * /usr/local/bin/netxfw system health --quiet || /usr/local/bin/send-alert.sh
```

### 2. Set Up Alerts

Integrate Prometheus + AlertManager with configured alert rules.

### 3. Capacity Planning

Plan Map capacity in advance based on business growth trends:

```yaml
capacity:
  conntrack: 200000      # Reserve 2x headroom
  lock_list: 4000000     # Reserve 2x headroom
  dyn_lock_list: 2000000 # Reserve 2x headroom
```

### 4. Logging

Enable health check logging:

```yaml
logging:
  level: "info"
  path: "/var/log/netxfw/health.log"
```

## Troubleshooting

### Map Usage Continuously Growing

1. Check for memory leaks:
   ```bash
   sudo bpftool map dump name dynamic_blacklist | wc -l
   ```

2. Check expiration policy:
   ```bash
   sudo netxfw dynamic list --expired
   ```

3. Manual cleanup:
   ```bash
   sudo netxfw dynamic cleanup --force
   ```

### Health Check Failure

1. Check BPF program status:
   ```bash
   sudo bpftool prog show | grep netxfw
   ```

2. Check Map status:
   ```bash
   sudo bpftool map show
   ```

3. Check logs:
   ```bash
   sudo journalctl -u netxfw -n 100
   ```
