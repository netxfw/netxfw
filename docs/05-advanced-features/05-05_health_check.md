# 健康检查系统

## 概述

NetXFW 提供完善的健康检查系统，用于监控 BPF Map 状态、服务运行状态和资源使用情况。通过 API 接口和命令行工具，运维人员可以实时了解系统健康状态。

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                      健康检查系统架构                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   HealthChecker                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │ Map 健康检查 │  │ 服务状态检查 │  │ 资源监控    │  │   │
│  │  │ - 容量使用率 │  │ - 运行时间   │  │ - CPU 使用  │  │   │
│  │  │ - 条目数量   │  │ - 错误计数   │  │ - 内存使用  │  │   │
│  │  │ - 增长趋势   │  │ - 重启次数   │  │ - 网络流量  │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    健康状态输出                       │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │ HTTP API    │  │ CLI 命令    │  │ Prometheus  │  │   │
│  │  │ /health     │  │ netxfw      │  │ Metrics     │  │   │
│  │  │ /health/maps│  │ health      │  │             │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## BPF Map 健康检查

### 检查指标

| 指标 | 说明 | 阈值 |
|------|------|------|
| `entries` | 当前条目数 | - |
| `max_entries` | 最大容量 | - |
| `usage_pct` | 使用率百分比 | 警告: 80%, 严重: 95% |
| `status` | 健康状态 | ok/warning/critical |

### 状态判定

```go
// internal/xdp/health_check.go
const (
    statusOK          = "ok"          // 使用率 < 80%
    statusWarning     = "warning"     // 使用率 80% - 95%
    statusCritical    = "critical"    // 使用率 > 95%
    statusUnavailable = "unavailable" // Map 不可用
)
```

### 监控的 Map

| Map 名称 | 类型 | 说明 | 默认容量 |
|----------|------|------|----------|
| `conntrack_map` | LRU_HASH | 连接跟踪 | 100,000 |
| `static_blacklist` | LPM_TRIE | 静态黑名单 | 2,000,000 |
| `dynamic_blacklist` | LRU_HASH | 动态黑名单 | 1,000,000 |
| `critical_blacklist` | HASH | 危机黑名单 | 10,000 |
| `whitelist` | LPM_TRIE | 白名单 | 100,000 |
| `rule_map` | LPM_TRIE | IP+端口规则 | 100,000 |
| `ratelimit_map` | LRU_HASH | 速率限制 | 100,000 |

## API 接口

### 基础健康检查

```bash
GET /healthz
```

响应示例：

```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 详细健康检查

```bash
GET /health
```

响应示例：

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

### Map 健康检查

```bash
GET /health/maps
```

响应示例：

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

### 单个 Map 健康检查

```bash
GET /health/map?name=conntrack_map
```

响应示例：

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

## CLI 命令

### 查看健康状态

```bash
sudo netxfw system health
```

输出示例：

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

### 查看特定 Map 状态

```bash
sudo netxfw system health --map conntrack_map
```

## Prometheus 集成

### 健康指标

```
# Map 使用率
netxfw_map_usage_pct{map="conntrack_map"} 45
netxfw_map_usage_pct{map="static_blacklist"} 85

# Map 条目数
netxfw_map_entries{map="conntrack_map"} 45000
netxfw_map_max_entries{map="conntrack_map"} 100000

# 健康状态 (0=unavailable, 1=ok, 2=warning, 3=critical)
netxfw_map_health_status{map="conntrack_map"} 1

# 整体健康状态
netxfw_health_status 1
```

### 告警规则示例

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

## 阈值配置

### 自定义阈值

```go
// 代码中设置自定义阈值
healthChecker := xdp.NewHealthChecker(manager)
healthChecker.SetThresholds(
    70,  // 警告阈值: 70%
    90,  // 严重阈值: 90%
)
```

### 配置文件

```yaml
# config.yaml
health:
  check_interval: "30s"
  warning_threshold: 80
  critical_threshold: 95
  auto_cleanup: true
  cleanup_threshold: 90
```

## 自动修复

### Map 容量告警处理

当 Map 使用率超过阈值时，系统可以自动执行清理：

```yaml
health:
  auto_cleanup: true
  cleanup_actions:
    - map: "dynamic_blacklist"
      action: "expire_old_entries"
    - map: "conntrack_map"
      action: "expire_idle_connections"
```

### 手动清理

```bash
# 清理过期条目
sudo netxfw system cleanup --expire

# 清理动态黑名单
sudo netxfw dynamic cleanup

# 清理连接跟踪
sudo netxfw conntrack cleanup
```

## 最佳实践

### 1. 定期监控

```bash
# 添加到 cron
*/5 * * * * /usr/local/bin/netxfw system health --quiet || /usr/local/bin/send-alert.sh
```

### 2. 设置告警

集成 Prometheus + AlertManager，配置告警规则。

### 3. 容量规划

根据业务增长趋势，提前规划 Map 容量：

```yaml
capacity:
  conntrack: 200000      # 预留 2x 余量
  lock_list: 4000000     # 预留 2x 余量
  dyn_lock_list: 2000000 # 预留 2x 余量
```

### 4. 日志记录

启用健康检查日志：

```yaml
logging:
  level: "info"
  path: "/var/log/netxfw/health.log"
```

## 故障排查

### Map 使用率持续增长

1. 检查是否有内存泄漏：
   ```bash
   sudo bpftool map dump name dynamic_blacklist | wc -l
   ```

2. 检查过期策略：
   ```bash
   sudo netxfw dynamic list --expired
   ```

3. 手动清理：
   ```bash
   sudo netxfw dynamic cleanup --force
   ```

### 健康检查失败

1. 检查 BPF 程序状态：
   ```bash
   sudo bpftool prog show | grep netxfw
   ```

2. 检查 Map 状态：
   ```bash
   sudo bpftool map show
   ```

3. 检查日志：
   ```bash
   sudo journalctl -u netxfw -n 100
   ```
