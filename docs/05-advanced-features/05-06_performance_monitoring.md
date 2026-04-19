# 性能监控

## 概述

NetXFW 提供全面的性能监控系统，包括 Map 操作延迟、缓存命中率、实时流量统计等关键指标。通过这些指标，运维人员可以深入了解系统性能瓶颈并进行优化。

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                      性能监控架构                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                PerformanceStats                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │ Map 延迟    │  │ 缓存命中率  │  │ 流量统计    │  │   │
│  │  │ - 读操作    │  │ - 全局统计  │  │ - PPS       │  │   │
│  │  │ - 写操作    │  │ - 丢弃详情  │  │ - BPS       │  │   │
│  │  │ - 删除操作  │  │ - 通过详情  │  │ - 丢包率    │  │   │
│  │  │ - 迭代操作  │  │ - Map 计数  │  │ - 峰值      │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   输出接口                           │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │ HTTP API    │  │ CLI 命令    │  │ Prometheus  │  │   │
│  │  │ /api/perf   │  │ netxfw perf │  │ Metrics     │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 监控指标

### Map 操作延迟

```go
// internal/datapath/xdp/stats/performance.go
type MapLatencyStats struct {
    TotalOperations uint64  // 总操作数
    TotalErrors     uint64  // 总错误数
    TotalLatencyNs  uint64  // 总延迟（纳秒）
    MinLatencyNs    uint64  // 最小延迟
    MaxLatencyNs    uint64  // 最大延迟
    AvgLatencyNs    uint64  // 平均延迟

    // 按操作类型统计
    ReadOps   OperationStats  // 读操作
    WriteOps  OperationStats  // 写操作
    DeleteOps OperationStats  // 删除操作
    IterOps   OperationStats  // 迭代操作

    // 按 Map 统计
    BlacklistOps  OperationStats  // 黑名单操作
    WhitelistOps  OperationStats  // 白名单操作
    ConntrackOps  OperationStats  // 连接跟踪操作
    RateLimitOps  OperationStats  // 速率限制操作
}
```

### 缓存命中率

```go
type CacheHitRateStats struct {
    // 全局统计缓存
    GlobalStatsHits    uint64  // 缓存命中
    GlobalStatsMisses  uint64  // 缓存未命中
    GlobalStatsHitRate float64 // 命中率 (0-1)

    // 丢弃详情缓存
    DropDetailsHits    uint64
    DropDetailsMisses  uint64
    DropDetailsHitRate float64

    // 通过详情缓存
    PassDetailsHits    uint64
    PassDetailsMisses  uint64
    PassDetailsHitRate float64

    // Map 计数缓存
    MapCountsHits    uint64
    MapCountsMisses  uint64
    MapCountsHitRate float64
}
```

### 实时流量统计

```go
type TrafficStats struct {
    PacketsPerSecond   uint64  // 每秒包数
    BytesPerSecond     uint64  // 每秒字节数
    DropsPerSecond     uint64  // 每秒丢包数
    PassPerSecond      uint64  // 每秒通过数

    PeakPPS            uint64  // PPS 峰值
    PeakBPS            uint64  // BPS 峰值

    TotalPackets       uint64  // 总包数
    TotalBytes         uint64  // 总字节数
    TotalDrops         uint64  // 总丢包数
}
```

## API 接口

### 获取性能统计

```bash
GET /api/perf
```

响应示例：

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime": "2h30m15s",
  "map_latency": {
    "total_operations": 1500000,
    "total_errors": 12,
    "total_latency_ns": 45000000000,
    "min_latency_ns": 100,
    "max_latency_ns": 500000,
    "avg_latency_ns": 30000,
    "read_ops": {
      "count": 1000000,
      "avg_latency": 25000
    },
    "write_ops": {
      "count": 450000,
      "avg_latency": 35000
    }
  },
  "cache_hit_rate": {
    "global_stats_hit_rate": 0.95,
    "drop_details_hit_rate": 0.88,
    "pass_details_hit_rate": 0.92,
    "map_counts_hit_rate": 0.97,
    "total_hit_rate": 0.93
  },
  "traffic": {
    "packets_per_second": 125000,
    "bytes_per_second": 187500000,
    "drops_per_second": 150,
    "peak_pps": 250000,
    "peak_bps": 375000000
  }
}
```

### 获取延迟详情

```bash
GET /api/perf/latency
```

响应示例：

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "operations": {
    "read": {
      "count": 1000000,
      "total_latency_ns": 25000000000,
      "min_latency_ns": 100,
      "max_latency_ns": 100000,
      "avg_latency_ns": 25000,
      "errors": 5
    },
    "write": {
      "count": 450000,
      "total_latency_ns": 15750000000,
      "min_latency_ns": 200,
      "max_latency_ns": 200000,
      "avg_latency_ns": 35000,
      "errors": 3
    },
    "delete": {
      "count": 50000,
      "total_latency_ns": 2000000000,
      "min_latency_ns": 150,
      "max_latency_ns": 150000,
      "avg_latency_ns": 40000,
      "errors": 2
    }
  },
  "by_map": {
    "blacklist": {
      "count": 500000,
      "avg_latency_ns": 28000
    },
    "whitelist": {
      "count": 100000,
      "avg_latency_ns": 22000
    },
    "conntrack": {
      "count": 800000,
      "avg_latency_ns": 32000
    }
  }
}
```

### 获取缓存统计

```bash
GET /api/perf/cache
```

响应示例：

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "caches": {
    "global_stats": {
      "hits": 950000,
      "misses": 50000,
      "hit_rate": 0.95
    },
    "drop_details": {
      "hits": 880000,
      "misses": 120000,
      "hit_rate": 0.88
    },
    "pass_details": {
      "hits": 920000,
      "misses": 80000,
      "hit_rate": 0.92
    },
    "map_counts": {
      "hits": 970000,
      "misses": 30000,
      "hit_rate": 0.97
    }
  },
  "total": {
    "hits": 3720000,
    "misses": 280000,
    "hit_rate": 0.93
  }
}
```

### 获取流量统计

```bash
GET /api/perf/traffic
```

响应示例：

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "current": {
    "pps": 125000,
    "bps": 187500000,
    "drops_per_second": 150,
    "pass_per_second": 124850
  },
  "peak": {
    "pps": 250000,
    "bps": 375000000,
    "timestamp": "2024-01-15T09:45:00Z"
  },
  "total": {
    "packets": 45000000000,
    "bytes": 67500000000000,
    "drops": 54000000,
    "pass": 44946000000
  },
  "rates": {
    "drop_rate": 0.0012,
    "pass_rate": 0.9988
  }
}
```

### 重置统计

```bash
POST /api/perf/reset
```

## CLI 命令

### 查看性能概览

```bash
sudo netxfw perf
```

输出示例：

```
NetXFW Performance Statistics
==============================

Uptime: 2h30m15s

Map Latency:
  Total Operations: 1,500,000
  Total Errors:     12
  Avg Latency:      30.0 µs
  Min Latency:      100 ns
  Max Latency:      500.0 µs

  By Operation:
    Read:   1,000,000 ops, avg 25.0 µs
    Write:    450,000 ops, avg 35.0 µs
    Delete:   50,000 ops, avg 40.0 µs

Cache Hit Rate:
  Total Hit Rate:   93.0%
  Global Stats:     95.0%
  Drop Details:     88.0%
  Pass Details:     92.0%
  Map Counts:       97.0%

Traffic:
  Current PPS:      125,000
  Current BPS:      187.5 MB/s
  Peak PPS:         250,000
  Peak BPS:         375.0 MB/s
  Drop Rate:        0.12%
```

### 查看延迟详情

```bash
sudo netxfw perf latency
```

### 查看缓存统计

```bash
sudo netxfw perf cache
```

### 查看流量统计

```bash
sudo netxfw perf traffic
```

### 持续监控

```bash
sudo netxfw perf watch --interval 1s
```

输出示例：

```
Time                 PPS        BPS        Drop/s   Cache%   Latency
10:30:00            125,000    187.5 MB   150      93.0%    30.0 µs
10:30:01            126,500    189.8 MB   145      93.2%    29.5 µs
10:30:02            124,800    187.2 MB   152      92.8%    30.2 µs
10:30:03            127,200    190.8 MB   148      93.1%    29.8 µs
```

## Prometheus 集成

### 性能指标

```
# Map 操作延迟
netxfw_map_latency_avg_ns{operation="read"} 25000
netxfw_map_latency_avg_ns{operation="write"} 35000
netxfw_map_latency_avg_ns{operation="delete"} 40000

# Map 操作计数
netxfw_map_operations_total{operation="read"} 1000000
netxfw_map_operations_total{operation="write"} 450000
netxfw_map_errors_total{operation="read"} 5

# 缓存命中率
netxfw_cache_hit_rate{cache="global_stats"} 0.95
netxfw_cache_hit_rate{cache="drop_details"} 0.88
netxfw_cache_hit_rate_total 0.93

# 流量统计
netxfw_traffic_pps 125000
netxfw_traffic_bps 1.875e+08
netxfw_traffic_drops_per_second 150
netxfw_traffic_peak_pps 250000
netxfw_traffic_peak_bps 3.75e+08
```

### Grafana 仪表板

推荐创建以下面板：

1. **流量概览**
   - PPS 折线图
   - BPS 折线图
   - 丢包率仪表盘

2. **延迟监控**
   - 平均延迟折线图
   - P99 延迟折线图
   - 操作类型分布饼图

3. **缓存性能**
   - 命中率仪表盘
   - 各缓存命中率对比

## 性能优化建议

### 延迟优化

| 延迟范围 | 状态 | 建议 |
|----------|------|------|
| < 10 µs | 优秀 | 无需优化 |
| 10-50 µs | 良好 | 正常范围 |
| 50-100 µs | 一般 | 检查 Map 大小 |
| > 100 µs | 较差 | 优化 Map 配置或扩容 |

### 缓存命中率优化

| 命中率 | 状态 | 建议 |
|--------|------|------|
| > 95% | 优秀 | 无需优化 |
| 90-95% | 良好 | 正常范围 |
| 80-90% | 一般 | 增加缓存大小 |
| < 80% | 较差 | 检查访问模式 |

### 流量处理优化

```yaml
# 高流量场景配置
capacity:
  conntrack: 500000      # 增加连接跟踪容量
  dyn_lock_list: 2000000 # 增加动态黑名单

# 调整缓存参数
cache:
  stats_ttl: "5s"        # 统计缓存 TTL
  counts_ttl: "10s"      # 计数缓存 TTL
```

## 基准测试

### 运行基准测试

```bash
# 运行内置基准测试
sudo netxfw perf benchmark

# 指定测试参数
sudo netxfw perf benchmark --duration 60s --pps 100000
```

### 基准测试结果示例

```
NetXFW Benchmark Results
========================

Duration: 60s
Target PPS: 100,000

Results:
  Actual PPS:        99,850
  Actual BPS:        149.8 MB/s
  Drop Rate:         0.15%
  Avg Latency:       28.5 µs
  P99 Latency:       85.0 µs
  CPU Usage:         15.2%
  Memory Usage:      512 MB

Map Performance:
  Blacklist Lookup:  12.5 µs
  Whitelist Lookup:  10.2 µs
  Conntrack Lookup:  15.8 µs

Cache Performance:
  Hit Rate:          94.5%
  Avg Lookup:        2.1 µs
```

## 故障排查

### 延迟异常高

1. 检查 Map 大小：
   ```bash
   sudo netxfw system health --maps
   ```

2. 检查 CPU 使用：
   ```bash
   top -p $(pgrep netxfw)
   ```

3. 检查内存压力：
   ```bash
   cat /proc/meminfo | grep -i mem
   ```

### 缓存命中率低

1. 检查缓存配置：
   ```bash
   sudo netxfw perf cache --detail
   ```

2. 分析访问模式：
   ```bash
   sudo netxfw perf traffic --top
   ```

### 流量处理瓶颈

1. 检查 XDP 模式：
   ```bash
   sudo bpftool net show
   ```

2. 检查网卡队列：
   ```bash
   ethtool -l eth0
   ```

3. 优化 RSS 配置：
   ```bash
   ethtool -X eth0 equal 4
   ```
