# BPF Map 容量配置指南

## 概述

NetXFW 使用多个 BPF Map 存储防火墙规则、连接跟踪和统计数据。合理的容量配置可以在内存占用和性能之间取得平衡。

## Map 类型说明

| Map 名称 | 类型 | 说明 | 自动淘汰 |
|----------|------|------|----------|
| `conntrack_map` | LRU_HASH | 连接跟踪 | ✅ LRU |
| `static_blacklist` | LPM_TRIE | 静态黑名单 (别名: lock_list) | ❌ |
| `dynamic_blacklist` | LRU_HASH | 动态黑名单 (别名: dyn_lock_list) | ✅ LRU + TTL |
| `critical_blacklist` | HASH | 危机封锁 | ❌ |
| `whitelist` | LPM_TRIE | 白名单 | ❌ |
| `rule_map` | LPM_TRIE | IP+端口规则 (合并 allowed_ports + ip_port_rules) | ❌ |
| `ratelimit_map` | LRU_HASH | 速率限制 | ✅ LRU |
| `top_drop_map` | LRU_HASH | 丢弃统计 (别名: drop_reason_stats) | ✅ LRU |
| `top_pass_map` | LRU_HASH | 通过统计 (别名: pass_reason_stats) | ✅ LRU |
| `stats_global_map` | PERCPU_ARRAY | 全局统计 | ❌ |
| `global_config` | ARRAY | 全局配置 | ❌ |
| `jmp_table` | PROG_ARRAY | 尾调用表 | ❌ |
| `xsk_map` | XSKMAP | AF_XDP socket | ❌ |

## Map 大小默认值 (BPF 代码定义)

```c
#define CT_MAP_SIZE            100000    // 连接跟踪条目
#define RATELIMIT_MAP_SIZE     100000    // 速率限制条目
#define STATIC_BLACKLIST_SIZE  2000000   // 静态黑名单条目
#define DYNAMIC_BLACKLIST_SIZE 1000000   // 动态黑名单条目
#define CRITICAL_BLACKLIST_SIZE 10000    // 危机封锁条目
#define WHITELIST_SIZE         100000    // 白名单条目
#define RULE_MAP_SIZE          100000    // IP+端口规则条目
#define STATS_GLOBAL_SIZE      64        // 全局统计槽位
#define TOP_STATS_SIZE         1024      // Top 统计条目
#define GLOBAL_CONFIG_SIZE     32        // 全局配置槽位
```

## 配置文件映射

在 `config.yaml` 中，通过 `capacity` 和 `conntrack` 部分配置：

```yaml
conntrack:
  enabled: true
  max_entries: 100000      # conntrack_map 大小
  tcp_timeout: "1h"
  udp_timeout: "5m"

capacity:
  lock_list: 2000000       # static_blacklist 大小
  dyn_lock_list: 2000000   # dynamic_blacklist 大小
  whitelist: 65536         # whitelist 大小
  ip_port_rules: 65536     # rule_map 大小
  rate_limits: 1000        # ratelimit_map 大小
  drop_reason_stats: 1000000   # top_drop_map 大小
  pass_reason_stats: 1000000   # top_pass_map 大小
```

## 默认配置 (高配服务器)

适用于 16+ 核、32GB+ 内存的服务器：

```yaml
conntrack:
  enabled: true
  max_entries: 100000
  tcp_timeout: "1h"
  udp_timeout: "5m"

capacity:
  lock_list: 2000000           # 静态黑名单
  dyn_lock_list: 2000000       # 动态黑名单
  whitelist: 65536             # 白名单
  ip_port_rules: 65536         # IP+端口规则
  rate_limits: 1000            # 速率限制
  drop_reason_stats: 1000000   # 丢弃统计
  pass_reason_stats: 1000000   # 通过统计
```

**内存估算**: ~211 MB

## 中等配置 (4-8 核, 8GB 内存)

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

**内存估算**: ~60 MB

## 精简配置 (512MB 内存)

适用于低配服务器、嵌入式设备：

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
  lock_list: 20000           # 静态黑名单
  dyn_lock_list: 20000       # 动态黑名单
  whitelist: 30              # 白名单
  ip_port_rules: 50          # IP+端口规则
  rate_limits: 1000          # 速率限制
  drop_reason_stats: 5000    # 丢弃统计
  pass_reason_stats: 5000    # 通过统计

rate_limit:
  enabled: true
  auto_block: true
  auto_block_expiry: "5m"

metrics:
  enabled: false
```

**内存估算**: ~8 MB

## 内存计算公式

每个 Map 的内存占用估算：

| Map 类型 | 每条目大小 | 计算公式 |
|----------|-----------|----------|
| LPM_TRIE | ~80-120 字节 | 条目数 × 100 字节 |
| LRU_HASH | ~64-96 字节 | 条目数 × 80 字节 |
| HASH | ~64-96 字节 | 条目数 × 80 字节 |
| PERCPU_ARRAY | 按 CPU 核心数倍增 | 槽位数 × 结构体大小 × CPU数 |

### 示例计算 (高配配置)

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
总计约: 509 MB (理论最大值)
```

**注意**: LRU Hash Map 采用懒分配，实际内存占用取决于实际使用的条目数。

## 配置建议

### 按场景配置

| 场景 | conntrack | blacklist | whitelist | rule_map |
|------|-----------|-----------|-----------|----------|
| Web 服务器 | 50,000 | 100,000 | 100 | 1,000 |
| API 网关 | 100,000 | 500,000 | 50 | 500 |
| DDoS 防护 | 200,000 | 2,000,000 | 200 | 100 |
| 内网防火墙 | 20,000 | 10,000 | 500 | 2,000 |

### 调优原则

1. **conntrack**: 根据并发连接数设置，通常为最大并发数的 1.5-2 倍
2. **blacklist**: 根据攻击规模设置，DDoS 防护需要较大值
3. **whitelist**: 通常较小，几十到几百条
4. **rule_map**: 根据 IP+端口规则数量设置
5. **top_stats**: 用于分析，建议设置为 1000-10000

## 热重载注意事项

当修改 `capacity` 配置后执行 `netxfw reload`：

- **容量增加**: 需要重新加载 XDP 程序，创建新的 Map
- **容量减少**: 同样需要重新加载，数据会被截断
- **容量不变**: 仅更新规则，无需重建 Map

```bash
# 修改配置后热重载
sudo netxfw reload

# 或使用 system reload 进行无损更新
sudo netxfw system reload -i eth0
```

## 相关文档

- [架构概览](./02-01_architecture.md) - 系统架构
- [配置管理](./07-01_config_management_unification.md) - 配置说明
- [性能基准测试](./performance/06-01_benchmarks.md) - 性能测试
