# 配置文件参考 (Configuration Reference)

本文档详细说明 NetXFW 的 TOML 配置文件结构和各配置项的含义。

## 配置文件位置

| 模式 | 配置文件路径 |
|------|-------------|
| Agent 模式 | `/etc/netxfw/config-agent.toml` |
| DP 模式 | `/etc/netxfw/config-dp.toml` |
| 默认路径 | `/etc/netxfw/config.toml` |

## 配置文件结构

```
1. Core Configuration / 核心配置
   ├── Base Configuration / 基础配置
   ├── Network Interfaces / 网络接口
   ├── Protocol Security / 协议安全
   ├── ICMP Rate Limiting / ICMP 速率限制
   ├── Cleanup & Expiry / 清理与过期
   ├── Debug / 调试
   └── File Paths / 文件路径

2. Security Rules / 安全规则
   ├── Whitelist / 白名单
   ├── Port Configuration / 端口配置
   ├── IP-Port Rules / IP-端口规则
   ├── Rate Limit / 速率限制
   └── Connection Tracking / 连接跟踪

3. XDP Configuration / XDP 配置
   ├── Capacity / 容量配置
   ├── Module Configuration / 模块配置
   └── BPF Plugin / BPF 插件

4. Services / 服务
   ├── Web API Server / Web API 服务器
   └── Metrics / 监控指标

5. Logging / 日志
   ├── Log Engine / 日志引擎
   └── Application Logging / 应用日志

6. Advanced / 高级配置
   ├── Cluster / 集群
   ├── Cloud Environment / 云环境
   ├── AI Assistant / AI 助手
   └── MCP Server / MCP 服务器
```

---

## 1. 核心配置 (Core Configuration)

### 1.1 基础配置 (Base Configuration)

```toml
[base]
default_deny = true          # 默认拒绝策略
allow_return_traffic = true  # 允许回程流量
allow_icmp = true            # 允许 ICMP
persist_rules = true         # 持久化规则
backup_keep = 3              # 配置备份保留数量
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `default_deny` | bool | `true` | 默认拒绝所有未明确允许的流量 |
| `allow_return_traffic` | bool | `true` | 允许已建立连接的回程流量（无状态检查） |
| `allow_icmp` | bool | `true` | 允许 Ping 和其他 ICMP 消息 |
| `persist_rules` | bool | `true` | 关闭时保存规则，启动时重新加载 |
| `backup_keep` | int | `3` | 配置文件备份保留数量（0 = 不备份） |

### 1.2 网络接口 (Network Interfaces)

```toml
interfaces = []              # 网络接口列表
enable_af_xdp = false        # 启用 AF_XDP
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `interfaces` | []string | `[]` | 附加 XDP 程序的网络接口（空 = 所有接口） |
| `enable_af_xdp` | bool | `false` | 使用 AF_XDP socket 进行数据包处理 |

### 1.3 协议安全 (Protocol Security)

```toml
strict_protocol = true       # 严格协议检查
drop_fragments = true        # 丢弃分片
strict_tcp = false           # 严格 TCP 检查
syn_limit = true             # SYN 速率限制
bogon_filter = true          # 伪路由过滤
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `strict_protocol` | bool | `true` | 拒绝具有无效协议头的数据包 |
| `drop_fragments` | bool | `true` | 丢弃 IP 分片（防止分片攻击） |
| `strict_tcp` | bool | `false` | 强制 TCP 头验证 |
| `syn_limit` | bool | `true` | 限制 SYN 数据包（防止 SYN 洪水） |
| `bogon_filter` | bool | `true` | 过滤伪路由 IP 地址 |

### 1.4 ICMP 速率限制 (ICMP Rate Limiting)

```toml
icmp_rate = 10               # ICMP 速率
icmp_burst = 50              # ICMP 突发
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `icmp_rate` | uint64 | `10` | 每个目标每秒最大 ICMP 数据包数 |
| `icmp_burst` | uint64 | `50` | 允许的最大 ICMP 突发数据包数 |

### 1.5 清理与过期 (Cleanup & Expiry)

```toml
enable_expiry = true         # 启用过期
cleanup_interval = "1m"      # 清理间隔
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enable_expiry` | bool | `true` | 基于时间戳自动过期条目 |
| `cleanup_interval` | string | `"1m"` | 清理过期条目的间隔 |

### 1.6 调试 (Debug)

```toml
enable_pprof = false         # 启用 pprof
pprof_port = 6060            # pprof 端口
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enable_pprof` | bool | `false` | 启用 Go 性能分析 HTTP 服务器 |
| `pprof_port` | int | `6060` | pprof HTTP 服务器端口 |

### 1.7 文件路径 (File Paths)

```toml
lock_list_file = "/etc/netxfw/deny_list.txt"
lock_list_binary = "/etc/netxfw/deny_list.bin.zst"
bpf_pin_path = ""
lock_list_merge_threshold = 0
lock_list_v4_mask = 24
lock_list_v6_mask = 64
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `lock_list_file` | string | `/etc/netxfw/deny_list.txt` | 拒绝列表文件路径（文本格式） |
| `lock_list_binary` | string | `/etc/netxfw/deny_list.bin.zst` | 拒绝列表文件路径（压缩二进制） |
| `bpf_pin_path` | string | `""` | BPF Map 固定路径（空 = 默认） |
| `lock_list_merge_threshold` | int | `0` | 触发子网合并的最小条目数 |
| `lock_list_v4_mask` | int | `24` | IPv4 锁定列表聚合的子网掩码（/24 = 256 个 IP） |
| `lock_list_v6_mask` | int | `64` | IPv6 锁定列表聚合的子网掩码（/64 = 标准子网） |

---

## 2. 安全规则 (Security Rules)

### 2.1 白名单 (Whitelist)

```toml
whitelist = [
    # IPv4 Addresses
    "127.0.0.1/32",
    "192.168.1.0/24",
    "10.0.0.0/8",
    # IPv6 Addresses
    "::1/128",
    "fe80::/10",
    "2001:db8::/32",
]
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `whitelist` | []string | `[]` | 允许的 IP 地址或网络（CIDR 格式，支持 IPv4/IPv6） |

### 2.2 端口配置 (Port Configuration)

```toml
[port]
allowed_ports = [22, 80, 443]
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `allowed_ports` | []uint16 | `[]` | 允许传入连接的端口列表 |

### 2.3 IP-端口规则 (IP-Port Rules)

```toml
ip_port_rules = [
    # IPv4 Rules
    { ip = "0.0.0.0/0", port = 22, action = 1 },
    { ip = "0.0.0.0/0", port = 80, action = 1 },
    { ip = "0.0.0.0/0", port = 443, action = 1 },
    # IPv6 Rules
    { ip = "::/0", port = 22, action = 1 },
    { ip = "::/0", port = 80, action = 1 },
    { ip = "::/0", port = 443, action = 1 },
    # Mixed Rules
    { ip = "192.168.1.100", port = 3306, action = 0 },
    { ip = "2001:db8::/32", port = 8080, action = 0 },
]
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `ip` | string | IP 地址或 CIDR（支持 IPv4/IPv6） |
| `port` | uint16 | 端口号 |
| `action` | uint8 | 动作：`0` = 拒绝，`1` = 允许 |

### 2.4 速率限制 (Rate Limit)

```toml
[rate_limit]
enabled = false
auto_block = true
auto_block_expiry = "10m"
rules = [
    { ip = "0.0.0.0/0", rate = 1000, burst = 2000 },
]
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用每客户端速率限制 |
| `auto_block` | bool | `true` | 自动阻止超过速率限制的 IP |
| `auto_block_expiry` | string | `"10m"` | 自动阻止 IP 的持续时间 |
| `rules` | []RateLimitRule | `[]` | 速率限制规则列表 |

**RateLimitRule 结构：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `ip` | string | IP 地址或 CIDR（支持 IPv4/IPv6） |
| `rate` | uint64 | 每秒允许的请求数 |
| `burst` | uint64 | 允许的突发请求数 |

**示例：**

```toml
rules = [
    # IPv4 Rate Limits
    { ip = "10.0.0.0/24", rate = 100, burst = 200 },
    { ip = "192.168.1.0/24", rate = 500, burst = 1000 },
    # IPv6 Rate Limits
    { ip = "2001:db8::/32", rate = 1000, burst = 2000 },
    { ip = "2400:3200::/32", rate = 800, burst = 1600 },
    # Mixed Rate Limits
    { ip = "::/0", port = 80, rate = 50, burst = 100 },
]
```

### 2.5 连接跟踪 (Connection Tracking)

```toml
[conntrack]
enabled = true
max_entries = 10000
tcp_timeout = "1h"
udp_timeout = "5m"
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `true` | 启用 TCP/UDP 连接跟踪 |
| `max_entries` | int | `10000` | 跟踪的最大连接数 |
| `tcp_timeout` | string | `"1h"` | 非活动 TCP 连接超时 |
| `udp_timeout` | string | `"5m"` | 非活动 UDP 流超时 |

---

## 3. XDP 配置 (XDP Configuration)

### 3.1 容量配置 (Capacity)

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

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `lock_list` | int | `20000` | 拒绝列表最大条目数 |
| `dyn_lock_list` | int | `2000` | 动态拒绝列表最大条目数 |
| `whitelist` | int | `30` | 白名单最大条目数 |
| `ip_port_rules` | int | `30` | IP-端口规则最大数 |
| `allowed_ports` | int | `30` | 允许端口最大数 |
| `rate_limits` | int | `1000` | 速率限制最大条目数 |
| `drop_reason_stats` | int | `1000000` | 丢弃原因统计最大数 |
| `pass_reason_stats` | int | `1000000` | 通过原因统计最大数 |

### 3.2 模块配置 (Module Configuration)

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

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | 模块名称 |
| `enabled` | bool | 是否启用 |
| `priority` | int | 执行优先级（数字越小优先级越高） |

**内置模块说明：**

| 模块 | 优先级 | 说明 |
|------|--------|------|
| `sanity` | 1 | 数据包完整性检查 |
| `critical_blacklist` | 2 | 关键黑名单检查 |
| `whitelist` | 3 | 白名单检查 |
| `blacklist` | 4 | 黑名单检查 |
| `dynamic_blacklist` | 5 | 动态黑名单检查 |
| `ratelimit` | 6 | 速率限制 |
| `conntrack` | 7 | 连接跟踪 |
| `ip_port_rules` | 8 | IP-端口规则 |
| `icmp` | 9 | ICMP 处理 |
| `return_traffic` | 10 | 回程流量处理 |

### 3.3 BPF 插件 (BPF Plugin)

```toml
[bpf_plugin]
enabled = false
plugins = []
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用外部 BPF 程序加载 |
| `plugins` | []PluginConfig | `[]` | BPF 插件配置列表 |

---

## 4. 服务 (Services)

### 4.1 Web API 服务器 (Web API Server)

```toml
[web]
enabled = false
port = 11811
token = ""
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用 HTTP API 服务器 |
| `port` | int | `11811` | HTTP API 服务器端口 |
| `token` | string | `""` | API 认证的 Bearer 令牌 |

### 4.2 监控指标 (Metrics)

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

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用指标收集 |
| `server_enabled` | bool | `false` | 启动 HTTP 指标端点 |
| `port` | int | `11812` | 指标服务器端口 |
| `push_enabled` | bool | `false` | 推送指标到 Pushgateway |
| `push_gateway_addr` | string | `""` | Prometheus Pushgateway URL |
| `push_interval` | string | `"15s"` | 推送指标间隔 |
| `textfile_enabled` | bool | `false` | 从文本文件读取指标 |
| `textfile_path` | string | `""` | 文本文件目录 |
| `top_n` | int | `10` | Top IP 统计数量 |
| `threshold_critical` | int | `90` | 严重警报阈值 |
| `threshold_high` | int | `75` | 高警报阈值 |
| `threshold_medium` | int | `50` | 中警报阈值 |
| `stats_interval` | string | `"1s"` | 统计更新间隔 |
| `avg_packet_size` | int | `500` | 平均数据包大小估算 |

---

## 5. 日志 (Logging)

### 5.1 日志引擎 (Log Engine)

```toml
[log_engine]
enabled = false
workers = 4
rules = []
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用结构化日志 |
| `workers` | int | `4` | 日志处理工作线程数 |
| `rules` | []LogEngineRule | `[]` | 日志过滤和处理规则 |

### 5.2 应用日志 (Application Logging)

```toml
[logging]
enabled = false
path = "/var/log/netxfw/agent.log"
max_size = 10
max_backups = 3
max_age = 30
compress = true
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用基于文件的日志 |
| `path` | string | `/var/log/netxfw/agent.log` | 日志文件路径 |
| `max_size` | int | `10` | 轮转前的最大日志文件大小（MB） |
| `max_backups` | int | `3` | 保留的备份文件数 |
| `max_age` | int | `30` | 保留备份文件的最大天数 |
| `compress` | bool | `true` | 压缩轮转的日志文件 |

---

## 6. 高级配置 (Advanced)

### 6.1 集群 (Cluster)

```toml
[cluster]
enabled = false
configpath = "cluster.toml"
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用集群模式 |
| `configpath` | string | `"cluster.toml"` | 集群配置文件路径 |

### 6.2 云环境 (Cloud Environment)

```toml
[cloud]
enabled = false
provider = "other"

[cloud.proxy_protocol]
enabled = false
trusted_lb_ranges = []
cache_ttl = "5m"
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用云环境功能 |
| `provider` | string | `"other"` | 云提供商（alibaba/aws/huawei/tencent/other） |

**Proxy Protocol 配置：**

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 解析 PROXY 协议头 |
| `trusted_lb_ranges` | []string | `[]` | 可信负载均衡器 IP 范围（支持 IPv4/IPv6） |
| `cache_ttl` | string | `"5m"` | 真实 IP 缓存持续时间 |

**示例：**

```toml
trusted_lb_ranges = [
    # IPv4 LB Ranges
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    # IPv6 LB Ranges
    "fc00::/7",
    "2001:db8::/32",
]
```

### 6.3 AI 助手 (AI Assistant)（实验性）

> **注意**：此功能目前处于实验阶段，配置项已预留但尚未完整实现。

```toml
[ai]
enabled = false
port = 11813
api_key = ""
model = ""
base_url = ""
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用 AI 助手功能 |
| `port` | int | `11813` | AI 助手 HTTP 服务器端口 |
| `api_key` | string | `""` | AI 服务的 API 密钥 |
| `model` | string | `""` | 使用的 AI 模型 |
| `base_url` | string | `""` | AI 服务基础 URL |

### 6.4 MCP 服务器 (MCP Server)（实验性）

> **注意**：此功能目前处于实验阶段，配置项已预留但尚未完整实现。

```toml
[mcp]
enabled = false
port = 11814
mode = "sse"
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | bool | `false` | 启用 MCP 服务器 |
| `port` | int | `11814` | MCP 服务器端口 |
| `mode` | string | `"sse"` | 通信模式（stdio/sse） |

---

## 配置文件备份

当 `backup_keep > 0` 时，修改配置文件会自动创建备份：

```
/etc/netxfw/config.toml                    # 当前配置
/etc/netxfw/config.toml.bak.20240101-120000  # 备份文件
```

### 备份相关命令

```bash
# 列出所有备份
ls -la /etc/netxfw/*.bak.*

# 恢复备份
cp /etc/netxfw/config.toml.bak.20240101-120000 /etc/netxfw/config.toml
```

---

## 配置验证

```bash
# 验证配置文件语法
netxfw test --config /etc/netxfw/config.toml

# 查看当前配置
cat /etc/netxfw/config.toml
```

---

## 完整配置示例

```toml
# NetXFW Configuration File

# ============================================================================
# 1. Core Configuration / 核心配置
# ============================================================================
[base]
default_deny = true
allow_return_traffic = true
allow_icmp = true
persist_rules = true
backup_keep = 3

interfaces = []
enable_af_xdp = false

strict_protocol = true
drop_fragments = true
strict_tcp = false
syn_limit = true
bogon_filter = true

icmp_rate = 10
icmp_burst = 50

enable_expiry = true
cleanup_interval = "1m"

enable_pprof = false
pprof_port = 6060

lock_list_file = "/etc/netxfw/deny_list.txt"
lock_list_binary = "/etc/netxfw/deny_list.bin.zst"
bpf_pin_path = ""
lock_list_merge_threshold = 0
lock_list_v4_mask = 24
lock_list_v6_mask = 64

# ============================================================================
# 2. Security Rules / 安全规则
# ============================================================================
whitelist = ["192.168.1.0/24"]

[port]
allowed_ports = [22, 80, 443]

ip_port_rules = [
    { ip = "0.0.0.0", port = 22, action = 1 },
]

[rate_limit]
enabled = false
auto_block = true
auto_block_expiry = "10m"
rules = []

[conntrack]
enabled = true
max_entries = 10000
tcp_timeout = "1h"
udp_timeout = "5m"

# ============================================================================
# 3. XDP Configuration / XDP 配置
# ============================================================================
[capacity]
lock_list = 20000
dyn_lock_list = 2000
whitelist = 30
ip_port_rules = 30
allowed_ports = 30
rate_limits = 1000
drop_reason_stats = 1000000
pass_reason_stats = 1000000

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

[bpf_plugin]
enabled = false
plugins = []

# ============================================================================
# 4. Services / 服务
# ============================================================================
[web]
enabled = true
port = 11811
token = "your-secret-token"

[metrics]
enabled = true
server_enabled = true
port = 11812

# ============================================================================
# 5. Logging / 日志
# ============================================================================
[log_engine]
enabled = false
workers = 4
rules = []

[logging]
enabled = true
path = "/var/log/netxfw/agent.log"
max_size = 10
max_backups = 3
max_age = 30
compress = true

# ============================================================================
# 6. Advanced / 高级配置
# ============================================================================
[cluster]
enabled = false
configpath = "cluster.toml"

[cloud]
enabled = false
provider = "other"

[cloud.proxy_protocol]
enabled = false
trusted_lb_ranges = []
cache_ttl = "5m"

[ai]
enabled = false
port = 11813
api_key = ""
model = ""
base_url = ""

[mcp]
enabled = false
port = 11814
mode = "sse"
```
