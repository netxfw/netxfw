package types

// DefaultConfigTOMLTemplate defines the default configuration file structure in TOML format.
// DefaultConfigTOMLTemplate 定义 TOML 格式的默认配置文件结构。
// TOML format is preferred for better cross-language support.
// TOML 格式优先，以获得更好的跨语言支持。
const DefaultConfigTOMLTemplate = `# NetXFW Configuration File / NetXFW 配置文件
# TOML format - Better cross-language support / TOML 格式 - 更好的跨语言支持
#

# ============================================================================
# 1. Core Configuration / 核心配置
# ============================================================================

# ----------------------------------------------------------------------------
# 1.1 Base Configuration / 基础配置
# ----------------------------------------------------------------------------
# Core firewall behavior settings / 核心防火墙行为设置
[base]
# Default Deny Policy: If true, all traffic not explicitly allowed is dropped.
# 默认拒绝策略：如果为 true，所有未显式允许的流量将被丢弃。
default_deny = true
# Allow Return Traffic: Stateless check (ACK + Port range) for established connections.
# 允许回程流量：无状态检查（ACK + 端口范围）用于已建立的连接。
allow_return_traffic = true
# Allow ICMP: Allow Ping and other ICMP messages.
# 允许 ICMP：允许 Ping 和其他 ICMP 消息。
allow_icmp = true
# Persist Rules: Save rules to disk on shutdown, reload on startup.
# 持久化规则：关闭时保存规则到磁盘，启动时重新加载。
persist_rules = true
# Backup Keep: Number of config backup files to keep (0 = no backup).
# 备份保留：保留的配置备份文件数量（0 = 不备份）。
backup_keep = 3

# ----------------------------------------------------------------------------
# 1.2 Network Interfaces / 网络接口
# ----------------------------------------------------------------------------
# Interfaces: List of network interfaces to attach XDP program (empty = all).
# 接口：附加 XDP 程序的网络接口列表（空 = 所有接口）。
interfaces = []
# Enable AF_XDP: Use AF_XDP socket for packet processing (requires kernel support).
# 启用 AF_XDP：使用 AF_XDP socket 进行数据包处理（需要内核支持）。
enable_af_xdp = false

# ----------------------------------------------------------------------------
# 1.3 Protocol Security / 协议安全
# ----------------------------------------------------------------------------
# Strict Protocol Check: Reject packets with invalid protocol headers.
# 严格协议检查：拒绝具有无效协议头的数据包。
strict_protocol = true
# Drop Fragments: Drop IP fragments (prevents fragmentation attacks).
# 丢弃分片：丢弃 IP 分片（防止分片攻击）。
drop_fragments = true
# Strict TCP Check: Enforce TCP header validation.
# 严格 TCP 检查：强制 TCP 头验证。
strict_tcp = false
# SYN Rate Limit: Limit SYN packets to prevent SYN flood attacks.
# SYN 速率限制：限制 SYN 数据包以防止 SYN 洪水攻击。
syn_limit = true
# Bogon Filter: Filter bogon/martian IP addresses (reserved/private ranges).
# 伪路由过滤：过滤伪路由 IP 地址（保留/私有范围）。
bogon_filter = true

# ----------------------------------------------------------------------------
# 1.4 ICMP Rate Limiting / ICMP 速率限制
# ----------------------------------------------------------------------------
# ICMP Rate: Maximum ICMP packets per second per destination.
# ICMP 速率：每个目标每秒最大 ICMP 数据包数。
icmp_rate = 10
# ICMP Burst: Maximum ICMP packets allowed in a burst.
# ICMP 突发：允许的最大 ICMP 突发数据包数。
icmp_burst = 50

# ----------------------------------------------------------------------------
# 1.5 Cleanup & Expiry / 清理与过期
# ----------------------------------------------------------------------------
# Enable Expiry: Automatically expire entries based on timestamp.
# 启用过期：基于时间戳自动过期条目。
enable_expiry = true
# Cleanup Interval: Interval for cleaning up expired entries.
# 清理间隔：清理过期条目的间隔。
cleanup_interval = "1m"

# ----------------------------------------------------------------------------
# 1.6 Debug / 调试
# ----------------------------------------------------------------------------
# Enable pprof: Enable Go profiling HTTP server.
# 启用 pprof：启用 Go 性能分析 HTTP 服务器。
enable_pprof = false
# pprof Port: Port for pprof HTTP server.
# pprof 端口：pprof HTTP 服务器端口。
pprof_port = 6060

# ----------------------------------------------------------------------------
# 1.7 File Paths / 文件路径
# ----------------------------------------------------------------------------
# Lock List File: Path to deny list file (text format).
# 锁定列表文件：拒绝列表文件路径（文本格式）。
lock_list_file = "/etc/netxfw/deny_list.txt"
# Lock List Binary: Path to deny list file (compressed binary format).
# 锁定列表二进制：拒绝列表文件路径（压缩二进制格式）。
lock_list_binary = "/etc/netxfw/deny_list.bin.zst"
# BPF Pin Path: Path to pin BPF maps (override default).
# BPF 固定路径：固定 BPF Map 的路径（覆盖默认值）。
bpf_pin_path = ""
# Lock List Merge Threshold: Minimum entries to trigger subnet merging.
# 锁定列表合并阈值：触发子网合并的最小条目数。
lock_list_merge_threshold = 0
# IPv4 Mask: Subnet mask for IPv4 lock list aggregation.
# IPv4 掩码：IPv4 锁定列表聚合的子网掩码。
lock_list_v4_mask = 24
# IPv6 Mask: Subnet mask for IPv6 lock list aggregation.
# IPv6 掩码：IPv6 锁定列表聚合的子网掩码。
lock_list_v6_mask = 64

# ============================================================================
# 2. Security Rules / 安全规则
# ============================================================================

# ----------------------------------------------------------------------------
# 2.1 Whitelist / 白名单
# ----------------------------------------------------------------------------
# Allowed IP addresses or networks / 允许的 IP 地址或网络
whitelist = []

# ----------------------------------------------------------------------------
# 2.2 Port Configuration / 端口配置
# ----------------------------------------------------------------------------
[port]
# Allowed Ports: List of ports allowed for incoming connections.
# 允许端口：允许传入连接的端口列表。
allowed_ports = []

# ----------------------------------------------------------------------------
# 2.3 IP-Port Rules / IP-端口规则
# ----------------------------------------------------------------------------
# Specific IP+Port based filtering rules / 基于特定 IP+端口的过滤规则
# action: 0 = Deny / 拒绝, 1 = Allow / 允许
ip_port_rules = [
    { ip = "0.0.0.0", port = 22, action = 1 },
]

# ----------------------------------------------------------------------------
# 2.4 Rate Limit / 速率限制
# ----------------------------------------------------------------------------
[rate_limit]
# Enable Rate Limit: Enable per-client rate limiting.
# 启用速率限制：启用每客户端速率限制。
enabled = false
# Auto Block: Automatically block IPs exceeding rate limits.
# 自动阻止：自动阻止超过速率限制的 IP。
auto_block = true
# Auto Block Expiry: Duration for auto-blocked IPs.
# 自动阻止过期：自动阻止 IP 的持续时间。
auto_block_expiry = "10m"
# Rate Limit Rules: Rate limit rules configuration.
# 速率限制规则：速率限制规则配置。
rules = []

# ----------------------------------------------------------------------------
# 2.5 Connection Tracking / 连接跟踪
# ----------------------------------------------------------------------------
[conntrack]
# Enable Conntrack: Track TCP/UDP connections.
# 启用连接跟踪：跟踪 TCP/UDP 连接。
enabled = true
# Max Entries: Maximum number of tracked connections.
# 最大条目：跟踪的最大连接数。
max_entries = 10000
# TCP Timeout: Inactive TCP connection timeout.
# TCP 超时：非活动 TCP 连接超时。
tcp_timeout = "1h"
# UDP Timeout: Inactive UDP flow timeout.
# UDP 超时：非活动 UDP 流超时。
udp_timeout = "5m"

# ============================================================================
# 3. XDP Configuration / XDP 配置
# ============================================================================

# ----------------------------------------------------------------------------
# 3.1 Capacity / 容量配置
# ----------------------------------------------------------------------------
# BPF map capacity settings / BPF map 容量设置
[capacity]
# Lock List Capacity: Maximum entries in deny list.
# 锁定列表容量：拒绝列表中的最大条目数。
lock_list = 20000
# Dynamic Lock List Capacity: Maximum entries in dynamic deny list.
# 动态锁定列表容量：动态拒绝列表中的最大条目数。
dyn_lock_list = 2000
# Whitelist Capacity: Maximum entries in whitelist.
# 白名单容量：白名单中的最大条目数。
whitelist = 30
# IP-Port Rules Capacity: Maximum IP-port rules.
# IP-端口规则容量：最大 IP-端口规则数。
ip_port_rules = 30
# Allowed Ports Capacity: Maximum allowed ports.
# 允许端口容量：最大允许端口数。
allowed_ports = 30
# Rate Limits Capacity: Maximum rate limit entries.
# 速率限制容量：最大速率限制条目数。
rate_limits = 1000
# Drop Reason Stats Capacity: Maximum drop reason statistics.
# 丢弃原因统计容量：最大丢弃原因统计数。
drop_reason_stats = 1000000
# Pass Reason Stats Capacity: Maximum pass reason statistics.
# 通过原因统计容量：最大通过原因统计数。
pass_reason_stats = 1000000

# ----------------------------------------------------------------------------
# 3.2 Module Configuration / 模块配置
# ----------------------------------------------------------------------------
# Order of execution for XDP modules / XDP 模块的执行顺序
# Priority determines execution order (lower number = higher priority)
# 优先级决定执行顺序（数字越小优先级越高）
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

# ----------------------------------------------------------------------------
# 3.3 BPF Plugin / BPF 插件
# ----------------------------------------------------------------------------
[bpf_plugin]
# Enable BPF Plugins: Load external BPF programs.
# 启用 BPF 插件：加载外部 BPF 程序。
enabled = false
# Plugin List: List of BPF plugin configurations.
# 插件列表：BPF 插件配置列表。
plugins = []

# ============================================================================
# 4. Services / 服务
# ============================================================================

# ----------------------------------------------------------------------------
# 4.1 Web API Server / Web API 服务器
# ----------------------------------------------------------------------------
[web]
# Enable Web Server: Start HTTP API server.
# 启用 Web 服务器：启动 HTTP API 服务器。
enabled = false
# Web Port: HTTP API server port.
# Web 端口：HTTP API 服务器端口。
port = 11811
# Authentication Token: Bearer token for API authentication.
# 认证令牌：API 认证的 Bearer 令牌。
token = ""

# ----------------------------------------------------------------------------
# 4.2 Metrics / 监控指标
# ----------------------------------------------------------------------------
[metrics]
# Enable Metrics: Enable metrics collection.
# 启用指标：启用指标收集。
enabled = false
# Enable Metrics Server: Start HTTP metrics endpoint.
# 启用指标服务器：启动 HTTP 指标端点。
server_enabled = false
# Metrics Port: HTTP metrics server port.
# 指标端口：HTTP 指标服务器端口。
port = 11812
# Enable Push Mode: Push metrics to Prometheus Pushgateway.
# 启用推送模式：将指标推送到 Prometheus Pushgateway。
push_enabled = false
# Push Gateway Address: Prometheus Pushgateway URL.
# Push 网关地址：Prometheus Pushgateway URL。
push_gateway_addr = ""
# Push Interval: Interval for pushing metrics.
# 推送间隔：推送指标的间隔。
push_interval = "15s"
# Enable Textfile Mode: Read metrics from text files.
# 启用文本文件模式：从文本文件读取指标。
textfile_enabled = false
# Textfile Directory: Directory to read metrics from.
# 文本文件目录：读取指标的目录。
textfile_path = ""
# Top N: Number of top IPs to track in statistics.
# Top N：在统计中跟踪的 Top IP 数量。
top_n = 10
# Critical Threshold: CPU/Memory usage threshold for critical alerts.
# 严重阈值：严重警报的 CPU/内存使用阈值。
threshold_critical = 90
# High Threshold: CPU/Memory usage threshold for high alerts.
# 高阈值：高警报的 CPU/内存使用阈值。
threshold_high = 75
# Medium Threshold: CPU/Memory usage threshold for medium alerts.
# 中阈值：中警报的 CPU/内存使用阈值。
threshold_medium = 50
# Stats Interval: Interval for updating statistics.
# 统计间隔：更新统计的间隔。
stats_interval = "1s"
# Average Packet Size: Estimated average packet size for calculations.
# 平均数据包大小：估算的平均数据包大小用于计算。
avg_packet_size = 500

# ============================================================================
# 5. Logging / 日志
# ============================================================================

# ----------------------------------------------------------------------------
# 5.1 Log Engine / 日志引擎
# ----------------------------------------------------------------------------
[log_engine]
# Enable Log Engine: Enable structured logging.
# 启用日志引擎：启用结构化日志。
enabled = false
# Workers: Number of log processing workers.
# 工作线程：日志处理工作线程数。
workers = 4
# Log Rules: Log filtering and processing rules.
# 日志规则：日志过滤和处理规则。
rules = []

# ----------------------------------------------------------------------------
# 5.2 Application Logging / 应用日志
# ----------------------------------------------------------------------------
[logging]
# Enable Logging: Enable file-based logging.
# 启用日志：启用基于文件的日志。
enabled = false
# Log Path: Path to log file.
# 日志路径：日志文件路径。
path = "/var/log/netxfw/agent.log"
# Max Size: Maximum log file size (MB) before rotation.
# 最大大小：轮转前的最大日志文件大小（MB）。
max_size = 10
# Max Backups: Number of backup files to keep.
# 最大备份：要保留的备份文件数。
max_backups = 3
# Max Age: Maximum days to keep backup files.
# 最大天数：保留备份文件的最大天数。
max_age = 30
# Compress: Compress rotated log files.
# 压缩：压缩轮转的日志文件。
compress = true

# ============================================================================
# 6. Advanced / 高级配置
# ============================================================================

# ----------------------------------------------------------------------------
# 6.1 Cluster / 集群
# ----------------------------------------------------------------------------
# Multi-node cluster support / 多节点集群支持
[cluster]
# Enable cluster mode / 启用集群模式
enabled = false
# Cluster configuration file path / 集群配置文件路径
configpath = "cluster.toml"

# ----------------------------------------------------------------------------
# 6.2 Cloud Environment / 云环境
# ----------------------------------------------------------------------------
[cloud]
# Enable Cloud Config: Enable cloud environment features.
# 启用云配置：启用云环境功能。
enabled = false
# Cloud Provider: Cloud provider name (alibaba/aws/huawei/tencent/other).
# 云提供商：云提供商名称（alibaba/aws/huawei/tencent/other）。
provider = "other"

# Proxy Protocol Configuration / Proxy Protocol 配置
[cloud.proxy_protocol]
# Enable Proxy Protocol: Parse PROXY protocol header.
# 启用 Proxy Protocol：解析 PROXY 协议头。
enabled = false
# Trusted LB Ranges: Trusted load balancer IP ranges.
# 信任的 LB 范围：可信负载均衡器 IP 范围。
trusted_lb_ranges = []
# Cache TTL: Cache duration for resolved real IPs.
# 缓存 TTL：解析的真实 IP 缓存持续时间。
cache_ttl = "5m"

# ----------------------------------------------------------------------------
# 6.3 AI Assistant / AI 助手
# ----------------------------------------------------------------------------
[ai]
# Enable AI: Enable AI assistant features.
# 启用 AI：启用 AI 助手功能。
enabled = false
# AI Port: HTTP server port for AI assistant.
# AI 端口：AI 助手 HTTP 服务器端口。
port = 11813
# API Key: API key for AI service.
# API 密钥：AI 服务的 API 密钥。
api_key = ""
# Model: AI model to use.
# 模型：使用的 AI 模型。
model = ""
# Base URL: AI service base URL.
# 基础 URL：AI 服务基础 URL。
base_url = ""

# ----------------------------------------------------------------------------
# 6.4 MCP Server / MCP 服务器
# ----------------------------------------------------------------------------
[mcp]
# Enable MCP: Enable MCP server.
# 启用 MCP：启用 MCP 服务器。
enabled = false
# MCP Port: MCP server port.
# MCP 端口：MCP 服务器端口。
port = 11814
# MCP Mode: Communication mode (stdio/sse).
# MCP 模式：通信模式（stdio/sse）。
mode = "sse"

`
