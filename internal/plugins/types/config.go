package types

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/livp123/netxfw/internal/utils/fileutil"
	"gopkg.in/yaml.v3"
)

// ConfigMu protects concurrent access to the configuration file.
// ConfigMu 保护对配置文件的并发访问。
var ConfigMu sync.RWMutex

// DefaultConfigTemplate defines the default configuration file structure with bilingual comments.
// This template is used to initialize new config files and to repair missing sections in existing files
// while preserving documentation.
const DefaultConfigTemplate = `# NetXFW Configuration File / NetXFW 配置文件
#

# Cluster Configuration / 集群配置
# Default cluster config file path / 默认集群配置文件路径
cluster:
  enabled: false
  configpath: "cluster.yaml"

# Base Configuration / 基础配置
base:
  # Default Deny Policy: If true, all traffic not explicitly allowed is dropped.
  # 默认拒绝策略：如果为 true，所有未显式允许的流量将被丢弃。
  default_deny: true

  # Allow Return Traffic: Stateless check (ACK + Port range).
  # 允许回程流量：无状态检查（ACK + 端口范围）。
  allow_return_traffic: true

  # Allow ICMP: Allow Ping and other ICMP messages.
  # 允许 ICMP：允许 Ping 和其他 ICMP 消息。
  allow_icmp: true

  # Interfaces: Network interfaces to attach XDP to.
  # If empty, all physical interfaces will be auto-detected.
  # 接口：要挂载 XDP 的网络接口。
  # 如果为空，将自动检测所有物理接口。
  interfaces: []

  # Enable AF_XDP: Enable high-performance packet redirection to userspace.
  # 启用 AF_XDP：启用高性能数据包重定向到用户空间。
  enable_af_xdp: false

  # BPF Pin Path: Path to pin BPF maps. Defaults to /sys/fs/bpf/netxfw if empty.
  # BPF 固定路径：固定 BPF Map 的路径。如果为空，默认为 /sys/fs/bpf/netxfw。
  bpf_pin_path: ""

  # Strict Protocol Validation: Drop malformed packets.
  # 严格协议验证：丢弃畸形数据包。
  strict_protocol: false

  # Drop IP Fragments: Prevent fragmentation attacks.
  # 丢弃 IP 分片：防止分片攻击。
  drop_fragments: false

  # Strict TCP Validation: Check TCP flags and sequence numbers.
  # 严格 TCP 验证：检查 TCP 标志和序列号。
  strict_tcp: false

  # SYN Rate Limit: Limit SYN packets to prevent flood attacks.
  # SYN 速率限制：限制 SYN 数据包以防止泛洪攻击。
  syn_limit: false

  # Bogon Filter: Drop packets from reserved/private IP ranges on public interfaces.
  # Bogon 过滤：丢弃来自保留/私有 IP 范围的数据包。
  bogon_filter: false

  # ICMP Rate Limit (pps) / ICMP 速率限制 (每秒包数)
  icmp_rate: 10

  # ICMP Burst Size / ICMP 突发大小
  icmp_burst: 50

  # Whitelist: Global allowed IPs/CIDRs.
  # 白名单：全局允许的 IP/CIDR。
  whitelist: []

  # Lock List File: Persistence file for blocked IPs.
  # 锁定列表文件：被封禁 IP 的持久化文件。
  lock_list_file: "/etc/netxfw/lock_list.txt"

  # Lock List Binary: Binary format for fast loading (optional).
  # 锁定列表二进制文件：用于快速加载的二进制格式（可选）。
  lock_list_binary: ""

  # Lock List Merge Threshold: If > 0, merge IPs into subnets if count >= threshold.
  # 锁定列表合并阈值：如果 > 0，当数量 >= 阈值时将 IP 合并为子网。
  lock_list_merge_threshold: 0

  # Lock List IPv4 Mask: Target mask for IPv4 merging (default 24).
  # 锁定列表 IPv4 掩码：IPv4 合并的目标掩码（默认 24）。
  lock_list_v4_mask: 24

  # Lock List IPv6 Mask: Target mask for IPv6 merging (default 64).
  # 锁定列表 IPv6 掩码：IPv6 合并的目标掩码（默认 64）。
  lock_list_v6_mask: 64

  # Enable Expiry: Automatically clean up old rules.
  # 启用过期：自动清理旧规则。
  enable_expiry: true

  # Cleanup Interval: How often to run cleanup (e.g., "1m", "1h").
  # 清理间隔：多久运行一次清理（例如 "1m", "1h"）。
  cleanup_interval: "1m"

  # Persist Rules: Save runtime rule changes to disk.
  # 持久化规则：将运行时规则更改保存到磁盘。
  persist_rules: true

  # Enable Pprof: Enable Go performance profiling.
  # 启用 Pprof：启用 Go 性能分析。
  enable_pprof: false

  # Pprof Port: Port for pprof server (localhost only).
  # Pprof 端口：pprof 服务器端口（仅限本地主机）。
  pprof_port: 6060

# Web Server Configuration / Web 服务器配置
web:
  enabled: false
  port: 11811
  token: ""

# Metrics Configuration / 监控指标配置
# When metrics.enabled = false, metrics are served via web server at /metrics path
# 当 metrics.enabled = false 时，指标通过 web 服务器的 /metrics 路径提供
metrics:
  enabled: false
  server_enabled: false
  port: 11812
  push_enabled: false
  push_gateway_addr: ""
  push_interval: "15s"
  textfile_enabled: false
  textfile_path: ""


# Port Configuration / 端口配置
port:
  # Allowed Ports: List of allowed destination ports (TCP/UDP).
  # 允许端口：允许的目标端口列表 (TCP/UDP)。
  allowed_ports: []
  
  # IP-Port Rules: Specific rules for IP+Port combinations.
  # IP-端口规则：针对 IP+端口组合的特定规则。
  ip_port_rules: []
  # Example / 示例:
  # - ip: "192.168.1.100"
  #   port: 80
  #   action: 1  # 1: Allow, 2: Deny

# Conntrack Configuration / 连接跟踪配置
conntrack:
  enabled: true
  max_entries: 100000
  tcp_timeout: "1h"
  udp_timeout: "5m"

# Rate Limit Configuration / 速率限制配置
rate_limit:
  enabled: true
  auto_block: true
  # Auto Block Expiry: Duration to block IPs that exceed limits.
  # 自动封禁过期时间：超过限制的 IP 的封禁持续时间。
  auto_block_expiry: "10m"
  rules: []
  # Example / 示例:
  # - ip: "10.0.0.0/24"
  #   rate: 1000
  #   burst: 2000

# Log Engine Configuration / 日志引擎配置
log_engine:
  enabled: false
  workers: 4
  
  rules: []
  # Example 1: SSH Brute Force Protection / 示例 1：SSH 防爆破
  # - id: "ssh_brute_force"
  #   path: "/var/log/auth.log"
  #   tail_position: "end" # "start", "end", "offset" (default: end)
  #   # Expression Syntax / 表达式语法:
  #   # log("pattern")  -> Case-insensitive match / 不区分大小写匹配
  #   # logE("pattern") -> Case-sensitive match (Exact) / 区分大小写匹配 (精确)
  #   # time(seconds)   -> Count occurrences in last N seconds / 过去 N 秒内的计数
  #   expression: 'log("Failed password") && log("root") && time(60) > 5'
  #   action: "block"   # Actions: 0="log", 1="block" (dynamic), 2="static" (permanent)
  #   ttl: "10m"        # Block duration / 封禁时长

  # Example 2: Nginx 404 Flood / 示例 2：Nginx 404 洪水攻击
  # - id: "nginx_404_flood"
  #   path: "/var/log/nginx/access.log"
  #   expression: 'log(" 404 ") && time(10) > 20'
  #   action: "block"
  #   ttl: "1h"

# Capacity Configuration / 容量配置
# Adjust these based on your system memory and requirements.
# 根据您的系统内存和需求进行调整。
capacity:
  lock_list: 2000000
  dyn_lock_list: 2000000
  whitelist: 65536
  ip_port_rules: 65536
  allowed_ports: 1024

# Logging Configuration / 日志配置
logging:
  enabled: false
  # Log file path / 日志文件路径
  path: "/var/log/netxfw/agent.log"
  # Max size in MB before rotation / 轮转前的最大大小 (MB)
  max_size: 10
  # Max number of old files to keep / 保留的旧文件最大数量
  max_backups: 3
  # Max number of days to keep old files / 保留旧文件的最大天数
  max_age: 30
  # Whether to compress old files / 是否压缩旧文件
  compress: true
`

// GlobalConfig represents the top-level configuration structure.
// GlobalConfig 表示顶级配置结构。
type GlobalConfig struct {
	Cluster   ClusterConfig   `yaml:"cluster"`
	Base      BaseConfig      `yaml:"base"`
	Web       WebConfig       `yaml:"web"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Port      PortConfig      `yaml:"port"`
	Conntrack ConntrackConfig `yaml:"conntrack"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	LogEngine LogEngineConfig `yaml:"log_engine"`
	Capacity  CapacityConfig  `yaml:"capacity"`
	Logging   LoggingConfig   `yaml:"logging"`
	AI        AIConfig        `yaml:"ai"`
	MCP       MCPConfig       `yaml:"mcp"`
}

// LoggingConfig defines the configuration for logging.
// LoggingConfig 定义日志配置。
type LoggingConfig struct {
	Enabled bool   `yaml:"enabled"`
	Level   string `yaml:"level"` // Log level (debug, info, warn, error)
	// Level: 日志级别（debug, info, warn, error）
	Path string `yaml:"path"` // Log file path
	// Path: 日志文件路径
	MaxSize int `yaml:"max_size"` // Max size in MB before rotation
	// MaxSize: 轮转前的最大大小（MB）
	MaxBackups int `yaml:"max_backups"` // Max number of old files to keep
	// MaxBackups: 保留的旧文件最大数量
	MaxAge int `yaml:"max_age"` // Max number of days to keep old files
	// MaxAge: 保留旧文件的最大天数
	Compress bool `yaml:"compress"` // Whether to compress old files
	// Compress: 是否压缩旧文件
}

// LogEngineConfig defines the configuration for the log engine.
// LogEngineConfig 定义日志引擎配置。
type LogEngineConfig struct {
	Enabled   bool `yaml:"enabled"`
	Workers   int  `yaml:"workers"`
	MaxWindow int  `yaml:"max_window"` // Max history window in seconds (default 3600)
	// MaxWindow: 最大历史窗口（秒，默认 3600）
	Rules []LogEngineRule `yaml:"rules"`
}

// LogEngineRule defines a rule for the log engine.
// LogEngineRule 定义日志引擎规则。
type LogEngineRule struct {
	ID   string `yaml:"id"`
	Path string `yaml:"path"` // Optional: File path pattern (glob or substring)
	// Path: 可选：文件路径模式（glob 或子字符串）

	// Tail Position: "start", "end" (default), "offset"
	// 读取位置："start" (从头开始), "end" (从末尾开始), "offset" (从上次记录位置开始)
	TailPosition string `yaml:"tail_position"`

	Expression string `yaml:"expression"`
	Action     string `yaml:"action"` // "block", "log"
	// Action: 执行动作 ("block", "log")

	// Simplified Configuration (alternative to Expression)
	// 简化配置（Expression 的替代方案）
	Keywords []string `yaml:"keywords"` // Deprecated: Use Contains instead (AND logic)
	// Keywords: 已弃用：请改用 Contains (AND 逻辑)
	Contains []string `yaml:"contains"` // AND logic: Must contain ALL of these (supports * wildcard)
	// Contains: AND 逻辑：必须包含所有这些（支持 * 通配符）
	AnyContains []string `yaml:"any_contains"` // OR logic: Must contain AT LEAST ONE of these (supports * wildcard)
	// AnyContains: OR 逻辑：必须包含其中至少一个（支持 * 通配符）
	NotContains []string `yaml:"not_contains"` // NOT logic: Must NOT contain ANY of these (supports * wildcard)
	// NotContains: NOT 逻辑：不能包含其中任何一个（支持 * 通配符）

	// Aliases for better UX (User preference)
	// 为了更好的用户体验提供的别名
	And []string `yaml:"and"` // Alias for Contains (AND logic)
	// And: Contains 的别名 (AND 逻辑)
	Is []string `yaml:"is"` // Alias for Contains (AND logic)
	// Is: Contains 的别名 (AND 逻辑)
	Or []string `yaml:"or"` // Alias for AnyContains (OR logic)
	// Or: AnyContains 的别名 (OR 逻辑)
	Not []string `yaml:"not"` // Alias for NotContains (NOT logic)
	// Not: NotContains 的别名 (NOT 逻辑)

	Regex string `yaml:"regex"` // Regular expression to match
	// Regex: 正则表达式匹配
	Threshold int `yaml:"threshold"` // Trigger count
	// Threshold: 触发阈值
	Interval int `yaml:"interval"` // Time window in seconds (default 60)
	// Interval: 时间窗口（秒，默认 60）
	TTL string `yaml:"ttl"` // Block duration (e.g., "10m", "1h"). Empty or "0" means permanent/static or LRU auto-evict.
	// TTL: 封禁持续时间（例如 "10m", "1h"）。为空或 "0" 表示永久或 LRU 自动驱逐。
}

// RateLimitConfig defines the configuration for rate limiting.
// RateLimitConfig 定义速率限制配置。
type RateLimitConfig struct {
	Enabled         bool   `yaml:"enabled"`
	AutoBlock       bool   `yaml:"auto_block"`
	AutoBlockExpiry string `yaml:"auto_block_expiry"` // e.g., "5m", "1h"
	// AutoBlockExpiry: 自动封禁过期时间（例如 "5m", "1h"）
	Rules []RateLimitRule `yaml:"rules"`
}

// RateLimitRule defines a rate limit rule for a specific IP/CIDR.
// RateLimitRule 定义特定 IP/CIDR 的速率限制规则。
type RateLimitRule struct {
	IP    string `yaml:"ip"`
	Rate  uint64 `yaml:"rate"`
	Burst uint64 `yaml:"burst"`
}

// WebConfig defines the configuration for the web interface.
// WebConfig 定义 Web 界面配置。
type WebConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Token   string `yaml:"token"`
}

// AIConfig defines the configuration for AI features.
// AIConfig 定义 AI 功能配置。
type AIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Model   string `yaml:"model"`
	APIKey  string `yaml:"api_key"`
	BaseURL string `yaml:"base_url"`
}

// MCPConfig defines the configuration for Model Context Protocol.
// MCPConfig 定义模型上下文协议 (MCP) 配置。
type MCPConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Mode    string `yaml:"mode"` // "stdio", "sse"
}

// ClusterConfig defines the configuration for clustering.
// ClusterConfig 定义集群配置。
// For standalone mode, only enabled and configpath are used.
// For cluster mode, detailed config is read from the configpath file.
// 单机版只使用 enabled 和 configpath，集群版从 configpath 文件读取详细配置。
type ClusterConfig struct {
	Enabled    bool   `yaml:"enabled"`    // Enable cluster mode / 启用集群模式
	ConfigPath string `yaml:"configpath"` // Path to cluster config file / 集群配置文件路径
}

// CapacityConfig defines the capacity settings for BPF maps.
// CapacityConfig 定义 BPF Map 的容量设置。
type CapacityConfig struct {
	Conntrack    int `yaml:"-"` // Deprecated: Use Conntrack.MaxEntries / 已弃用：使用 Conntrack.MaxEntries
	LockList     int `yaml:"lock_list"`
	DynLockList  int `yaml:"dyn_lock_list"`
	Whitelist    int `yaml:"whitelist"`
	IPPortRules  int `yaml:"ip_port_rules"`
	AllowedPorts int `yaml:"allowed_ports"`
	// Stats map capacities (per minute capacity for top IP/port analysis)
	// 统计 Map 容量（每分钟容量，用于 top IP/端口分析）
	DropReasonStats int `yaml:"drop_reason_stats"` // Drop reason stats map size / 丢弃原因统计 Map 大小
	PassReasonStats int `yaml:"pass_reason_stats"` // Pass reason stats map size / 通过原因统计 Map 大小
}

// BaseConfig defines the base firewall settings.
// BaseConfig 定义基础防火墙设置。
type BaseConfig struct {
	DefaultDeny        bool `yaml:"default_deny"`
	AllowReturnTraffic bool `yaml:"allow_return_traffic"` // Stateless check (ACK + Port range)
	// AllowReturnTraffic: 无状态检查（ACK + 端口范围）
	AllowICMP      bool     `yaml:"allow_icmp"`
	Interfaces     []string `yaml:"interfaces"`
	EnableAFXDP    bool     `yaml:"enable_af_xdp"`
	StrictProtocol bool     `yaml:"strict_protocol"`
	DropFragments  bool     `yaml:"drop_fragments"`
	StrictTCP      bool     `yaml:"strict_tcp"`
	SYNLimit       bool     `yaml:"syn_limit"`
	BogonFilter    bool     `yaml:"bogon_filter"`
	ICMPRate       uint64   `yaml:"icmp_rate"` // packets per second
	// ICMPRate: 每秒包数
	ICMPBurst uint64 `yaml:"icmp_burst"` // max burst
	// ICMPBurst: 最大突发量
	Whitelist              []string `yaml:"whitelist"`
	LockListFile           string   `yaml:"lock_list_file"`
	LockListBinary         string   `yaml:"lock_list_binary"`
	LockListMergeThreshold int      `yaml:"lock_list_merge_threshold"` // If > 0, merge IPs into /24 (IPv4) or /64 (IPv6) if count >= threshold
	// LockListMergeThreshold: 如果 > 0，当数量 >= 阈值时将 IP 合并为子网
	LockListV4Mask int `yaml:"lock_list_v4_mask"` // Target mask for IPv4 merging (default 24)
	// LockListV4Mask: IPv4 合并的目标掩码（默认 24）
	LockListV6Mask int `yaml:"lock_list_v6_mask"` // Target mask for IPv6 merging (default 64)
	// LockListV6Mask: IPv6 合并的目标掩码（默认 64）
	BPFPinPath string `yaml:"bpf_pin_path"` // Path to pin BPF maps (override default)
	// BPFPinPath: 固定 BPF Map 的路径（覆盖默认值）
	EnableExpiry    bool   `yaml:"enable_expiry"`
	CleanupInterval string `yaml:"cleanup_interval"`
	PersistRules    bool   `yaml:"persist_rules"`
	EnablePprof     bool   `yaml:"enable_pprof"`
	PprofPort       int    `yaml:"pprof_port"`
}

// ConntrackConfig defines the configuration for connection tracking.
// ConntrackConfig 定义连接跟踪配置。
type ConntrackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	MaxEntries int    `yaml:"max_entries"`
	TCPTimeout string `yaml:"tcp_timeout"`
	UDPTimeout string `yaml:"udp_timeout"`
}

// MetricsConfig defines the configuration for metrics collection.
// MetricsConfig 定义指标收集配置。
type MetricsConfig struct {
	Enabled         bool   `yaml:"enabled"`
	ServerEnabled   bool   `yaml:"server_enabled"`
	Port            int    `yaml:"port"`
	PushEnabled     bool   `yaml:"push_enabled"`
	PushGatewayAddr string `yaml:"push_gateway_addr"`
	PushInterval    string `yaml:"push_interval"`
	TextfileEnabled bool   `yaml:"textfile_enabled"`
	TextfilePath    string `yaml:"textfile_path"`
}

// PortConfig defines the configuration for port filtering.
// PortConfig 定义端口过滤配置。
type PortConfig struct {
	AllowedPorts []uint16     `yaml:"allowed_ports"`
	IPPortRules  []IPPortRule `yaml:"ip_port_rules"`
}

// IPPortRule defines a filtering rule for a specific IP and port.
// IPPortRule 定义特定 IP 和端口的过滤规则。
type IPPortRule struct {
	IP     string `yaml:"ip"`
	Port   uint16 `yaml:"port"`
	Action uint8  `yaml:"action"` // 1: allow, 2: deny
}

// LoadGlobalConfig loads the configuration from a YAML file.
// LoadGlobalConfig 从 YAML 文件加载配置。
func LoadGlobalConfig(path string) (*GlobalConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Initialize with defaults / 使用默认值初始化
	cfg := GlobalConfig{
		Cluster: ClusterConfig{
			Enabled:    false,
			ConfigPath: "cluster.yaml",
		},
		Base: BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: false,
			AllowICMP:          true,
			PersistRules:       true,
			CleanupInterval:    "1m",
			ICMPRate:           10,
			ICMPBurst:          50,
			LockListV4Mask:     24,
			LockListV6Mask:     64,
			EnablePprof:        false,
			PprofPort:          6060,
		},
		Conntrack: ConntrackConfig{
			Enabled:    true,
			MaxEntries: 100000,
			TCPTimeout: "1h",
			UDPTimeout: "5m",
		},
		RateLimit: RateLimitConfig{
			Enabled:         true,
			AutoBlock:       true,
			AutoBlockExpiry: "10m",
		},
		LogEngine: LogEngineConfig{
			Enabled: false,
			Workers: 4,
		},
		Capacity: CapacityConfig{
			Conntrack:       100000,
			LockList:        2000000,
			Whitelist:       65536,
			IPPortRules:     65536,
			AllowedPorts:    1024,
			DropReasonStats: 1000000, // 1 million entries per minute / 每分钟 100 万条目
			PassReasonStats: 1000000, // 1 million entries per minute / 每分钟 100 万条目
		},
		Logging: LoggingConfig{
			Enabled:    false,
			Path:       "/var/log/netxfw/agent.log",
			MaxSize:    10, // 10MB
			MaxBackups: 3,
			MaxAge:     30, // 30 days
			Compress:   true,
		},

		Web: WebConfig{
			Port: 11811,
		},
		Metrics: MetricsConfig{
			Enabled:       false,
			ServerEnabled: false,
			Port:          11812,
		},
		AI: AIConfig{
			Enabled: false,
			Port:    11813,
		},
		MCP: MCPConfig{
			Enabled: false,
			Port:    11814,
			Mode:    "sse",
		},
	}

	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	// Validate configuration / 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Check for missing keys and update file if needed
	checkForUpdates(path, &cfg, data)

	return &cfg, nil
}

func checkForUpdates(path string, cfg *GlobalConfig, data []byte) {
	// 1. Unmarshal default config (TEMPLATE) to Node (Source of Truth for structure & comments)
	// We use DefaultConfigTemplate instead of marshaling cfg to preserve comments.
	var defaultNode yaml.Node
	if err := yaml.Unmarshal([]byte(DefaultConfigTemplate), &defaultNode); err != nil {
		log.Printf("⚠️  Failed to parse default config template: %v", err)
		return
	}

	// 2. Unmarshal existing file to Node (Target to update)
	var fileNode yaml.Node
	if err := yaml.Unmarshal(data, &fileNode); err != nil {
		log.Printf("⚠️  Config file seems malformed, skipping auto-update check: %v", err)
		return
	}

	// 3. Merge missing keys from defaultNode into fileNode
	// We want to keep fileNode's values, but add missing keys from defaultNode (with comments).
	// Currently MergeYamlNodes(target, source) updates target with source.
	// If we use MergeYamlNodes(&defaultNode, &fileNode), defaultNode becomes the master.
	// defaultNode has comments. fileNode has user values.
	// Result: defaultNode structure + comments + user values + user extra keys.
	// This effectively "repairs" the config file structure while keeping values.
	MergeYamlNodes(&defaultNode, &fileNode)

	// Check if content changed before writing
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&defaultNode); err != nil {
		log.Printf("❌ Failed to encode updated config: %v", err)
		return
	}

	if bytes.Equal(buf.Bytes(), data) {
		// No changes (including comments), skip write
		return
	}

	log.Println("🔄 Refreshing configuration file structure and comments...")

	// Backup original
	backupPath := path + ".bak." + time.Now().Format("20060102-150405")
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		log.Printf("⚠️  Failed to backup config file, skipping update: %v", err)
		return
	}

	// Cleanup old backups (Keep latest 3) / 清理旧备份（保留最近 3 个）
	cleanupBackups(path, 3)

	// Write new config (defaultNode now contains merged state)
	// yaml.v3 Encoder adds a newline
	if err := fileutil.AtomicWriteFile(path, buf.Bytes(), 0644); err != nil {
		log.Printf("❌ Failed to update config file: %v", err)
	} else {
		log.Println("✅ Configuration file updated (comments restored/preserved).")
	}
}

// updateYamlNode recursively adds keys from defaultNode to fileNode if they are missing.
// Returns true if any change was made.
// updateYamlNode 递归地将 defaultNode 中缺失的键添加到 fileNode。
// 如果进行了任何更改，则返回 true。
//
//nolint:unused
func updateYamlNode(fileNode, defaultNode *yaml.Node) bool {
	if fileNode.Kind == yaml.DocumentNode && defaultNode.Kind == yaml.DocumentNode {
		return updateYamlNode(fileNode.Content[0], defaultNode.Content[0])
	}
	if fileNode.Kind != yaml.MappingNode || defaultNode.Kind != yaml.MappingNode {
		return false
	}

	modified := false

	// Iterate over keys in defaultNode (Key, Value pairs)
	for i := 0; i < len(defaultNode.Content); i += 2 {
		keyNode := defaultNode.Content[i]
		valNode := defaultNode.Content[i+1]

		// Check if key exists in fileNode
		var fileValNode *yaml.Node
		for j := 0; j < len(fileNode.Content); j += 2 {
			if fileNode.Content[j].Value == keyNode.Value {
				fileValNode = fileNode.Content[j+1]
				break
			}
		}

		if fileValNode == nil {
			// Key missing, append Key and Value
			// We append the nodes directly.
			fileNode.Content = append(fileNode.Content, keyNode, valNode)
			modified = true
		} else if fileValNode.Kind == yaml.MappingNode && valNode.Kind == yaml.MappingNode {
			// Key exists, recurse if both are mappings
			if updateYamlNode(fileValNode, valNode) {
				modified = true
			}
		}
	}
	return modified
}

// hasMissingKeys checks if file is missing keys from full.
// Deprecated: logic moved to updateYamlNode
// hasMissingKeys 检查 file 是否缺少 full 中的键。
// 已弃用：逻辑已移至 updateYamlNode
//
//nolint:unused
func hasMissingKeys(full, file map[string]interface{}) bool {
	// Deprecated: logic moved to updateYamlNode
	return false
}

func SaveGlobalConfig(path string, cfg *GlobalConfig) error {
	// 1. Marshal new config to Node
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	var newNode yaml.Node
	if unmarshalErr := yaml.Unmarshal(data, &newNode); unmarshalErr != nil {
		return unmarshalErr
	}

	// 2. Read existing file to Node (if exists)
	fileData, readErr := os.ReadFile(path)
	if readErr == nil {
		var fileNode yaml.Node
		if unmarshalErr := yaml.Unmarshal(fileData, &fileNode); unmarshalErr == nil {
			// 3. Clean deprecated cluster fields BEFORE merge (to remove old fields)
			// 在合并之前清理已弃用的集群字段（以移除旧字段）
			CleanDeprecatedClusterFields(&fileNode)

			// 4. Merge new config INTO file config (preserving comments)
			MergeYamlNodes(&fileNode, &newNode)

			// Encode back
			var buf bytes.Buffer
			enc := yaml.NewEncoder(&buf)
			enc.SetIndent(2)
			if encodeErr := enc.Encode(&fileNode); encodeErr != nil {
				return encodeErr
			}
			return fileutil.AtomicWriteFile(path, buf.Bytes(), 0644)
		}
	}

	// Fallback if file doesn't exist or is malformed: just write the new config
	return fileutil.AtomicWriteFile(path, data, 0644)
}

// MergeYamlNodes updates target (existing file) with source (new config).
// It preserves comments from target where possible.
// For cluster config, it removes deprecated fields (port, nodes, secret) that are no longer in the struct.
func MergeYamlNodes(target, source *yaml.Node) {
	if target.Kind == yaml.DocumentNode {
		if source.Kind == yaml.DocumentNode {
			MergeYamlNodes(target.Content[0], source.Content[0])
		}
		return
	}

	if target.Kind != yaml.MappingNode || source.Kind != yaml.MappingNode {
		// Replace target with source, but try to keep comments
		// Copy comments from target (old) to source (new)
		if source.HeadComment == "" {
			source.HeadComment = target.HeadComment
		}
		if source.LineComment == "" {
			source.LineComment = target.LineComment
		}
		if source.FootComment == "" {
			source.FootComment = target.FootComment
		}

		*target = *source
		return
	}

	// Both are MappingNodes.
	// We want to preserve Target's structure/comments (Default Config)
	// and update it with Source's values (User Config).
	// We also want to keep any extra keys from Source that are not in Target.

	// 1. Map Source keys for lookup
	sourceMap := make(map[string]int)
	for i := 0; i < len(source.Content); i += 2 {
		sourceMap[source.Content[i].Value] = i
	}

	var newContent []*yaml.Node
	processedSourceKeys := make(map[string]bool)

	// 2. Iterate Target (Default) keys
	for i := 0; i < len(target.Content); i += 2 {
		tKey := target.Content[i]
		tVal := target.Content[i+1]

		if sIdx, ok := sourceMap[tKey.Value]; ok {
			// Key exists in Source: Merge Source value into Target value
			sVal := source.Content[sIdx+1]
			MergeYamlNodes(tVal, sVal)
			processedSourceKeys[tKey.Value] = true
		}
		// Always append Target key/value (to keep comments and order)
		newContent = append(newContent, tKey, tVal)
	}

	// 3. Append keys from Source that were not in Target
	for i := 0; i < len(source.Content); i += 2 {
		sKey := source.Content[i]
		sVal := source.Content[i+1]
		if !processedSourceKeys[sKey.Value] {
			newContent = append(newContent, sKey, sVal)
		}
	}

	target.Content = newContent
}

// CleanDeprecatedClusterFields removes deprecated cluster fields from the config file.
// This is called during config save to clean up old fields that are no longer in the struct.
// CleanDeprecatedClusterFields 从配置文件中移除已弃用的集群字段。
// 这在配置保存期间调用，用于清理结构体中不再存在的旧字段。
func CleanDeprecatedClusterFields(target *yaml.Node) {
	if target.Kind == yaml.DocumentNode && len(target.Content) > 0 {
		CleanDeprecatedClusterFields(target.Content[0])
		return
	}

	if target.Kind != yaml.MappingNode {
		return
	}

	// Find cluster key in target
	clusterIdx := -1
	for i := 0; i < len(target.Content); i += 2 {
		if target.Content[i].Value == "cluster" {
			clusterIdx = i + 1
			break
		}
	}

	if clusterIdx == -1 {
		return
	}

	clusterNode := target.Content[clusterIdx]
	if clusterNode.Kind != yaml.MappingNode {
		return
	}

	// Deprecated fields to remove / 要移除的已弃用字段
	deprecatedFields := map[string]bool{
		"port":     true,
		"nodes":    true,
		"secret":   true,
		"node_id":  true,
		"election": true,
		"sync":     true,
		"failover": true,
	}

	// Filter out deprecated fields / 过滤掉已弃用字段
	var newContent []*yaml.Node
	for i := 0; i < len(clusterNode.Content); i += 2 {
		key := clusterNode.Content[i].Value
		if !deprecatedFields[key] {
			newContent = append(newContent, clusterNode.Content[i], clusterNode.Content[i+1])
		}
	}

	clusterNode.Content = newContent
}

// cleanupBackups keeps only the latest N backup files.
func cleanupBackups(originalPath string, keep int) {
	dir := filepath.Dir(originalPath)
	baseName := filepath.Base(originalPath)
	pattern := baseName + ".bak.*"

	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return
	}

	if len(matches) <= keep {
		return
	}

	// Sort by name (timestamp allows chronological sorting)
	sort.Strings(matches)

	// Remove oldest
	toRemove := matches[:len(matches)-keep]
	for _, f := range toRemove {
		if err := os.Remove(f); err == nil {
			log.Printf("🗑️ Removed old backup: %s", f)
		}
	}
}
