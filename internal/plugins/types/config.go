package types

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// ConfigMu protects concurrent access to the configuration file.
// ConfigMu 保护对配置文件的并发访问。
var ConfigMu sync.RWMutex

// BPFPluginConfig defines the configuration for a BPF plugin.
// BPFPluginConfig 定义 BPF 插件配置。
type BPFPluginConfig struct {
	// Path to the BPF plugin ELF file / BPF 插件 ELF 文件路径
	Path string `toml:"path"`
	// Index in the jump table (2-15) / 跳转表中的索引 (2-15)
	Index int `toml:"index"`
	// Enabled flag to control whether to load this plugin / 启用标志，控制是否加载此插件
	Enabled bool `toml:"enabled"`
	// Description of the plugin (optional) / 插件描述（可选）
	Description string `toml:"description"`
}

// BPFPluginSettings defines global BPF plugin settings.
// BPFPluginSettings 定义全局 BPF 插件设置。
type BPFPluginSettings struct {
	// Enable BPF plugin auto-loading on startup / 启用启动时自动加载 BPF 插件
	Enabled bool `toml:"enabled"`
	// List of BPF plugins to load / 要加载的 BPF 插件列表
	Plugins []BPFPluginConfig `toml:"plugins"`
}

// GlobalConfig represents the top-level configuration structure.
// GlobalConfig 表示顶级配置结构。
type GlobalConfig struct {
	Cluster   ClusterConfig        `toml:"cluster"`
	Base      BaseConfig           `toml:"base"`
	Web       WebConfig            `toml:"web"`
	Metrics   MetricsConfig        `toml:"metrics"`
	Port      PortConfig           `toml:"port"`
	Conntrack ConntrackConfig      `toml:"conntrack"`
	RateLimit RateLimitConfig      `toml:"rate_limit"`
	LogEngine LogEngineConfig      `toml:"log_engine"`
	Capacity  CapacityConfig       `toml:"capacity"`
	Logging   logger.LoggingConfig `toml:"logging"`
	Cloud     CloudConfig          `toml:"cloud"`
	AI        AIConfig             `toml:"ai"`
	MCP       MCPConfig            `toml:"mcp"`
	BPFPlugin BPFPluginSettings    `toml:"bpf_plugin"`
	Modules   []ModuleConfig       `toml:"modules"`
}

// ModuleConfig defines the configuration for a BPF module.
// ModuleConfig 定义 BPF 模块的配置。
type ModuleConfig struct {
	Name     string `toml:"name"`
	Enabled  bool   `toml:"enabled"`
	Priority int    `toml:"priority"` // Lower number = higher priority (runs earlier) / 数字越小优先级越高（越早执行）
}

// LogEngineConfig defines the configuration for the log engine.
// LogEngineConfig 定义日志引擎配置。
type LogEngineConfig struct {
	Enabled bool `toml:"enabled"`
	Workers int  `toml:"workers"`
	// Max history window in seconds (default 3600) / 最大历史窗口（秒，默认 3600）
	MaxWindow int             `toml:"max_window"`
	Rules     []LogEngineRule `toml:"rules"`
}

// LogEngineRule defines a rule for the log engine.
// LogEngineRule 定义日志引擎规则。
type LogEngineRule struct {
	ID string `toml:"id"`
	// Optional: File path pattern (glob or substring) / 可选：文件路径模式（glob 或子字符串）
	Path string `toml:"path"`

	// Tail Position: "start", "end" (default), "offset" / 读取位置："start" (从头开始), "end" (从末尾开始), "offset" (从上次记录位置开始)
	TailPosition string `toml:"tail_position"`

	Expression string `toml:"expression"`
	// Action: "block", "log" / 执行动作："block"（封禁）, "log"（记录）
	Action string `toml:"action"`

	// Simplified Configuration (alternative to Expression) / 简化配置（Expression 的替代方案）
	// Keywords: AND logic alias for Contains (supports * wildcard) / Contains 的 AND 逻辑别名（支持 * 通配符）
	Keywords []string `toml:"keywords"`
	// Contains: AND logic: Must contain ALL of these (supports * wildcard) / AND 逻辑：必须包含所有这些（支持 * 通配符）
	Contains []string `toml:"contains"`
	// AnyContains: OR logic: Must contain AT LEAST ONE of these (supports * wildcard) / OR 逻辑：必须包含其中至少一个（支持 * 通配符）
	AnyContains []string `toml:"any_contains"`
	// NotContains: NOT logic: Must NOT contain ANY of these (supports * wildcard) / NOT 逻辑：不能包含其中任何一个（支持 * 通配符）
	NotContains []string `toml:"not_contains"`

	// Aliases for better UX (User preference) / 为了更好的用户体验提供的别名
	// And: Alias for Contains (AND logic) / Contains 的别名 (AND 逻辑)
	And []string `toml:"and"`
	// Is: Alias for Contains (AND logic) / Contains 的别名 (AND 逻辑)
	Is []string `toml:"is"`
	// Or: Alias for AnyContains (OR logic) / AnyContains 的别名 (OR 逻辑)
	Or []string `toml:"or"`
	// Not: Alias for NotContains (NOT logic) / NotContains 的别名 (NOT 逻辑)
	Not []string `toml:"not"`

	// Regex: Regular expression to match / 正则表达式匹配
	Regex string `toml:"regex"`
	// Threshold: Trigger count / 触发阈值
	Threshold int `toml:"threshold"`
	// Interval: Time window in seconds (default 60) / 时间窗口（秒，默认 60）
	Interval int `toml:"interval"`
	// TTL: Block duration (e.g., "10m", "1h"). Empty or "0" means permanent/static or LRU auto-evict. / 封禁持续时间（例如 "10m", "1h"）。为空或 "0" 表示永久或 LRU 自动驱逐。
	TTL string `toml:"ttl"`
}

// RateLimitConfig defines the configuration for rate limiting.
// RateLimitConfig 定义速率限制配置。
type RateLimitConfig struct {
	Enabled   bool `toml:"enabled"`
	AutoBlock bool `toml:"auto_block"`
	// AutoBlockExpiry: Auto block expiry duration (e.g., "5m", "1h") / 自动封禁过期时间（例如 "5m", "1h"）
	AutoBlockExpiry string          `toml:"auto_block_expiry"`
	Rules           []RateLimitRule `toml:"rules"`
}

// RateLimitRule defines a rate limit rule for a specific IP/CIDR.
// RateLimitRule 定义特定 IP/CIDR 的速率限制规则。
type RateLimitRule struct {
	IP    string `toml:"ip"`
	Rate  uint64 `toml:"rate"`
	Burst uint64 `toml:"burst"`
}

// WebConfig defines the configuration for the web interface.
// WebConfig 定义 Web 界面配置。
type WebConfig struct {
	Enabled bool   `toml:"enabled"`
	Port    int    `toml:"port"`
	Token   string `toml:"token"`
}

// AIConfig defines the configuration for AI features.
// AIConfig 定义 AI 功能配置。
type AIConfig struct {
	Enabled bool   `toml:"enabled"`
	Port    int    `toml:"port"`
	Model   string `toml:"model"`
	APIKey  string `toml:"api_key"`
	BaseURL string `toml:"base_url"`
}

// MCPConfig defines the configuration for Model Context Protocol.
// MCPConfig 定义模型上下文协议 (MCP) 配置。
type MCPConfig struct {
	Enabled bool   `toml:"enabled"`
	Port    int    `toml:"port"`
	Mode    string `toml:"mode"` // "stdio", "sse"
}

// CloudConfig defines the configuration for cloud environment support.
// CloudConfig 定义云环境支持配置。
type CloudConfig struct {
	// Enable cloud environment support / 启用云环境支持
	Enabled bool `toml:"enabled"`
	// Cloud provider: alibaba, tencent, aws, azure, gcp, other / 云服务商
	Provider string `toml:"provider"`
	// ProxyProtocol: Proxy Protocol configuration / Proxy Protocol 配置
	ProxyProtocol ProxyProtocolConfig `toml:"proxy_protocol"`
	// RealIPBlacklist is managed via API/CLI, stored in dynamic_blacklist map. / 真实 IP 黑名单通过 API/CLI 管理，存储在 dynamic_blacklist Map 中。
}

// ProxyProtocolConfig defines the Proxy Protocol configuration.
// ProxyProtocolConfig 定义 Proxy Protocol 配置。
type ProxyProtocolConfig struct {
	// Enabled: Enable Proxy Protocol parsing / 启用 Proxy Protocol 解析
	Enabled bool `toml:"enabled"`
	// TrustedLBRanges: Trusted LB IP ranges (custom ranges) / 可信 LB IP 范围（自定义范围）
	TrustedLBRanges []string `toml:"trusted_lb_ranges"`
	// CacheTTL: Cache TTL / 缓存 TTL
	CacheTTL string `toml:"cache_ttl"`
}

// ClusterConfig defines the configuration for clustering.
// ClusterConfig 定义集群配置。
// For standalone mode, only enabled and configpath are used. / 单机版只使用 enabled 和 configpath。
// For cluster mode, detailed config is read from the configpath file. / 集群版从 configpath 文件读取详细配置。
type ClusterConfig struct {
	Enabled    bool   `toml:"enabled"`    // Enable cluster mode / 启用集群模式
	ConfigPath string `toml:"configpath"` // Path to cluster config file / 集群配置文件路径
}

// CapacityConfig defines the capacity settings for BPF maps.
// CapacityConfig 定义 BPF Map 的容量设置。
type CapacityConfig struct {
	// Deprecated: Use Conntrack.MaxEntries / 已弃用：使用 Conntrack.MaxEntries
	Conntrack    int `toml:"-"`
	LockList     int `toml:"lock_list"`
	DynLockList  int `toml:"dyn_lock_list"`
	Whitelist    int `toml:"whitelist"`
	IPPortRules  int `toml:"ip_port_rules"`
	AllowedPorts int `toml:"allowed_ports"`
	// RateLimits: Rate limit rules capacity / 限速规则容量
	RateLimits int `toml:"rate_limits"`
	// DropReasonStats: Stats map capacities (per minute capacity for top IP/port analysis) / 丢弃原因统计 Map 大小（每分钟容量，用于 top IP/端口分析）
	DropReasonStats int `toml:"drop_reason_stats"`
	// PassReasonStats: Pass reason stats map size / 通过原因统计 Map 大小
	PassReasonStats int `toml:"pass_reason_stats"`
}

// BaseConfig defines the base firewall settings.
// BaseConfig 定义基础防火墙设置。
type BaseConfig struct {
	DefaultDeny bool `toml:"default_deny"`
	// AllowReturnTraffic: Stateless check (ACK + Port range) / 无状态检查（ACK + 端口范围）
	AllowReturnTraffic bool     `toml:"allow_return_traffic"`
	AllowICMP          bool     `toml:"allow_icmp"`
	Interfaces         []string `toml:"interfaces"`
	EnableAFXDP        bool     `toml:"enable_af_xdp"`
	StrictProtocol     bool     `toml:"strict_protocol"`
	DropFragments      bool     `toml:"drop_fragments"`
	StrictTCP          bool     `toml:"strict_tcp"`
	SYNLimit           bool     `toml:"syn_limit"`
	BogonFilter        bool     `toml:"bogon_filter"`
	// ICMPRate: Packets per second / 每秒包数
	ICMPRate uint64 `toml:"icmp_rate"`
	// ICMPBurst: Max burst / 最大突发量
	ICMPBurst      uint64   `toml:"icmp_burst"`
	Whitelist      []string `toml:"whitelist"`
	LockListFile   string   `toml:"lock_list_file"`
	LockListBinary string   `toml:"lock_list_binary"`
	// LockListMergeThreshold: If > 0, merge IPs into /24 (IPv4) or /64 (IPv6) if count >= threshold / 如果 > 0，当数量 >= 阈值时将 IP 合并为子网
	LockListMergeThreshold int `toml:"lock_list_merge_threshold"`
	// LockListV4Mask: Target mask for IPv4 merging (default 24) / IPv4 合并的目标掩码（默认 24）
	LockListV4Mask int `toml:"lock_list_v4_mask"`
	// LockListV6Mask: Target mask for IPv6 merging (default 64) / IPv6 合并的目标掩码（默认 64）
	LockListV6Mask int `toml:"lock_list_v6_mask"`
	// BPFPinPath: Path to pin BPF maps (override default) / 固定 BPF Map 的路径（覆盖默认值）
	BPFPinPath      string `toml:"bpf_pin_path"`
	EnableExpiry    bool   `toml:"enable_expiry"`
	CleanupInterval string `toml:"cleanup_interval"`
	PersistRules    bool   `toml:"persist_rules"`
	EnablePprof     bool   `toml:"enable_pprof"`
	PprofPort       int    `toml:"pprof_port"`
	// BackupKeep: Number of config backup files to keep (default 3) / 保留的配置备份文件数量（默认 3）
	BackupKeep int `toml:"backup_keep"`
}

// ConntrackConfig defines the configuration for connection tracking.
// ConntrackConfig 定义连接跟踪配置。
type ConntrackConfig struct {
	Enabled    bool   `toml:"enabled"`
	MaxEntries int    `toml:"max_entries"`
	TCPTimeout string `toml:"tcp_timeout"`
	UDPTimeout string `toml:"udp_timeout"`
}

// MetricsConfig defines the configuration for metrics collection.
// MetricsConfig 定义指标收集配置。
type MetricsConfig struct {
	Enabled         bool   `toml:"enabled"`
	ServerEnabled   bool   `toml:"server_enabled"`
	Port            int    `toml:"port"`
	PushEnabled     bool   `toml:"push_enabled"`
	PushGatewayAddr string `toml:"push_gateway_addr"`
	PushInterval    string `toml:"push_interval"`
	TextfileEnabled bool   `toml:"textfile_enabled"`
	TextfilePath    string `toml:"textfile_path"`
	// TopN: Number of top entries to display in status output / 状态输出中显示的 Top 条目数量
	TopN int `toml:"top_n"`
	// ThresholdCritical: Critical usage threshold (default 90) / 危机使用率阈值（默认 90）
	ThresholdCritical int `toml:"threshold_critical"`
	// ThresholdHigh: High usage threshold (default 75) / 高使用率阈值（默认 75）
	ThresholdHigh int `toml:"threshold_high"`
	// ThresholdMedium: Medium usage threshold (default 50) / 中等使用率阈值（默认 50）
	ThresholdMedium int `toml:"threshold_medium"`
	// StatsInterval: Traffic stats collection interval (default "1s") / 流量统计收集间隔（默认 "1s"）
	StatsInterval string `toml:"stats_interval"`
	// AvgPacketSize: Average packet size in bytes for BPS estimation (default 500) / 用于 BPS 估算的平均包大小（默认 500）
	AvgPacketSize int `toml:"avg_packet_size"`
}

// PortConfig defines the configuration for port filtering.
// PortConfig 定义端口过滤配置。
type PortConfig struct {
	AllowedPorts []uint16     `toml:"allowed_ports"`
	IPPortRules  []IPPortRule `toml:"ip_port_rules"`
}

// IPPortRule defines a filtering rule for a specific IP and port.
// IPPortRule 定义特定 IP 和端口的过滤规则。
type IPPortRule struct {
	IP   string `toml:"ip"`
	Port uint16 `toml:"port"`
	// Action: 0: deny, 1: allow / 0: 拒绝, 1: 允许
	Action uint8 `toml:"action"`
}

// LoadGlobalConfig loads the configuration from a TOML file.
// LoadGlobalConfig 从 TOML 文件加载配置。
func LoadGlobalConfig(path string) (*GlobalConfig, error) {
	safePath := filepath.Clean(path) // Sanitize path to prevent directory traversal
	data, err := os.ReadFile(safePath)
	if err != nil {
		return nil, err
	}

	// Initialize with defaults / 使用默认值初始化
	cfg := GlobalConfig{
		Cluster: ClusterConfig{
			Enabled:    false,
			ConfigPath: "cluster.toml",
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
			DynLockList:     2000000,
			Whitelist:       65536,
			IPPortRules:     65536,
			AllowedPorts:    1024,
			RateLimits:      1000,
			DropReasonStats: 1000000, // 1 million entries per minute / 每分钟 100 万条目
			PassReasonStats: 1000000, // 1 million entries per minute / 每分钟 100 万条目
		},
		Logging: logger.LoggingConfig{
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
			Enabled:           false,
			ServerEnabled:     false,
			Port:              11812,
			TopN:              10,   // Default top N entries to display / 默认显示的 Top 条目数量
			ThresholdCritical: 90,   // Default critical threshold / 默认危机阈值
			ThresholdHigh:     75,   // Default high threshold / 默认高阈值
			ThresholdMedium:   50,   // Default medium threshold / 默认中等阈值
			StatsInterval:     "1s", // Default stats collection interval / 默认统计收集间隔
			AvgPacketSize:     500,  // Default average packet size in bytes / 默认平均包大小（字节）
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

	_, err = toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, err
	}

	// Validate configuration / 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// SaveGlobalConfig saves the configuration to a TOML file.
// SaveGlobalConfig 将配置保存到 TOML 文件。
func SaveGlobalConfig(path string, cfg *GlobalConfig) error {
	var buf bytes.Buffer
	err := toml.NewEncoder(&buf).Encode(cfg)
	if err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(path, buf.Bytes(), 0600)
}

// SaveGlobalConfigWithBackup saves the configuration to a TOML file with backup.
// SaveGlobalConfigWithBackup 将配置保存到 TOML 文件并创建备份。
func SaveGlobalConfigWithBackup(path string, cfg *GlobalConfig, keepBackups int) error {
	log := logger.Get(nil)

	// Read existing content to check if changed / 读取现有内容检查是否更改
	safePath := filepath.Clean(path)
	oldData, readErr := os.ReadFile(safePath)

	// Encode new config / 编码新配置
	var buf bytes.Buffer
	err := toml.NewEncoder(&buf).Encode(cfg)
	if err != nil {
		return err
	}
	newData := buf.Bytes()

	// If file exists and content unchanged, skip write / 如果文件存在且内容未更改，跳过写入
	if readErr == nil && bytes.Equal(oldData, newData) {
		return nil
	}

	// Create backup if file exists / 如果文件存在则创建备份
	if readErr == nil && keepBackups > 0 {
		backupPath := safePath + ".bak." + time.Now().Format("20060102-150405")
		if err := os.WriteFile(backupPath, oldData, 0600); err != nil {
			log.Warnf("[WARN] Failed to backup config file: %v", err)
		} else {
			log.Infof("[BACKUP] Created config backup: %s", backupPath)
			// Cleanup old backups / 清理旧备份
			CleanupOldBackups(path, keepBackups)
		}
	}

	return fileutil.AtomicWriteFile(path, newData, 0600)
}

// CleanupOldBackups removes old backup files, keeping only the latest N.
// CleanupOldBackups 清理旧备份文件，只保留最近 N 个。
func CleanupOldBackups(originalPath string, keep int) error {
	log := logger.Get(nil)

	dir := filepath.Dir(originalPath)
	baseName := filepath.Base(originalPath)
	pattern := baseName + ".bak.*"

	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return err
	}

	if len(matches) <= keep {
		return nil
	}

	// Sort by name (timestamp allows chronological sorting) / 按名称排序（时间戳允许按时间排序）
	sort.Strings(matches)

	// Remove oldest / 移除最旧的
	toRemove := matches[:len(matches)-keep]
	for _, f := range toRemove {
		if err := os.Remove(f); err == nil {
			log.Infof("[DELETE] Removed old backup: %s", f)
		}
	}

	return nil
}

// BackupConfig creates a backup of the configuration file.
// BackupConfig 创建配置文件的备份。
func BackupConfig(path string) (string, error) {
	safePath := filepath.Clean(path)
	data, err := os.ReadFile(safePath)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	backupPath := safePath + ".bak." + time.Now().Format("20060102-150405")
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	return backupPath, nil
}

// RestoreConfigFromBackup restores configuration from a backup file.
// RestoreConfigFromBackup 从备份文件恢复配置。
func RestoreConfigFromBackup(backupPath, configPath string) error {
	safeBackupPath := filepath.Clean(backupPath)
	safeConfigPath := filepath.Clean(configPath)

	data, err := os.ReadFile(safeBackupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Validate TOML syntax before restoring / 恢复前验证 TOML 语法
	var testCfg map[string]any
	if _, err := toml.Decode(string(data), &testCfg); err != nil {
		return fmt.Errorf("backup file contains invalid TOML: %w", err)
	}

	return fileutil.AtomicWriteFile(safeConfigPath, data, 0600)
}

// ListBackups lists all backup files for a configuration.
// ListBackups 列出配置的所有备份文件。
func ListBackups(path string) ([]string, error) {
	dir := filepath.Dir(path)
	baseName := filepath.Base(path)
	pattern := baseName + ".bak.*"

	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, err
	}

	// Sort by name descending (newest first) / 按名称降序排序（最新的在前）
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))

	return matches, nil
}
