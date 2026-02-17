package config

const (
	// DefaultConfigPath is the standard location for the netxfw configuration file.
	// DefaultConfigPath 是 netxfw 配置文件的标准位置。
	DefaultConfigPath = "/etc/netxfw/config.yaml"

	// DefaultPidPath is the location of the daemon PID file.
	// DefaultPidPath 是守护进程 PID 文件的位置。
	DefaultPidPath = "/var/run/netxfw.pid"

	// BPFPinPath is the filesystem path where BPF maps and programs are pinned.
	// BPFPinPath 是 BPF Map 和程序固定的文件系统路径。
	// We use _v2 to allow parallel existence during migration/upgrades or to avoid conflicts with old versions.
	// 我们使用 _v2 来允许在迁移/升级期间并行存在，或避免与旧版本冲突。
	BPFPinPath = "/sys/fs/bpf/netxfw"
)

// BPF Map Names (new unified names)
// BPF Map 名称（新的统一名称）
const (
	MapConntrack        = "conntrack_map"
	MapRatelimit        = "ratelimit_map"
	MapStaticBlacklist  = "static_blacklist"
	MapDynamicBlacklist = "dynamic_blacklist"
	MapCriticalBlacklist = "critical_blacklist"
	MapWhitelist        = "whitelist"
	MapRuleMap          = "rule_map"
	MapStatsGlobal      = "stats_global_map"
	MapTopDrop          = "top_drop_map"
	MapTopPass          = "top_pass_map"
	MapXskMap           = "xsk_map"
	MapJmpTable         = "jmp_table"
	MapGlobalConfig     = "global_config"
)

// Backward compatibility aliases (deprecated, will be removed)
// 向后兼容别名（已弃用，将被移除）
const (
	MapLockList        = "static_blacklist"        // Deprecated: use MapStaticBlacklist
	MapDynLockList     = "dynamic_blacklist"       // Deprecated: use MapDynamicBlacklist
	MapAllowedPorts    = "rule_map"                // Deprecated: use MapRuleMap
	MapIPPortRules     = "rule_map"                // Deprecated: use MapRuleMap
	MapDropStats       = "stats_global_map"        // Deprecated: use MapStatsGlobal
	MapDropReasonStats = "top_drop_map"            // Deprecated: use MapTopDrop
	MapPassStats       = "stats_global_map"        // Deprecated: use MapStatsGlobal
	MapPassReasonStats = "top_pass_map"            // Deprecated: use MapTopPass
	MapICMPLimit       = "stats_global_map"        // Deprecated: use MapStatsGlobal
	MapRatelimitConfig = "ratelimit_map"           // Deprecated: use MapRatelimit
	MapRatelimitState  = "ratelimit_map"           // Deprecated: use MapRatelimit
)
