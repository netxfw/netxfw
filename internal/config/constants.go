package config

const (
	// DefaultConfigPath is the standard location for the netxfw configuration file.
	// DefaultConfigPath 是 netxfw 配置文件的标准位置。
	DefaultConfigPath = "/etc/netxfw/config.yaml"

	// DefaultPidPath is the location of the daemon PID file.
	// DefaultPidPath 是守护进程 PID 文件的位置。
	DefaultPidPath = "/var/run/netxfw.pid"

	// InterfacePidPathPattern is the pattern for interface-specific PID files.
	// InterfacePidPathPattern 是接口特定 PID 文件的模式。
	InterfacePidPathPattern = "/var/run/netxfw_%s.pid"

	// BPFPinPath is the filesystem path where BPF maps and programs are pinned.
	// BPFPinPath 是 BPF Map 和程序固定的文件系统路径。
	// We use _v2 to allow parallel existence during migration/upgrades or to avoid conflicts with old versions.
	// 我们使用 _v2 来允许在迁移/升级期间并行存在，或避免与旧版本冲突。
	BPFPinPath = "/sys/fs/bpf/netxfw"
)

// BPF Map Names (new unified names)
// BPF Map 名称（新的统一名称）
const (
	MapConntrack         = "conntrack_map"
	MapRatelimit         = "ratelimit_map"
	MapStaticBlacklist   = "static_blacklist"
	MapDynamicBlacklist  = "dynamic_blacklist"
	MapCriticalBlacklist = "critical_blacklist"
	MapWhitelist         = "whitelist"
	MapRuleMap           = "rule_map"
	MapStatsGlobal       = "stats_global_map"
	MapTopDrop           = "top_drop_map"
	MapTopPass           = "top_pass_map"
	MapXskMap            = "xsk_map"
	MapJmpTable          = "jmp_table"
	MapGlobalConfig      = "global_config"
)
