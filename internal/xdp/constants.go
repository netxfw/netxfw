//go:build linux
// +build linux

package xdp

// Config indices for global_config map.
// global_config Map 的配置索引。
const (
	ConfigIndexDefaultDeny        = 0
	ConfigIndexAllowReturnTraffic = 1
	ConfigIndexAllowICMP          = 2
	ConfigIndexEnableConntrack    = 3
	ConfigIndexConntrackTimeout   = 4
	ConfigIndexICMPRate           = 5
	ConfigIndexICMPBurst          = 6
	ConfigIndexEnableAFXDP        = 7
	ConfigIndexVersion            = 8
	ConfigIndexStrictProto        = 9
	ConfigIndexEnableRateLimit    = 10
	ConfigIndexDropFragments      = 11
	ConfigIndexStrictTCP          = 12
	ConfigIndexSYNLimit           = 13
	ConfigIndexBogonFilter        = 14
	ConfigIndexAutoBlock          = 15
	ConfigIndexAutoBlockExpiry    = 16
)

// Program indices for jmp_table.
// jmp_table 的程序索引。
const (
	ProgramIndexMain        = 1
	ProgramIndexPluginStart = 2
	ProgramIndexPluginEnd   = 14
	ProgramIndexDefaultDeny = 15
)

// Module IDs for BPF module chain (must match BPF definitions).
// BPF 模块链的模块 ID（必须匹配 BPF 定义）。
const (
	ModuleIDEntry            = 0
	ModuleIDSanity           = 1
	ModuleIDCritical         = 2
	ModuleIDWhitelist        = 3
	ModuleIDBlacklist        = 4
	ModuleIDDynamicBlacklist = 5
	ModuleIDRateLimit        = 6
	ModuleIDConntrack        = 7
	ModuleIDRules            = 8
	ModuleIDICMP             = 9
	ModuleIDReturn           = 10
	ModuleIDPlugins          = 11
)

// Health status constants.
// 健康状态常量。
const (
	StatusOK          = "ok"
	StatusWarning     = "warning"
	StatusCritical    = "critical"
	StatusUnavailable = "unavailable"
	StatusError       = "error"
	StatusHealthy     = "healthy"
)

// Map names (using new unified names).
// Map 名称（使用新的统一名称）。
const (
	MapNameConntrack         = "conntrack_map"
	MapNameRatelimit         = "ratelimit_map"
	MapNameStaticBlacklist   = "static_blacklist"
	MapNameDynamicBlacklist  = "dynamic_blacklist"
	MapNameCriticalBlacklist = "critical_blacklist"
	MapNameWhitelist         = "whitelist"
	MapNameRuleMap           = "rule_map"
	MapNameStatsGlobal       = "stats_global_map"
	MapNameTopDrop           = "top_drop_map"
	MapNameTopPass           = "top_pass_map"
	MapNameXskMap            = "xsk_map"
	MapNameJmpTable          = "jmp_table"
	MapNameGlobalConfig      = "global_config"
)
