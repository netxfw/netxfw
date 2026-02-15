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

	// BPF Map Names
	// BPF Map 名称，这些名称与 eBPF C 代码中定义的 Map 名称保持一致。
	MapLockList        = "lock_list"
	MapDynLockList     = "dyn_lock_list"
	MapWhitelist       = "whitelist"
	MapAllowedPorts    = "allowed_ports"
	MapIPPortRules     = "ip_port_rules"
	MapGlobalConfig    = "global_config"
	MapDropStats       = "drop_stats"
	MapDropReasonStats = "drop_reason_stats"
	MapPassStats       = "pass_stats"
	MapPassReasonStats = "pass_reason_stats"
	MapICMPLimit       = "icmp_limit_map"
	MapConntrack       = "conntrack_map"
	MapRatelimitConfig = "ratelimit_config"
	MapRatelimitState  = "ratelimit_state"
)
