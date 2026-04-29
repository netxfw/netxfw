package config

type ClusterConfig struct {
	Enabled    bool   `toml:"enabled"`
	ConfigPath string `toml:"configpath"`
}

type BaseConfig struct {
	DefaultDeny            bool     `toml:"default_deny"`
	AllowReturnTraffic     bool     `toml:"allow_return_traffic"`
	AllowICMP              bool     `toml:"allow_icmp"`
	Interfaces             []string `toml:"interfaces"`
	EnableAFXDP            bool     `toml:"enable_af_xdp"`
	StrictProtocol         bool     `toml:"strict_protocol"`
	DropFragments          bool     `toml:"drop_fragments"`
	StrictTCP              bool     `toml:"strict_tcp"`
	SYNLimit               bool     `toml:"syn_limit"`
	BogonFilter            bool     `toml:"bogon_filter"`
	ICMPRate               uint64   `toml:"icmp_rate"`
	ICMPBurst              uint64   `toml:"icmp_burst"`
	Whitelist              []string `toml:"whitelist"`
	LockListFile           string   `toml:"lock_list_file"`
	LockListBinary         string   `toml:"lock_list_binary"`
	LockListMergeThreshold int      `toml:"lock_list_merge_threshold"`
	LockListV4Mask         int      `toml:"lock_list_v4_mask"`
	LockListV6Mask         int      `toml:"lock_list_v6_mask"`
	BPFPinPath             string   `toml:"bpf_pin_path"`
	EnableExpiry           bool     `toml:"enable_expiry"`
	CleanupInterval        string   `toml:"cleanup_interval"`
	PersistRules           bool     `toml:"persist_rules"`
	EnablePprof            bool     `toml:"enable_pprof"`
	PprofBind              string   `toml:"pprof_bind"`
	PprofPort              int      `toml:"pprof_port"`
	BackupKeep             int      `toml:"backup_keep"`
}

type ModuleConfig struct {
	Name     string `toml:"name"`
	Enabled  bool   `toml:"enabled"`
	Priority int    `toml:"priority"`
}
