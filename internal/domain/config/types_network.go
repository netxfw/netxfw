package config

type PortConfig struct {
	AllowedPorts []uint16     `toml:"allowed_ports"`
	IPPortRules  []IPPortRule `toml:"ip_port_rules"`
}

type IPPortRule struct {
	IP     string `toml:"ip"`
	Port   uint16 `toml:"port"`
	Action uint8  `toml:"action"`
}

type ConntrackConfig struct {
	Enabled    bool   `toml:"enabled"`
	MaxEntries int    `toml:"max_entries"`
	TCPTimeout string `toml:"tcp_timeout"`
	UDPTimeout string `toml:"udp_timeout"`
}

type RateLimitConfig struct {
	Enabled         bool            `toml:"enabled"`
	AutoBlock       bool            `toml:"auto_block"`
	AutoBlockExpiry string          `toml:"auto_block_expiry"`
	Rules           []RateLimitRule `toml:"rules"`
}

type RateLimitRule struct {
	IP    string `toml:"ip"`
	Rate  uint64 `toml:"rate"`
	Burst uint64 `toml:"burst"`
}

type CapacityConfig struct {
	Conntrack       int `toml:"-"`
	LockList        int `toml:"lock_list"`
	DynLockList     int `toml:"dyn_lock_list"`
	Whitelist       int `toml:"whitelist"`
	IPPortRules     int `toml:"ip_port_rules"`
	AllowedPorts    int `toml:"allowed_ports"`
	RateLimits      int `toml:"rate_limits"`
	DropReasonStats int `toml:"drop_reason_stats"`
	PassReasonStats int `toml:"pass_reason_stats"`
}
