package sdk

// PortConfig defines the configuration for port filtering.
type PortConfig struct {
	AllowedPorts []uint16     `toml:"allowed_ports"`
	IPPortRules  []IPPortRule `toml:"ip_port_rules"`
}

// ConntrackConfig defines the configuration for connection tracking.
type ConntrackConfig struct {
	Enabled    bool   `toml:"enabled"`
	MaxEntries int    `toml:"max_entries"`
	TCPTimeout string `toml:"tcp_timeout"`
	UDPTimeout string `toml:"udp_timeout"`
}

// RateLimitConfig defines the configuration for rate limiting.
type RateLimitConfig struct {
	Enabled         bool            `toml:"enabled"`
	AutoBlock       bool            `toml:"auto_block"`
	AutoBlockExpiry string          `toml:"auto_block_expiry"`
	Rules           []RateLimitRule `toml:"rules"`
}

// RateLimitRule defines a rate limit rule for a specific IP/CIDR.
type RateLimitRule struct {
	IP    string `toml:"ip"`
	Rate  uint64 `toml:"rate"`
	Burst uint64 `toml:"burst"`
}

// CapacityConfig defines the capacity settings for BPF maps.
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
