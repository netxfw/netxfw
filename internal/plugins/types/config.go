package types

type GlobalConfig struct {
	Base      BaseConfig      `yaml:"base"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Port      PortConfig      `yaml:"port"`
	Conntrack ConntrackConfig `yaml:"conntrack"`
}

type BaseConfig struct {
	DefaultDeny        bool     `yaml:"default_deny"`
	AllowReturnTraffic bool     `yaml:"allow_return_traffic"` // Stateless check (ACK + Port range)
	AllowICMP          bool     `yaml:"allow_icmp"`
	ICMPRate           uint64   `yaml:"icmp_rate"`  // packets per second
	ICMPBurst          uint64   `yaml:"icmp_burst"` // max burst
	Whitelist          []string `yaml:"whitelist"`
	LockListFile       string   `yaml:"lock_list_file"`
	LockListBinary     string   `yaml:"lock_list_binary"`
	EnableExpiry       bool     `yaml:"enable_expiry"`
	CleanupInterval    string   `yaml:"cleanup_interval"`
	PersistRules       bool     `yaml:"persist_rules"`
}

type ConntrackConfig struct {
	Enabled bool   `yaml:"enabled"`
	MaxEntries int `yaml:"max_entries"`
	TCPTimeout string `yaml:"tcp_timeout"`
	UDPTimeout string `yaml:"udp_timeout"`
}

type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type PortConfig struct {
	AllowedPorts []uint16      `yaml:"allowed_ports"`
	IPPortRules  []IPPortRule `yaml:"ip_port_rules"`
}

type IPPortRule struct {
	IP     string `yaml:"ip"`
	Port   uint16 `yaml:"port"`
	Action uint8  `yaml:"action"` // 1: allow, 2: deny
}
