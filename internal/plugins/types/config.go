package types

import (
	"os"

	"gopkg.in/yaml.v3"
)

type GlobalConfig struct {
	Edition   string          `yaml:"edition"` // standalone, standalone-ai, small-cluster, small-cluster-ai, large-cluster, large-cluster-ai, embedded
	Base      BaseConfig      `yaml:"base"`
	Web       WebConfig       `yaml:"web"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Port      PortConfig      `yaml:"port"`
	Conntrack ConntrackConfig `yaml:"conntrack"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Capacity  CapacityConfig  `yaml:"capacity"`
}

type RateLimitConfig struct {
	Enabled bool            `yaml:"enabled"`
	Rules   []RateLimitRule `yaml:"rules"`
}

type RateLimitRule struct {
	IP    string `yaml:"ip"`
	Rate  uint64 `yaml:"rate"`
	Burst uint64 `yaml:"burst"`
}

type WebConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Token   string `yaml:"token"`
}

type CapacityConfig struct {
	Conntrack    int `yaml:"conntrack"`
	LockList     int `yaml:"lock_list"`
	Whitelist    int `yaml:"whitelist"`
	IPPortRules  int `yaml:"ip_port_rules"`
	AllowedPorts int `yaml:"allowed_ports"`
}

type BaseConfig struct {
	DefaultDeny        bool     `yaml:"default_deny"`
	AllowReturnTraffic bool     `yaml:"allow_return_traffic"` // Stateless check (ACK + Port range)
	AllowICMP          bool     `yaml:"allow_icmp"`
	EnableAFXDP        bool     `yaml:"enable_af_xdp"`
	StrictProtocol     bool     `yaml:"strict_protocol"`
	DropFragments      bool     `yaml:"drop_fragments"`
	StrictTCP          bool     `yaml:"strict_tcp"`
	SYNLimit           bool     `yaml:"syn_limit"`
	BogonFilter        bool     `yaml:"bogon_filter"`
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
	Enabled    bool   `yaml:"enabled"`
	MaxEntries int    `yaml:"max_entries"`
	TCPTimeout string `yaml:"tcp_timeout"`
	UDPTimeout string `yaml:"udp_timeout"`
}

type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type PortConfig struct {
	AllowedPorts []uint16     `yaml:"allowed_ports"`
	IPPortRules  []IPPortRule `yaml:"ip_port_rules"`
}

type IPPortRule struct {
	IP     string `yaml:"ip"`
	Port   uint16 `yaml:"port"`
	Action uint8  `yaml:"action"` // 1: allow, 2: deny
}

func LoadGlobalConfig(path string) (*GlobalConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg GlobalConfig
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}

func SaveGlobalConfig(path string, cfg *GlobalConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
