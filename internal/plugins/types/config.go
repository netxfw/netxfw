package types

type GlobalConfig struct {
	Base    BaseConfig    `yaml:"base"`
	Metrics MetricsConfig `yaml:"metrics"`
	Port    PortConfig    `yaml:"port"`
}

type BaseConfig struct {
	DefaultDeny  bool     `yaml:"default_deny"`
	Whitelist    []string `yaml:"whitelist"`
	LockListFile string   `yaml:"lock_list_file"`
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
