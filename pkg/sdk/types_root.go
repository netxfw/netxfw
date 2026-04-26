package sdk

// RuntimeServicesConfig groups runtime-only service settings that are not persisted in TOML.
type RuntimeServicesConfig struct {
	AI  AIConfig  `toml:"-"`
	MCP MCPConfig `toml:"-"`
}

// GlobalConfig represents the top-level configuration structure.
type GlobalConfig struct {
	Cluster   ClusterConfig         `toml:"cluster"`
	Base      BaseConfig            `toml:"base"`
	Web       WebConfig             `toml:"web"`
	Metrics   MetricsConfig         `toml:"metrics"`
	Port      PortConfig            `toml:"port"`
	Conntrack ConntrackConfig       `toml:"conntrack"`
	RateLimit RateLimitConfig       `toml:"rate_limit"`
	LogEngine LogEngineConfig       `toml:"log_engine"`
	Capacity  CapacityConfig        `toml:"capacity"`
	Logging   LoggingConfig         `toml:"logging"`
	Cloud     CloudConfig           `toml:"cloud"`
	BPFPlugin BPFPluginSettings     `toml:"bpf_plugin"`
	Modules   []ModuleConfig        `toml:"modules"`
	Runtime   RuntimeServicesConfig `toml:"-"`
}
