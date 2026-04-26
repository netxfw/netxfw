package sdk

// GlobalConfig represents the top-level configuration structure.
type GlobalConfig struct {
	Cluster   ClusterConfig     `toml:"cluster"`
	Base      BaseConfig        `toml:"base"`
	Web       WebConfig         `toml:"web"`
	Metrics   MetricsConfig     `toml:"metrics"`
	Port      PortConfig        `toml:"port"`
	Conntrack ConntrackConfig   `toml:"conntrack"`
	RateLimit RateLimitConfig   `toml:"rate_limit"`
	LogEngine LogEngineConfig   `toml:"log_engine"`
	Capacity  CapacityConfig    `toml:"capacity"`
	Logging   LoggingConfig     `toml:"logging"`
	Cloud     CloudConfig       `toml:"cloud"`
	AI        AIConfig          `toml:"-"`
	MCP       MCPConfig         `toml:"-"`
	BPFPlugin BPFPluginSettings `toml:"bpf_plugin"`
	Modules   []ModuleConfig    `toml:"modules"`
}
