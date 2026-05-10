package sdk

// LogEngineConfig defines the configuration for the log engine.
type LogEngineConfig struct {
	Enabled   bool            `toml:"enabled"`
	Workers   int             `toml:"workers"`
	MaxWindow int             `toml:"max_window"`
	Rules     []LogEngineRule `toml:"rules"`
}

// LogEngineRule defines a rule for the log engine.
type LogEngineRule struct {
	ID           string   `toml:"id"`
	Path         string   `toml:"path"`
	TailPosition string   `toml:"tail_position"`
	Expression   string   `toml:"expression"`
	Action       any      `toml:"action"`
	Keywords     []string `toml:"keywords"`
	Contains     []string `toml:"contains"`
	AnyContains  []string `toml:"any_contains"`
	NotContains  []string `toml:"not_contains"`
	And          []string `toml:"and"`
	Is           []string `toml:"is"`
	Or           []string `toml:"or"`
	Not          []string `toml:"not"`
	Regex        string   `toml:"regex"`
	Threshold    int      `toml:"threshold"`
	Interval     int      `toml:"interval"`
	TTL          string   `toml:"ttl"`
}

// CloudConfig defines the configuration for cloud environment support.
type CloudConfig struct {
	Enabled       bool                `toml:"enabled"`
	Provider      string              `toml:"provider"`
	ProxyProtocol ProxyProtocolConfig `toml:"proxy_protocol"`
}

// ProxyProtocolConfig defines the Proxy Protocol configuration.
type ProxyProtocolConfig struct {
	Enabled         bool     `toml:"enabled"`
	TrustedLBRanges []string `toml:"trusted_lb_ranges"`
	CacheTTL        string   `toml:"cache_ttl"`
}
