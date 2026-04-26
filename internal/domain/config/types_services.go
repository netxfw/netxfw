package config

type WebConfig struct {
	Enabled bool   `toml:"enabled"`
	Port    int    `toml:"port"`
	Token   string `toml:"token"`
}

type MetricsConfig struct {
	Enabled           bool   `toml:"enabled"`
	ServerEnabled     bool   `toml:"server_enabled"`
	Port              int    `toml:"port"`
	PushEnabled       bool   `toml:"push_enabled"`
	PushGatewayAddr   string `toml:"push_gateway_addr"`
	PushInterval      string `toml:"push_interval"`
	TextfileEnabled   bool   `toml:"textfile_enabled"`
	TextfilePath      string `toml:"textfile_path"`
	TopN              int    `toml:"top_n"`
	ThresholdCritical int    `toml:"threshold_critical"`
	ThresholdHigh     int    `toml:"threshold_high"`
	ThresholdMedium   int    `toml:"threshold_medium"`
	StatsInterval     string `toml:"stats_interval"`
	AvgPacketSize     int    `toml:"avg_packet_size"`
}

type AIConfig struct {
	Enabled bool   `toml:"-"`
	Port    int    `toml:"-"`
	Model   string `toml:"-"`
	APIKey  string `toml:"-"`
	BaseURL string `toml:"-"`
}

type MCPConfig struct {
	Enabled bool   `toml:"-"`
	Port    int    `toml:"-"`
	Mode    string `toml:"-"`
}
