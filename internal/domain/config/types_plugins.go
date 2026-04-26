package config

const (
	// BPFPluginSlotStart and BPFPluginSlotEnd define the supported jump-table
	// slot range for configured datapath plugins.
	BPFPluginSlotStart = 2
	BPFPluginSlotEnd   = 14
)

type BPFPluginConfig struct {
	Path        string `toml:"path"`
	Index       int    `toml:"index"`
	Enabled     bool   `toml:"enabled"`
	Description string `toml:"description"`
}

type BPFPluginSettings struct {
	Enabled bool              `toml:"enabled"`
	Plugins []BPFPluginConfig `toml:"plugins"`
}
