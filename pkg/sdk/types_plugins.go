package sdk

const (
	// BPFPluginSlotStart and BPFPluginSlotEnd define the supported jump-table
	// slot range for configured datapath plugins.
	BPFPluginSlotStart = 2
	BPFPluginSlotEnd   = 14
)

// BPFPluginConfig defines the configuration for a BPF plugin.
type BPFPluginConfig struct {
	Path        string `toml:"path"`
	Index       int    `toml:"index"`
	Enabled     bool   `toml:"enabled"`
	Description string `toml:"description"`
}

// BPFPluginSettings defines global BPF plugin settings.
type BPFPluginSettings struct {
	Enabled bool              `toml:"enabled"`
	Plugins []BPFPluginConfig `toml:"plugins"`
}
