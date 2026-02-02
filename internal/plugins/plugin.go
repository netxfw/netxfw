package plugins

import (
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

// Plugin defines the interface for netxfw plugins
type Plugin interface {
	Name() string
	Init(config *types.GlobalConfig) error
	Start(manager *xdp.Manager) error
	Stop() error
	// InitConfig returns default configuration for this plugin
	DefaultConfig() interface{}
	// Validate checks the plugin configuration for errors
	Validate(config *types.GlobalConfig) error
}
