package plugins

import (
	"github.com/livp123/netxfw/internal/xdp"
)

// Plugin defines the interface for netxfw plugins.
type Plugin interface {
	Name() string
	Description() string
	Init(manager *xdp.Manager, config interface{}) error
	Start() error
	Stop() error
}

// Registry stores registered plugins.
var Registry = make(map[string]Plugin)

// Register adds a plugin to the registry.
func Register(p Plugin) {
	Registry[p.Name()] = p
}
