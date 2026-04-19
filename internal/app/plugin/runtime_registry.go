package plugin

import (
	adapterruntime "github.com/netxfw/netxfw/internal/adapters/plugins/runtime"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	"github.com/netxfw/netxfw/internal/ports"
)

// RuntimeRegistry exposes the runtime plugin host inventory surface.
type RuntimeRegistry interface {
	Plugins() []ports.RuntimePlugin
}

type runtimeRegistry struct{}

// NewRuntimeRegistry returns the runtime plugin registry facade.
func NewRuntimeRegistry() RuntimeRegistry {
	return runtimeRegistry{}
}

func (runtimeRegistry) Plugins() []ports.RuntimePlugin {
	items := adapterruntime.NewRegistry().Plugins()
	out := make([]ports.RuntimePlugin, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

// RuntimeInventory returns the current runtime plugin asset inventory.
func RuntimeInventory() []domainruntime.Descriptor {
	registry := NewRuntimeRegistry()
	items := registry.Plugins()
	inventory := make([]domainruntime.Descriptor, 0, len(items))
	for _, p := range items {
		inventory = append(inventory, domainruntime.Descriptor{
			Name: p.Name(),
			Kind: ports.RuntimeKindFromPluginType(p.Type()),
		})
	}
	return inventory
}
