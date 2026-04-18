package plugin

import (
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	"github.com/netxfw/netxfw/internal/plugins"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// RuntimeRegistry exposes the runtime plugin host inventory surface.
type RuntimeRegistry interface {
	Plugins() []sdk.RuntimePlugin
}

type runtimeRegistry struct{}

// NewRuntimeRegistry returns the runtime plugin registry facade.
func NewRuntimeRegistry() RuntimeRegistry {
	return runtimeRegistry{}
}

func (runtimeRegistry) Plugins() []sdk.RuntimePlugin {
	return plugins.GetRuntimePlugins()
}

// RuntimeInventory returns the current runtime plugin asset inventory.
func RuntimeInventory() []domainruntime.Descriptor {
	registry := NewRuntimeRegistry()
	items := registry.Plugins()
	inventory := make([]domainruntime.Descriptor, 0, len(items))
	for _, p := range items {
		inventory = append(inventory, domainruntime.Descriptor{
			Name: p.Name(),
			Kind: runtimeKindFromSDK(p.Type()),
		})
	}
	return inventory
}

func runtimeKindFromSDK(kind sdk.PluginType) domainruntime.Kind {
	switch kind {
	case sdk.PluginTypeCore:
		return domainruntime.KindCore
	default:
		return domainruntime.KindExtension
	}
}
