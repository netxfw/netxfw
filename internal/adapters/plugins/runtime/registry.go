package runtime

import (
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	"github.com/netxfw/netxfw/internal/plugins"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// Registry exposes runtime plugin discovery for the host adapter.
type Registry interface {
	Plugins() []sdk.RuntimePlugin
	Inventory() []domainruntime.Descriptor
}

type defaultRegistry struct{}

// NewRegistry returns the default runtime plugin registry adapter.
func NewRegistry() Registry {
	return defaultRegistry{}
}

func (defaultRegistry) Plugins() []sdk.RuntimePlugin {
	return plugins.GetRuntimePlugins()
}

func (defaultRegistry) Inventory() []domainruntime.Descriptor {
	items := plugins.GetRuntimePlugins()
	inventory := make([]domainruntime.Descriptor, 0, len(items))
	for _, p := range items {
		inventory = append(inventory, domainruntime.Descriptor{
			Name: p.Name(),
			Kind: kindFromSDK(p.Type()),
		})
	}
	return inventory
}

func kindFromSDK(kind sdk.PluginType) domainruntime.Kind {
	switch kind {
	case sdk.PluginTypeCore:
		return domainruntime.KindCore
	default:
		return domainruntime.KindExtension
	}
}
