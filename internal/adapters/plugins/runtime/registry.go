package runtime

import (
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	logengine "github.com/netxfw/netxfw/internal/plugins/logengine"
	metricsplugin "github.com/netxfw/netxfw/internal/plugins/metricsplugin"
	webplugin "github.com/netxfw/netxfw/internal/plugins/webplugin"
	"github.com/netxfw/netxfw/internal/ports"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

// Registry exposes runtime plugin discovery for the host adapter.
type Registry interface {
	Plugins() []RegisteredPlugin
	Inventory() []domainruntime.Descriptor
}

type RegisteredPlugin interface {
	ports.RuntimePlugin
	SDKPlugin() sdk.RuntimePlugin
	Init(ctx *sdk.RuntimePluginContext) error
	Start(ctx *sdk.RuntimePluginContext) error
	Stop() error
	Reload(ctx *sdk.RuntimePluginContext) error
	DefaultConfig() any
	Validate(config *sdk.GlobalConfig) error
}

type defaultRegistry struct{}

var defaultRuntimePlugins = []func() sdk.RuntimePlugin{
	func() sdk.RuntimePlugin { return &logengine.LogEnginePlugin{} },
	func() sdk.RuntimePlugin { return &metricsplugin.MetricsPlugin{} },
	func() sdk.RuntimePlugin { return &webplugin.WebPlugin{} },
}

// NewRegistry returns the default runtime plugin registry adapter.
func NewRegistry() Registry {
	return defaultRegistry{}
}

func (defaultRegistry) Plugins() []RegisteredPlugin {
	items := instantiateRuntimePlugins()
	out := make([]RegisteredPlugin, 0, len(items))
	for _, item := range items {
		out = append(out, registeredPluginAdapter{inner: item})
	}
	return out
}

func (defaultRegistry) Inventory() []domainruntime.Descriptor {
	items := instantiateRuntimePlugins()
	inventory := make([]domainruntime.Descriptor, 0, len(items))
	for _, p := range items {
		inventory = append(inventory, domainruntime.Descriptor{
			Name: p.Name(),
			Kind: ports.RuntimeKindFromPluginType(ports.PluginTypeFromSDK(p.Type())),
		})
	}
	return inventory
}

func instantiateRuntimePlugins() []sdk.RuntimePlugin {
	plugins := make([]sdk.RuntimePlugin, 0, len(defaultRuntimePlugins))
	for _, factory := range defaultRuntimePlugins {
		plugins = append(plugins, factory())
	}
	return plugins
}

type registeredPluginAdapter struct {
	inner sdk.RuntimePlugin
}

func (p registeredPluginAdapter) SDKPlugin() sdk.RuntimePlugin { return p.inner }
func (p registeredPluginAdapter) Name() string                 { return p.inner.Name() }
func (p registeredPluginAdapter) Type() ports.PluginType {
	return ports.PluginTypeFromSDK(p.inner.Type())
}
func (p registeredPluginAdapter) Init(ctx *sdk.RuntimePluginContext) error { return p.inner.Init(ctx) }
func (p registeredPluginAdapter) Start(ctx *sdk.RuntimePluginContext) error {
	return p.inner.Start(ctx)
}
func (p registeredPluginAdapter) Stop() error { return p.inner.Stop() }
func (p registeredPluginAdapter) Reload(ctx *sdk.RuntimePluginContext) error {
	return p.inner.Reload(ctx)
}
func (p registeredPluginAdapter) DefaultConfig() any { return p.inner.DefaultConfig() }
func (p registeredPluginAdapter) Validate(config *sdk.GlobalConfig) error {
	return p.inner.Validate(config)
}
