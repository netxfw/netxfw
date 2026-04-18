package plugins

import (
	"github.com/netxfw/netxfw/internal/plugins/logengine"
	metricsplugin "github.com/netxfw/netxfw/internal/plugins/metricsplugin"
	webplugin "github.com/netxfw/netxfw/internal/plugins/webplugin"
	"github.com/netxfw/netxfw/pkg/sdk"
)

var (
	// registry contains all registered plugins
	// registry 包含所有已注册的插件。
	registry = []sdk.RuntimePlugin{
		&logengine.LogEnginePlugin{},
		&metricsplugin.MetricsPlugin{},
		&webplugin.WebPlugin{},
	}
)

// GetRuntimePlugins returns the list of all available runtime plugins.
// GetRuntimePlugins 返回所有可用 runtime 插件的列表。
func GetRuntimePlugins() []sdk.RuntimePlugin {
	return registry
}
