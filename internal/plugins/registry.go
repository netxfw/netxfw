package plugins

import (
	"github.com/netxfw/netxfw/internal/plugins/logengine"
	metricsplugin "github.com/netxfw/netxfw/internal/plugins/metricsplugin"
	webplugin "github.com/netxfw/netxfw/internal/plugins/webplugin"
)

var (
	// registry contains all registered plugins
	// registry 包含所有已注册的插件。
	registry = []Plugin{
		&logengine.LogEnginePlugin{},
		&metricsplugin.MetricsPlugin{},
		&webplugin.WebPlugin{},
	}
)

// GetPlugins returns the list of all available plugins.
// GetPlugins 返回所有可用插件的列表。
func GetPlugins() []Plugin {
	return registry
}
