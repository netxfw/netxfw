package plugins

import (
	"github.com/netxfw/netxfw/internal/plugins/agent/logengine"
	"github.com/netxfw/netxfw/internal/plugins/agent/metrics"
	"github.com/netxfw/netxfw/internal/plugins/agent/web"
)

var (
	// registry contains all registered plugins
	// registry 包含所有已注册的插件。
	registry = []Plugin{
		&logengine.LogEnginePlugin{},
		&metrics.MetricsPlugin{},
		&web.WebPlugin{},
	}
)

// GetPlugins returns the list of all available plugins.
// GetPlugins 返回所有可用插件的列表。
func GetPlugins() []Plugin {
	return registry
}
