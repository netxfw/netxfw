package plugins

import (
	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"github.com/livp123/netxfw/internal/plugins/agent/metrics"
	"github.com/livp123/netxfw/internal/plugins/dp/base"
	"github.com/livp123/netxfw/internal/plugins/dp/conntrack"
	"github.com/livp123/netxfw/internal/plugins/dp/port"
	"github.com/livp123/netxfw/internal/plugins/dp/ratelimit"
)

var (
	// registry contains all registered plugins
	// registry 包含所有已注册的插件。
	registry = []Plugin{
		&base.BasePlugin{},
		&conntrack.ConntrackPlugin{},
		&logengine.LogEnginePlugin{},
		&port.PortPlugin{},
		&ratelimit.RateLimitPlugin{},
		&metrics.MetricsPlugin{},
	}
)

// GetPlugins returns the list of all available plugins.
// GetPlugins 返回所有可用插件的列表。
func GetPlugins() []Plugin {
	return registry
}
