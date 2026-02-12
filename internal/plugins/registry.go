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
	registry = []Plugin{
		&base.BasePlugin{},
		&conntrack.ConntrackPlugin{},
		&logengine.LogEnginePlugin{},
		&port.PortPlugin{},
		&ratelimit.RateLimitPlugin{},
		&metrics.MetricsPlugin{},
	}
)

func GetPlugins() []Plugin {
	return registry
}
