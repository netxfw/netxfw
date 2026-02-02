package plugins

import (
	"github.com/livp123/netxfw/internal/plugins/base"
	"github.com/livp123/netxfw/internal/plugins/conntrack"
	"github.com/livp123/netxfw/internal/plugins/metrics"
	"github.com/livp123/netxfw/internal/plugins/port"
)

var (
	registry = []Plugin{
		&base.BasePlugin{},
		&conntrack.ConntrackPlugin{},
		&port.PortPlugin{},
		&metrics.MetricsPlugin{},
	}
)

func GetPlugins() []Plugin {
	return registry
}
