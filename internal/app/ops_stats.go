package app

import (
	datapathstats "github.com/netxfw/netxfw/internal/datapath/xdp/stats"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// LoadPerformanceStats returns performance statistics from the manager if available.
func LoadPerformanceStats(mgr sdk.ManagerInterface) (*PerformanceStats, error) {
	return datapathstats.LoadPerformanceStats(mgr)
}

// LoadMetrics returns unified datapath metrics derived from the active manager.
func LoadMetrics(mgr sdk.ManagerInterface) (*MetricsData, error) {
	return datapathstats.LoadMetrics(mgr)
}

// LoadTrafficStats returns shared runtime traffic statistics.
func LoadTrafficStats() (TrafficStats, error) {
	return datapathstats.LoadTrafficStats()
}

// GetConntrackMax returns configured conntrack capacity with a default fallback.
func GetConntrackMax() int {
	cfg, err := LoadConfig()
	if err == nil && cfg != nil && cfg.Capacity.Conntrack > 0 {
		return cfg.Capacity.Conntrack
	}
	return 100000
}
