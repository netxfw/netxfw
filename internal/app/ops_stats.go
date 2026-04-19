package app

import datapathstats "github.com/netxfw/netxfw/internal/datapath/xdp/stats"

type performanceProvider interface {
	PerfStats() any
}

// LoadPerformanceStats returns performance statistics from the manager if available.
func LoadPerformanceStats(source performanceProvider) (*PerformanceStats, error) {
	return datapathstats.LoadPerformanceStats(source)
}

// LoadMetrics returns unified datapath metrics derived from the active manager.
func LoadMetrics(source any) (*MetricsData, error) {
	return datapathstats.LoadMetrics(source)
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
