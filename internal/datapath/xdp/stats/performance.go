package stats

import (
	"fmt"

	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
)

type PerformanceStats = backendxdp.PerformanceStats

type PerformanceStatsSnapshot = backendxdp.PerformanceStatsSnapshot

type MapLatencyStats = backendxdp.MapLatencyStats

type OperationStats = backendxdp.OperationStats

type CacheHitRateStats = backendxdp.CacheHitRateStats

type TrafficStats = backendxdp.TrafficStats

type performanceProvider interface {
	PerfStats() any
}

func LoadPerformanceStats(mgr performanceProvider) (*PerformanceStats, error) {
	if mgr == nil {
		return nil, fmt.Errorf("manager not available")
	}

	perfInterface := mgr.PerfStats()
	if perfInterface == nil {
		return nil, fmt.Errorf("performance statistics not available")
	}

	perfStats, ok := perfInterface.(*backendxdp.PerformanceStats)
	if !ok || perfStats == nil {
		return nil, fmt.Errorf("invalid performance statistics type")
	}

	return perfStats, nil
}

func LoadTrafficStats() (TrafficStats, error) {
	return backendxdp.LoadTrafficStats()
}
