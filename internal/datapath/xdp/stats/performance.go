package stats

import (
	"fmt"

	statsbridge "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend/statsbridge"
)

type PerformanceStats = statsbridge.PerformanceStats

type PerformanceStatsSnapshot = statsbridge.PerformanceStatsSnapshot

type MapLatencyStats = statsbridge.MapLatencyStats

type OperationStats = statsbridge.OperationStats

type CacheHitRateStats = statsbridge.CacheHitRateStats

type TrafficStats = statsbridge.TrafficStats

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

	perfStats := statsbridge.WrapPerformanceStats(perfInterface)
	if perfStats == nil {
		return nil, fmt.Errorf("invalid performance statistics type")
	}

	return perfStats, nil
}

func LoadTrafficStats() (TrafficStats, error) {
	return statsbridge.LoadTrafficStats()
}
