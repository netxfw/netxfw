package stats

import (
	"fmt"

	xdpbackend "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
)

type PerformanceStats = datapathprograms.PerformanceStats

type PerformanceStatsSnapshot = xdpbackend.PerformanceStatsSnapshot

type MapLatencyStats = xdpbackend.MapLatencyStats

type OperationStats = xdpbackend.OperationStats

type CacheHitRateStats = xdpbackend.CacheHitRateStats

type TrafficStats = xdpbackend.TrafficStats

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

	perfStats, ok := perfInterface.(*xdpbackend.PerformanceStats)
	if !ok {
		return nil, fmt.Errorf("invalid performance statistics type")
	}

	return perfStats, nil
}

func LoadTrafficStats() (TrafficStats, error) {
	return xdpbackend.LoadTrafficStats()
}
