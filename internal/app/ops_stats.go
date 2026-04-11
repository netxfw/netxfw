package app

import (
	"fmt"

	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// LoadPerformanceStats returns performance statistics from the manager if available.
func LoadPerformanceStats(mgr sdk.ManagerInterface) (*PerformanceStats, error) {
	if mgr == nil {
		return nil, fmt.Errorf("manager not available")
	}

	perfInterface := mgr.PerfStats()
	if perfInterface == nil {
		return nil, fmt.Errorf("performance statistics not available")
	}

	perfStats, ok := perfInterface.(*xdp.PerformanceStats)
	if !ok {
		return nil, fmt.Errorf("invalid performance statistics type")
	}

	return perfStats, nil
}

// LoadTrafficStats returns shared runtime traffic statistics.
func LoadTrafficStats() (xdp.TrafficStats, error) {
	return xdp.LoadTrafficStats()
}

// GetConntrackMax returns configured conntrack capacity with a default fallback.
func GetConntrackMax() int {
	cfg, err := LoadConfig()
	if err == nil && cfg != nil && cfg.Capacity.Conntrack > 0 {
		return cfg.Capacity.Conntrack
	}
	return 100000
}
