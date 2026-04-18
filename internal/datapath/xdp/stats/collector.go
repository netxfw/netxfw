package stats

import (
	"fmt"

	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type MetricsCollector = backendxdp.MetricsCollector

type MetricsData = backendxdp.MetricsData

type TrafficMetrics = backendxdp.TrafficMetrics

type ConntrackHealth = backendxdp.ConntrackHealth

type MapUsageStats = backendxdp.MapUsageStats

type MapUsageDetail = backendxdp.MapUsageDetail

type RateLimitHitStats = backendxdp.RateLimitHitStats

type RateLimitRuleHit = backendxdp.RateLimitRuleHit

type ProtocolDistribution = backendxdp.ProtocolDistribution

type ProtocolStats = backendxdp.ProtocolStats

type StatsCache = backendxdp.StatsCache

type MapCounts = backendxdp.MapCounts

type managerAccessor interface {
	GetManager() *backendxdp.Manager
}

type counterProvider interface {
	GetDropCount() (uint64, error)
	GetPassCount() (uint64, error)
}

type detailProvider interface {
	GetDropDetails() ([]sdk.DropDetailEntry, error)
	GetPassDetails() ([]sdk.DropDetailEntry, error)
}

func NewCollector(mgr *backendxdp.Manager) *MetricsCollector {
	return backendxdp.NewMetricsCollector(mgr)
}

func NewCache(mgr *backendxdp.Manager) *StatsCache {
	return backendxdp.NewStatsCache(mgr)
}

func ExtractManager(mgr any) *backendxdp.Manager {
	switch typed := mgr.(type) {
	case nil:
		return nil
	case *backendxdp.Manager:
		return typed
	case managerAccessor:
		return typed.GetManager()
	default:
		return nil
	}
}

func LoadMetrics(mgr any) (*MetricsData, error) {
	xdpMgr := ExtractManager(mgr)
	if xdpMgr == nil {
		return nil, fmt.Errorf("manager not available")
	}

	collector := NewCollector(xdpMgr)
	if err := collector.Collect(); err != nil {
		return nil, err
	}

	return collector.GetMetrics(), nil
}

func LoadDropCount(mgr counterProvider) (uint64, error) {
	if mgr == nil {
		return 0, fmt.Errorf("manager not available")
	}
	return mgr.GetDropCount()
}

func LoadPassCount(mgr counterProvider) (uint64, error) {
	if mgr == nil {
		return 0, fmt.Errorf("manager not available")
	}
	return mgr.GetPassCount()
}

func LoadDropDetails(mgr detailProvider) ([]sdk.DropDetailEntry, error) {
	if mgr == nil {
		return nil, fmt.Errorf("manager not available")
	}
	return mgr.GetDropDetails()
}

func LoadPassDetails(mgr detailProvider) ([]sdk.DropDetailEntry, error) {
	if mgr == nil {
		return nil, fmt.Errorf("manager not available")
	}
	return mgr.GetPassDetails()
}
