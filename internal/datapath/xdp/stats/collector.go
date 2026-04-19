package stats

import (
	"fmt"

	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
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

type counterProvider interface {
	GetDropCount() (uint64, error)
	GetPassCount() (uint64, error)
}

type detailProvider interface {
	GetDropDetails() ([]sdk.DropDetailEntry, error)
	GetPassDetails() ([]sdk.DropDetailEntry, error)
}

type sdkManagerAccessor interface {
	GetManager() sdk.ManagerInterface
}

func NewCollector(mgr *datapathprograms.Handle) *MetricsCollector {
	return datapathprograms.NewMetricsCollector(mgr)
}

func NewCache(mgr *datapathprograms.Handle) *StatsCache {
	return datapathprograms.NewStatsCache(mgr)
}

func ExtractManager(mgr any) *datapathprograms.Handle {
	switch typed := mgr.(type) {
	case nil:
		return nil
	case *datapathprograms.Handle:
		return typed
	case interface{ GetManager() *backendxdp.Manager }:
		return datapathprograms.WrapExisting(typed.GetManager())
	case sdkManagerAccessor:
		return ExtractManager(typed.GetManager())
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
