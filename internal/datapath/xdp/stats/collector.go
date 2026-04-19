package stats

import (
	"fmt"

	xdpbackend "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type MetricsCollector = xdpbackend.MetricsCollector

type MetricsData = xdpbackend.MetricsData

type TrafficMetrics = xdpbackend.TrafficMetrics

type ConntrackHealth = xdpbackend.ConntrackHealth

type MapUsageStats = xdpbackend.MapUsageStats

type MapUsageDetail = xdpbackend.MapUsageDetail

type RateLimitHitStats = xdpbackend.RateLimitHitStats

type RateLimitRuleHit = xdpbackend.RateLimitRuleHit

type ProtocolDistribution = xdpbackend.ProtocolDistribution

type ProtocolStats = xdpbackend.ProtocolStats

type StatsCache = xdpbackend.StatsCache

type MapCounts = xdpbackend.MapCounts

type counterProvider interface {
	GetDropCount() (uint64, error)
	GetPassCount() (uint64, error)
}

type detailProvider interface {
	GetDropDetails() ([]sdk.DropDetailEntry, error)
	GetPassDetails() ([]sdk.DropDetailEntry, error)
}

type managerAccessor interface {
	GetManager() *xdpbackend.Manager
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
	case *xdpbackend.Manager:
		return datapathprograms.WrapExisting(typed)
	case managerAccessor:
		return datapathprograms.WrapExisting(typed.GetManager())
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
