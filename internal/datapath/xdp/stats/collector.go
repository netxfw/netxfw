package stats

import (
	"fmt"

	xdpbackend "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend"
	statsbridge "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend/statsbridge"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type MetricsCollector = statsbridge.Collector

type MetricsData = statsbridge.MetricsData

type TrafficMetrics = statsbridge.TrafficMetrics

type ConntrackHealth = statsbridge.ConntrackHealth

type MapUsageStats = statsbridge.MapUsageStats

type MapUsageDetail = statsbridge.MapUsageDetail

type RateLimitHitStats = statsbridge.RateLimitHitStats

type RateLimitRuleHit = statsbridge.RateLimitRuleHit

type ProtocolDistribution = statsbridge.ProtocolDistribution

type ProtocolStats = statsbridge.ProtocolStats

type StatsCache = statsbridge.Cache

type MapCounts = statsbridge.MapCounts

type counterProvider interface {
	GetDropCount() (uint64, error)
	GetPassCount() (uint64, error)
}

type detailProvider interface {
	GetDropDetails() ([]sdk.DropDetailEntry, error)
	GetPassDetails() ([]sdk.DropDetailEntry, error)
}

type managerAccessor interface {
	GetManagerHandle() *xdpbackend.Handle
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
	case *xdpbackend.Handle:
		return datapathprograms.WrapExisting(typed)
	case managerAccessor:
		return datapathprograms.WrapExisting(typed.GetManagerHandle())
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
