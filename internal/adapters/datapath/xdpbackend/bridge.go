package xdpbackend

import (
	"github.com/cilium/ebpf"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

type Manager = backendxdp.Manager
type Adapter = backendxdp.Adapter
type InterfaceXDPInfo = backendxdp.InterfaceXDPInfo

type PerformanceStats = backendxdp.PerformanceStats
type PerformanceStatsSnapshot = backendxdp.PerformanceStatsSnapshot
type MapLatencyStats = backendxdp.MapLatencyStats
type OperationStats = backendxdp.OperationStats
type CacheHitRateStats = backendxdp.CacheHitRateStats
type TrafficStats = backendxdp.TrafficStats

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

type MapHealthStatus = backendxdp.MapHealthStatus
type HealthStatus = backendxdp.HealthStatus
type HealthChecker = backendxdp.HealthChecker

type ConfigDiff = backendxdp.ConfigDiff
type IncrementalUpdater = backendxdp.IncrementalUpdater

func NewManager(cfg sdk.CapacityConfig, log *zap.SugaredLogger) (*Manager, error) {
	return backendxdp.NewManager(cfg, log)
}

func NewManagerFromPins(pinPath string, log *zap.SugaredLogger) (*Manager, error) {
	return backendxdp.NewManagerFromPins(pinPath, log)
}

func NewAdapter(manager *Manager) *Adapter {
	return backendxdp.NewAdapter(manager)
}

func GetPhysicalInterfaces() ([]string, error) {
	return backendxdp.GetPhysicalInterfaces()
}

func GetAttachedInterfaces(pinPath string) ([]string, error) {
	return backendxdp.GetAttachedInterfaces(pinPath)
}

func GetAttachedInterfacesWithInfo(pinPath string) ([]InterfaceXDPInfo, error) {
	return backendxdp.GetAttachedInterfacesWithInfo(pinPath)
}

func NewMetricsCollector(manager *Manager) *MetricsCollector {
	return backendxdp.NewMetricsCollector(manager)
}

func NewStatsCache(manager *Manager) *StatsCache {
	return backendxdp.NewStatsCache(manager)
}

func NewHealthChecker(manager *Manager) *HealthChecker {
	return backendxdp.NewHealthChecker(manager)
}

func NewIncrementalUpdater(manager *Manager) *IncrementalUpdater {
	return backendxdp.NewIncrementalUpdater(manager)
}

func LoadTrafficStats() (TrafficStats, error) {
	return backendxdp.LoadTrafficStats()
}

func ClearBlacklistMap(mapPtr *ebpf.Map) error {
	return backendxdp.ClearBlacklistMap(mapPtr)
}

func CleanupExpiredRules(mapPtr *ebpf.Map, isIPv6 bool) (int, error) {
	return backendxdp.CleanupExpiredRules(mapPtr, isIPv6)
}
