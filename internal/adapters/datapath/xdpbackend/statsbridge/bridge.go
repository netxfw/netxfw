package statsbridge

import (
	"encoding/json"
	"time"

	xdpbackend "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type Manager = xdpbackend.Handle

type OperationStats struct {
	Count        uint64 `json:"count"`
	TotalLatency uint64 `json:"total_latency"`
	MinLatency   uint64 `json:"min_latency"`
	MaxLatency   uint64 `json:"max_latency"`
	AvgLatency   uint64 `json:"avg_latency"`
	Errors       uint64 `json:"errors"`
}

type MapLatencyStats struct {
	TotalOperations uint64         `json:"total_operations"`
	TotalErrors     uint64         `json:"total_errors"`
	TotalLatencyNs  uint64         `json:"total_latency_ns"`
	MinLatencyNs    uint64         `json:"min_latency_ns"`
	MaxLatencyNs    uint64         `json:"max_latency_ns"`
	AvgLatencyNs    uint64         `json:"avg_latency_ns"`
	ReadOps         OperationStats `json:"read_ops"`
	WriteOps        OperationStats `json:"write_ops"`
	DeleteOps       OperationStats `json:"delete_ops"`
	IterOps         OperationStats `json:"iter_ops"`
	BlacklistOps    OperationStats `json:"blacklist_ops"`
	WhitelistOps    OperationStats `json:"whitelist_ops"`
	ConntrackOps    OperationStats `json:"conntrack_ops"`
	RateLimitOps    OperationStats `json:"rate_limit_ops"`
	RuleMapOps      OperationStats `json:"rule_map_ops"`
	StatsMapOps     OperationStats `json:"stats_map_ops"`
}

type CacheHitRateStats struct {
	GlobalStatsHits    uint64  `json:"global_stats_hits"`
	GlobalStatsMisses  uint64  `json:"global_stats_misses"`
	GlobalStatsHitRate float64 `json:"global_stats_hit_rate"`
	DropDetailsHits    uint64  `json:"drop_details_hits"`
	DropDetailsMisses  uint64  `json:"drop_details_misses"`
	DropDetailsHitRate float64 `json:"drop_details_hit_rate"`
	PassDetailsHits    uint64  `json:"pass_details_hits"`
	PassDetailsMisses  uint64  `json:"pass_details_misses"`
	PassDetailsHitRate float64 `json:"pass_details_hit_rate"`
	MapCountsHits      uint64  `json:"map_counts_hits"`
	MapCountsMisses    uint64  `json:"map_counts_misses"`
	MapCountsHitRate   float64 `json:"map_counts_hit_rate"`
	TotalHits          uint64  `json:"total_hits"`
	TotalMisses        uint64  `json:"total_misses"`
	TotalHitRate       float64 `json:"total_hit_rate"`
}

type TrafficStats struct {
	CurrentPPS            uint64    `json:"current_pps"`
	PeakPPS               uint64    `json:"peak_pps"`
	AveragePPS            uint64    `json:"average_pps"`
	CurrentBPS            uint64    `json:"current_bps"`
	PeakBPS               uint64    `json:"peak_bps"`
	AverageBPS            uint64    `json:"average_bps"`
	CurrentDropPPS        uint64    `json:"current_drop_pps"`
	PeakDropPPS           uint64    `json:"peak_drop_pps"`
	CurrentPassPPS        uint64    `json:"current_pass_pps"`
	PeakPassPPS           uint64    `json:"peak_pass_pps"`
	CurrentConntrackNew   uint64    `json:"current_conntrack_new"`
	CurrentConntrackEvict uint64    `json:"current_conntrack_evict"`
	LastConntrackCount    uint64    `json:"last_conntrack_count"`
	LastUpdateTime        time.Time `json:"last_update_time"`
	LastPackets           uint64    `json:"last_packets"`
	LastBytes             uint64    `json:"last_bytes"`
	LastDrops             uint64    `json:"last_drops"`
	LastPasses            uint64    `json:"last_passes"`
	UptimeSeconds         uint64    `json:"uptime_seconds"`
}

type PerformanceStatsSnapshot struct {
	MapLatency   MapLatencyStats   `json:"map_latency"`
	CacheHitRate CacheHitRateStats `json:"cache_hit_rate"`
	Traffic      TrafficStats      `json:"traffic"`
	StartTime    time.Time         `json:"start_time"`
}

type PerformanceStats struct {
	inner *backendxdp.PerformanceStats
}

type TrafficMetrics struct {
	CurrentPPS     uint64    `json:"current_pps"`
	CurrentBPS     uint64    `json:"current_bps"`
	PeakPPS        uint64    `json:"peak_pps"`
	PeakBPS        uint64    `json:"peak_bps"`
	AveragePPS     uint64    `json:"average_pps"`
	AverageBPS     uint64    `json:"average_bps"`
	CurrentDropPPS uint64    `json:"current_drop_pps"`
	PeakDropPPS    uint64    `json:"peak_drop_pps"`
	TotalDrops     uint64    `json:"total_drops"`
	CurrentPassPPS uint64    `json:"current_pass_pps"`
	PeakPassPPS    uint64    `json:"peak_pass_pps"`
	TotalPasses    uint64    `json:"total_passes"`
	TotalPackets   uint64    `json:"total_packets"`
	TotalBytes     uint64    `json:"total_bytes"`
	LastPackets    uint64    `json:"-"`
	LastBytes      uint64    `json:"-"`
	LastDrops      uint64    `json:"-"`
	LastPasses     uint64    `json:"-"`
	LastTime       time.Time `json:"-"`
}

type ConntrackHealth struct {
	CurrentEntries     int    `json:"current_entries"`
	MaxEntries         int    `json:"max_entries"`
	UsagePercent       int    `json:"usage_percent"`
	Status             string `json:"status"`
	Message            string `json:"message"`
	NewConnections     uint64 `json:"new_connections"`
	ExpiredConnections uint64 `json:"expired_connections"`
	ActiveConnections  uint64 `json:"active_connections"`
	TCPConnections     uint64 `json:"tcp_connections"`
	UDPConnections     uint64 `json:"udp_connections"`
	ICMPConnections    uint64 `json:"icmp_connections"`
	OtherConnections   uint64 `json:"other_connections"`
	TimeoutSeconds     uint64 `json:"timeout_seconds"`
	HashCollisions     uint64 `json:"hash_collisions"`
	LookupHits         uint64 `json:"lookup_hits"`
	LookupMisses       uint64 `json:"lookup_misses"`
}

type MapUsageDetail struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Entries    int    `json:"entries"`
	MaxEntries int    `json:"max_entries"`
	UsagePct   int    `json:"usage_pct"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}

type MapUsageStats struct {
	Maps          map[string]MapUsageDetail `json:"maps"`
	TotalMaps     int                       `json:"total_maps"`
	TotalEntries  int                       `json:"total_entries"`
	TotalCapacity int                       `json:"total_capacity"`
	OverallUsage  int                       `json:"overall_usage"`
	HealthyMaps   int                       `json:"healthy_maps"`
	WarningMaps   int                       `json:"warning_maps"`
	CriticalMaps  int                       `json:"critical_maps"`
}

type RateLimitRuleHit struct {
	CIDR    string `json:"cidr"`
	Rate    uint64 `json:"rate"`
	Burst   uint64 `json:"burst"`
	Hits    uint64 `json:"hits"`
	Dropped uint64 `json:"dropped"`
	Passed  uint64 `json:"passed"`
	HitRate string `json:"hit_rate"`
	LastHit string `json:"last_hit"`
}

type RateLimitHitStats struct {
	TotalRules     int                         `json:"total_rules"`
	ActiveRules    int                         `json:"active_rules"`
	TotalHits      uint64                      `json:"total_hits"`
	TotalDropped   uint64                      `json:"total_dropped"`
	TotalPassed    uint64                      `json:"total_passed"`
	CurrentHitRate string                      `json:"current_hit_rate"`
	AverageHitRate string                      `json:"average_hit_rate"`
	TopHitRules    []RateLimitRuleHit          `json:"top_hit_rules"`
	Rules          map[string]RateLimitRuleHit `json:"rules"`
}

type ProtocolStats struct {
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	Dropped    uint64 `json:"dropped"`
	Passed     uint64 `json:"passed"`
	Percentage string `json:"percentage"`
}

type ProtocolDistribution struct {
	TCP          ProtocolStats `json:"tcp"`
	UDP          ProtocolStats `json:"udp"`
	ICMP         ProtocolStats `json:"icmp"`
	Other        ProtocolStats `json:"other"`
	TotalPackets uint64        `json:"total_packets"`
	TotalBytes   uint64        `json:"total_bytes"`
	TCPPct       string        `json:"tcp_pct"`
	UDPPct       string        `json:"udp_pct"`
	ICMPPct      string        `json:"icmp_pct"`
	OtherPct     string        `json:"other_pct"`
}

type MetricsData struct {
	TrafficMetrics  TrafficMetrics       `json:"traffic_metrics"`
	ConntrackHealth ConntrackHealth      `json:"conntrack_health"`
	MapUsage        MapUsageStats        `json:"map_usage"`
	RateLimitStats  RateLimitHitStats    `json:"rate_limit_stats"`
	ProtocolStats   ProtocolDistribution `json:"protocol_stats"`
	StartTime       time.Time            `json:"start_time"`
	LastUpdate      time.Time            `json:"last_update"`
}

type MapCounts struct {
	Blacklist        uint64    `json:"blacklist"`
	Whitelist        uint64    `json:"whitelist"`
	Conntrack        uint64    `json:"conntrack"`
	DynamicBlacklist uint64    `json:"dynamic_blacklist"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type Collector struct {
	inner *backendxdp.MetricsCollector
}

type Cache struct {
	inner *backendxdp.StatsCache
}

func NewMetricsCollector(manager *Manager) *Collector {
	if manager == nil {
		return nil
	}
	return &Collector{inner: backendxdp.NewMetricsCollector(manager.BackendManager())}
}

func (c *Collector) Collect() error {
	if c == nil || c.inner == nil {
		return nil
	}
	return c.inner.Collect()
}

func (c *Collector) GetMetrics() *MetricsData {
	if c == nil || c.inner == nil {
		return nil
	}
	return convertMetricsData(c.inner.GetMetrics())
}

func (c *Collector) GetTrafficMetrics() TrafficMetrics {
	if c == nil || c.inner == nil {
		return TrafficMetrics{}
	}
	return convertTrafficMetrics(c.inner.GetTrafficMetrics())
}

func (c *Collector) GetConntrackHealth() ConntrackHealth {
	if c == nil || c.inner == nil {
		return ConntrackHealth{}
	}
	return convertConntrackHealth(c.inner.GetConntrackHealth())
}

func (c *Collector) GetMapUsage() MapUsageStats {
	if c == nil || c.inner == nil {
		return MapUsageStats{}
	}
	return convertMapUsageStats(c.inner.GetMapUsage())
}

func (c *Collector) GetRateLimitStats() RateLimitHitStats {
	if c == nil || c.inner == nil {
		return RateLimitHitStats{}
	}
	return convertRateLimitHitStats(c.inner.GetRateLimitStats())
}

func (c *Collector) GetProtocolStats() ProtocolDistribution {
	if c == nil || c.inner == nil {
		return ProtocolDistribution{}
	}
	return convertProtocolDistribution(c.inner.GetProtocolStats())
}

func NewStatsCache(manager *Manager) *Cache {
	if manager == nil {
		return nil
	}
	return &Cache{inner: backendxdp.NewStatsCache(manager.BackendManager())}
}

func (c *Cache) SetTTL(global, details, mapCounts time.Duration) {
	if c == nil || c.inner == nil {
		return
	}
	c.inner.SetTTL(global, details, mapCounts)
}

func (c *Cache) GetGlobalStats() (*sdk.GlobalStats, error) {
	if c == nil || c.inner == nil {
		return nil, nil
	}
	return c.inner.GetGlobalStats()
}

func (c *Cache) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	if c == nil || c.inner == nil {
		return nil, nil
	}
	return c.inner.GetDropDetails()
}

func (c *Cache) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	if c == nil || c.inner == nil {
		return nil, nil
	}
	return c.inner.GetPassDetails()
}

func (c *Cache) GetMapCounts() (MapCounts, error) {
	if c == nil || c.inner == nil {
		return MapCounts{}, nil
	}
	return convertMapCounts(c.inner.GetMapCounts())
}

func (c *Cache) InvalidateAll() {
	if c == nil || c.inner == nil {
		return
	}
	c.inner.InvalidateAll()
}

func (c *Cache) InvalidateGlobal() {
	if c == nil || c.inner == nil {
		return
	}
	c.inner.InvalidateGlobal()
}

func (c *Cache) InvalidateDetails() {
	if c == nil || c.inner == nil {
		return
	}
	c.inner.InvalidateDetails()
}

func (c *Cache) InvalidateMapCounts() {
	if c == nil || c.inner == nil {
		return
	}
	c.inner.InvalidateMapCounts()
}

func (c *Cache) GetCacheInfo() map[string]interface{} {
	if c == nil || c.inner == nil {
		return nil
	}
	return c.inner.GetCacheInfo()
}

func LoadTrafficStats() (TrafficStats, error) {
	stats, err := backendxdp.LoadTrafficStats()
	if err != nil {
		return TrafficStats{}, err
	}
	return convertTrafficStats(stats), nil
}

func WrapPerformanceStats(raw any) *PerformanceStats {
	switch typed := raw.(type) {
	case nil:
		return nil
	case *PerformanceStats:
		return typed
	case *backendxdp.PerformanceStats:
		return &PerformanceStats{inner: typed}
	default:
		return nil
	}
}

func (p *PerformanceStats) GetStats() *PerformanceStatsSnapshot {
	if p == nil || p.inner == nil {
		return nil
	}
	return convertPerformanceStatsSnapshot(p.inner.GetStats())
}

func (p *PerformanceStats) GetLatencyStats() any {
	if p == nil || p.inner == nil {
		return nil
	}
	return convertMapLatencyStats(p.inner.GetLatencyStats())
}

func (p *PerformanceStats) GetCacheStats() any {
	if p == nil || p.inner == nil {
		return nil
	}
	return convertCacheHitRateStats(p.inner.GetCacheStats())
}

func (p *PerformanceStats) GetTrafficStats() any {
	if p == nil || p.inner == nil {
		return nil
	}
	return convertTrafficStats(p.inner.GetTrafficStats())
}

func (p *PerformanceStats) Reset() {
	if p == nil || p.inner == nil {
		return
	}
	p.inner.Reset()
}

func (p *PerformanceStats) UpdateTrafficStats(totalPackets, totalBytes, totalDrops, totalPasses uint64) {
	if p == nil || p.inner == nil {
		return
	}
	p.inner.UpdateTrafficStats(totalPackets, totalBytes, totalDrops, totalPasses)
}

func (p *PerformanceStats) UpdateConntrackStats(currentCount uint64) {
	if p == nil || p.inner == nil {
		return
	}
	p.inner.UpdateConntrackStats(currentCount)
}

func (p *PerformanceStats) SaveTrafficStats() error {
	if p == nil || p.inner == nil {
		return nil
	}
	return p.inner.SaveTrafficStats()
}

func (p *PerformanceStats) MarshalJSON() ([]byte, error) {
	return marshalSnapshot(p.GetStats())
}

func convertMetricsData(data *backendxdp.MetricsData) *MetricsData {
	if data == nil {
		return nil
	}
	return &MetricsData{
		TrafficMetrics:  convertTrafficMetrics(data.TrafficMetrics),
		ConntrackHealth: convertConntrackHealth(data.ConntrackHealth),
		MapUsage:        convertMapUsageStats(data.MapUsage),
		RateLimitStats:  convertRateLimitHitStats(data.RateLimitStats),
		ProtocolStats:   convertProtocolDistribution(data.ProtocolStats),
		StartTime:       data.StartTime,
		LastUpdate:      data.LastUpdate,
	}
}

func marshalSnapshot(snapshot *PerformanceStatsSnapshot) ([]byte, error) {
	type alias PerformanceStatsSnapshot
	return json.Marshal((*alias)(snapshot))
}

func convertTrafficMetrics(data backendxdp.TrafficMetrics) TrafficMetrics {
	return TrafficMetrics{
		CurrentPPS:     data.CurrentPPS,
		CurrentBPS:     data.CurrentBPS,
		PeakPPS:        data.PeakPPS,
		PeakBPS:        data.PeakBPS,
		AveragePPS:     data.AveragePPS,
		AverageBPS:     data.AverageBPS,
		CurrentDropPPS: data.CurrentDropPPS,
		PeakDropPPS:    data.PeakDropPPS,
		TotalDrops:     data.TotalDrops,
		CurrentPassPPS: data.CurrentPassPPS,
		PeakPassPPS:    data.PeakPassPPS,
		TotalPasses:    data.TotalPasses,
		TotalPackets:   data.TotalPackets,
		TotalBytes:     data.TotalBytes,
		LastPackets:    data.LastPackets,
		LastBytes:      data.LastBytes,
		LastDrops:      data.LastDrops,
		LastPasses:     data.LastPasses,
		LastTime:       data.LastTime,
	}
}

func convertConntrackHealth(data backendxdp.ConntrackHealth) ConntrackHealth {
	return ConntrackHealth{
		CurrentEntries:     data.CurrentEntries,
		MaxEntries:         data.MaxEntries,
		UsagePercent:       data.UsagePercent,
		Status:             data.Status,
		Message:            data.Message,
		NewConnections:     data.NewConnections,
		ExpiredConnections: data.ExpiredConnections,
		ActiveConnections:  data.ActiveConnections,
		TCPConnections:     data.TCPConnections,
		UDPConnections:     data.UDPConnections,
		ICMPConnections:    data.ICMPConnections,
		OtherConnections:   data.OtherConnections,
		TimeoutSeconds:     data.TimeoutSeconds,
		HashCollisions:     data.HashCollisions,
		LookupHits:         data.LookupHits,
		LookupMisses:       data.LookupMisses,
	}
}

func convertMapUsageStats(data backendxdp.MapUsageStats) MapUsageStats {
	maps := make(map[string]MapUsageDetail, len(data.Maps))
	for name, detail := range data.Maps {
		maps[name] = MapUsageDetail{
			Name:       detail.Name,
			Type:       detail.Type,
			Entries:    detail.Entries,
			MaxEntries: detail.MaxEntries,
			UsagePct:   detail.UsagePct,
			Status:     detail.Status,
			Message:    detail.Message,
		}
	}

	return MapUsageStats{
		Maps:          maps,
		TotalMaps:     data.TotalMaps,
		TotalEntries:  data.TotalEntries,
		TotalCapacity: data.TotalCapacity,
		OverallUsage:  data.OverallUsage,
		HealthyMaps:   data.HealthyMaps,
		WarningMaps:   data.WarningMaps,
		CriticalMaps:  data.CriticalMaps,
	}
}

func convertRateLimitHitStats(data backendxdp.RateLimitHitStats) RateLimitHitStats {
	rules := make(map[string]RateLimitRuleHit, len(data.Rules))
	for cidr, rule := range data.Rules {
		rules[cidr] = RateLimitRuleHit{
			CIDR:    rule.CIDR,
			Rate:    rule.Rate,
			Burst:   rule.Burst,
			Hits:    rule.Hits,
			Dropped: rule.Dropped,
			Passed:  rule.Passed,
			HitRate: rule.HitRate,
			LastHit: rule.LastHit,
		}
	}

	topHitRules := make([]RateLimitRuleHit, 0, len(data.TopHitRules))
	for _, rule := range data.TopHitRules {
		topHitRules = append(topHitRules, RateLimitRuleHit{
			CIDR:    rule.CIDR,
			Rate:    rule.Rate,
			Burst:   rule.Burst,
			Hits:    rule.Hits,
			Dropped: rule.Dropped,
			Passed:  rule.Passed,
			HitRate: rule.HitRate,
			LastHit: rule.LastHit,
		})
	}

	return RateLimitHitStats{
		TotalRules:     data.TotalRules,
		ActiveRules:    data.ActiveRules,
		TotalHits:      data.TotalHits,
		TotalDropped:   data.TotalDropped,
		TotalPassed:    data.TotalPassed,
		CurrentHitRate: data.CurrentHitRate,
		AverageHitRate: data.AverageHitRate,
		TopHitRules:    topHitRules,
		Rules:          rules,
	}
}

func convertProtocolDistribution(data backendxdp.ProtocolDistribution) ProtocolDistribution {
	return ProtocolDistribution{
		TCP:          convertProtocolStats(data.TCP),
		UDP:          convertProtocolStats(data.UDP),
		ICMP:         convertProtocolStats(data.ICMP),
		Other:        convertProtocolStats(data.Other),
		TotalPackets: data.TotalPackets,
		TotalBytes:   data.TotalBytes,
		TCPPct:       data.TCPPct,
		UDPPct:       data.UDPPct,
		ICMPPct:      data.ICMPPct,
		OtherPct:     data.OtherPct,
	}
}

func convertProtocolStats(data backendxdp.ProtocolStats) ProtocolStats {
	return ProtocolStats{
		Packets:    data.Packets,
		Bytes:      data.Bytes,
		Dropped:    data.Dropped,
		Passed:     data.Passed,
		Percentage: data.Percentage,
	}
}

func convertMapCounts(data backendxdp.MapCounts, err error) (MapCounts, error) {
	if err != nil {
		return MapCounts{}, err
	}
	return MapCounts{
		Blacklist:        data.Blacklist,
		Whitelist:        data.Whitelist,
		Conntrack:        data.Conntrack,
		DynamicBlacklist: data.DynamicBlacklist,
		UpdatedAt:        data.UpdatedAt,
	}, nil
}

func convertPerformanceStatsSnapshot(data *backendxdp.PerformanceStatsSnapshot) *PerformanceStatsSnapshot {
	if data == nil {
		return nil
	}
	return &PerformanceStatsSnapshot{
		MapLatency:   convertMapLatencyStats(data.MapLatency),
		CacheHitRate: convertCacheHitRateStats(data.CacheHitRate),
		Traffic:      convertTrafficStats(data.Traffic),
		StartTime:    data.StartTime,
	}
}

func convertMapLatencyStats(data backendxdp.MapLatencyStats) MapLatencyStats {
	return MapLatencyStats{
		TotalOperations: data.TotalOperations,
		TotalErrors:     data.TotalErrors,
		TotalLatencyNs:  data.TotalLatencyNs,
		MinLatencyNs:    data.MinLatencyNs,
		MaxLatencyNs:    data.MaxLatencyNs,
		AvgLatencyNs:    data.AvgLatencyNs,
		ReadOps:         convertOperationStats(data.ReadOps),
		WriteOps:        convertOperationStats(data.WriteOps),
		DeleteOps:       convertOperationStats(data.DeleteOps),
		IterOps:         convertOperationStats(data.IterOps),
		BlacklistOps:    convertOperationStats(data.BlacklistOps),
		WhitelistOps:    convertOperationStats(data.WhitelistOps),
		ConntrackOps:    convertOperationStats(data.ConntrackOps),
		RateLimitOps:    convertOperationStats(data.RateLimitOps),
		RuleMapOps:      convertOperationStats(data.RuleMapOps),
		StatsMapOps:     convertOperationStats(data.StatsMapOps),
	}
}

func convertOperationStats(data backendxdp.OperationStats) OperationStats {
	return OperationStats{
		Count:        data.Count,
		TotalLatency: data.TotalLatency,
		MinLatency:   data.MinLatency,
		MaxLatency:   data.MaxLatency,
		AvgLatency:   data.AvgLatency,
		Errors:       data.Errors,
	}
}

func convertCacheHitRateStats(data backendxdp.CacheHitRateStats) CacheHitRateStats {
	return CacheHitRateStats{
		GlobalStatsHits:    data.GlobalStatsHits,
		GlobalStatsMisses:  data.GlobalStatsMisses,
		GlobalStatsHitRate: data.GlobalStatsHitRate,
		DropDetailsHits:    data.DropDetailsHits,
		DropDetailsMisses:  data.DropDetailsMisses,
		DropDetailsHitRate: data.DropDetailsHitRate,
		PassDetailsHits:    data.PassDetailsHits,
		PassDetailsMisses:  data.PassDetailsMisses,
		PassDetailsHitRate: data.PassDetailsHitRate,
		MapCountsHits:      data.MapCountsHits,
		MapCountsMisses:    data.MapCountsMisses,
		MapCountsHitRate:   data.MapCountsHitRate,
		TotalHits:          data.TotalHits,
		TotalMisses:        data.TotalMisses,
		TotalHitRate:       data.TotalHitRate,
	}
}

func convertTrafficStats(data backendxdp.TrafficStats) TrafficStats {
	return TrafficStats{
		CurrentPPS:            data.CurrentPPS,
		PeakPPS:               data.PeakPPS,
		AveragePPS:            data.AveragePPS,
		CurrentBPS:            data.CurrentBPS,
		PeakBPS:               data.PeakBPS,
		AverageBPS:            data.AverageBPS,
		CurrentDropPPS:        data.CurrentDropPPS,
		PeakDropPPS:           data.PeakDropPPS,
		CurrentPassPPS:        data.CurrentPassPPS,
		PeakPassPPS:           data.PeakPassPPS,
		CurrentConntrackNew:   data.CurrentConntrackNew,
		CurrentConntrackEvict: data.CurrentConntrackEvict,
		LastConntrackCount:    data.LastConntrackCount,
		LastUpdateTime:        data.LastUpdateTime,
		LastPackets:           data.LastPackets,
		LastBytes:             data.LastBytes,
		LastDrops:             data.LastDrops,
		LastPasses:            data.LastPasses,
		UptimeSeconds:         data.UptimeSeconds,
	}
}
