package xdp

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// PerformanceStats holds performance monitoring statistics.
// PerformanceStats 保存性能监控统计信息。
type PerformanceStats struct {
	mu sync.RWMutex

	// Map operation latency statistics / Map 操作延迟统计
	MapLatency MapLatencyStats `json:"map_latency"`

	// Cache hit rate statistics / 缓存命中率统计
	CacheHitRate CacheHitRateStats `json:"cache_hit_rate"`

	// Real-time traffic statistics / 实时流量统计
	Traffic TrafficStats `json:"traffic"`

	// Start time for uptime calculation / 启动时间用于计算运行时间
	StartTime time.Time `json:"start_time"`
}

// MapLatencyStats holds latency statistics for map operations.
// MapLatencyStats 保存 Map 操作的延迟统计。
type MapLatencyStats struct {
	// Operation counts / 操作计数
	TotalOperations uint64 `json:"total_operations"` // Total map operations / 总 Map 操作数
	TotalErrors     uint64 `json:"total_errors"`     // Total errors / 总错误数

	// Latency tracking (in nanoseconds) / 延迟跟踪（纳秒）
	TotalLatencyNs uint64 `json:"total_latency_ns"` // Total latency in ns / 总延迟（纳秒）
	MinLatencyNs   uint64 `json:"min_latency_ns"`   // Minimum latency / 最小延迟
	MaxLatencyNs   uint64 `json:"max_latency_ns"`   // Maximum latency / 最大延迟

	// Average latency (calculated) / 平均延迟（计算得出）
	AvgLatencyNs uint64 `json:"avg_latency_ns"` // Average latency in ns / 平均延迟（纳秒）

	// Per-operation type statistics / 按操作类型统计
	ReadOps   OperationStats `json:"read_ops"`   // Read operations / 读操作
	WriteOps  OperationStats `json:"write_ops"`  // Write operations / 写操作
	DeleteOps OperationStats `json:"delete_ops"` // Delete operations / 删除操作
	IterOps   OperationStats `json:"iter_ops"`   // Iterate operations / 迭代操作

	// Per-map statistics / 按 Map 统计
	BlacklistOps OperationStats `json:"blacklist_ops"`
	WhitelistOps OperationStats `json:"whitelist_ops"`
	ConntrackOps OperationStats `json:"conntrack_ops"`
	RateLimitOps OperationStats `json:"rate_limit_ops"`
	RuleMapOps   OperationStats `json:"rule_map_ops"`
	StatsMapOps  OperationStats `json:"stats_map_ops"`
}

// OperationStats holds statistics for a specific operation type.
// OperationStats 保存特定操作类型的统计信息。
type OperationStats struct {
	Count        uint64 `json:"count"`         // Number of operations / 操作次数
	TotalLatency uint64 `json:"total_latency"` // Total latency in ns / 总延迟（纳秒）
	MinLatency   uint64 `json:"min_latency"`   // Minimum latency / 最小延迟
	MaxLatency   uint64 `json:"max_latency"`   // Maximum latency / 最大延迟
	AvgLatency   uint64 `json:"avg_latency"`   // Average latency / 平均延迟
	Errors       uint64 `json:"errors"`        // Number of errors / 错误次数
}

// CacheHitRateStats holds cache hit rate statistics.
// CacheHitRateStats 保存缓存命中率统计信息。
type CacheHitRateStats struct {
	// Global stats cache / 全局统计缓存
	GlobalStatsHits    uint64  `json:"global_stats_hits"`     // Cache hits / 缓存命中
	GlobalStatsMisses  uint64  `json:"global_stats_misses"`   // Cache misses / 缓存未命中
	GlobalStatsHitRate float64 `json:"global_stats_hit_rate"` // Hit rate (0-1) / 命中率（0-1）

	// Drop details cache / 丢弃详情缓存
	DropDetailsHits    uint64  `json:"drop_details_hits"`
	DropDetailsMisses  uint64  `json:"drop_details_misses"`
	DropDetailsHitRate float64 `json:"drop_details_hit_rate"`

	// Pass details cache / 通过详情缓存
	PassDetailsHits    uint64  `json:"pass_details_hits"`
	PassDetailsMisses  uint64  `json:"pass_details_misses"`
	PassDetailsHitRate float64 `json:"pass_details_hit_rate"`

	// Map counts cache / Map 计数缓存
	MapCountsHits    uint64  `json:"map_counts_hits"`
	MapCountsMisses  uint64  `json:"map_counts_misses"`
	MapCountsHitRate float64 `json:"map_counts_hit_rate"`

	// Total cache statistics / 总缓存统计
	TotalHits    uint64  `json:"total_hits"`
	TotalMisses  uint64  `json:"total_misses"`
	TotalHitRate float64 `json:"total_hit_rate"`
}

// TrafficStats holds real-time traffic statistics.
// TrafficStats 保存实时流量统计信息。
type TrafficStats struct {
	// Packet rates (packets per second) / 数据包速率（每秒数据包数）
	CurrentPPS uint64 `json:"current_pps"` // Current packets per second / 当前每秒数据包数
	PeakPPS    uint64 `json:"peak_pps"`    // Peak packets per second / 峰值每秒数据包数
	AveragePPS uint64 `json:"average_pps"` // Average packets per second / 平均每秒数据包数

	// Byte rates (bytes per second) / 字节速率（每秒字节数）
	CurrentBPS uint64 `json:"current_bps"` // Current bytes per second / 当前每秒字节数
	PeakBPS    uint64 `json:"peak_bps"`    // Peak bytes per second / 峰值每秒字节数
	AverageBPS uint64 `json:"average_bps"` // Average bytes per second / 平均每秒字节数

	// Drop rates / 丢弃速率
	CurrentDropPPS uint64 `json:"current_drop_pps"` // Current drops per second / 当前每秒丢弃数
	PeakDropPPS    uint64 `json:"peak_drop_pps"`    // Peak drops per second / 峰值每秒丢弃数

	// Pass rates / 通过速率
	CurrentPassPPS uint64 `json:"current_pass_pps"` // Current passes per second / 当前每秒通过数
	PeakPassPPS    uint64 `json:"peak_pass_pps"`    // Peak passes per second / 峰值每秒通过数

	// Time window for rate calculation / 速率计算的时间窗口
	LastUpdateTime time.Time `json:"last_update_time"`
	LastPackets    uint64    `json:"last_packets"`
	LastBytes      uint64    `json:"last_bytes"`
	LastDrops      uint64    `json:"last_drops"`
	LastPasses     uint64    `json:"last_passes"`

	// Uptime / 运行时间
	UptimeSeconds uint64 `json:"uptime_seconds"`
}

// NewPerformanceStats creates a new performance statistics tracker.
// NewPerformanceStats 创建新的性能统计跟踪器。
func NewPerformanceStats() *PerformanceStats {
	return &PerformanceStats{
		StartTime: time.Now(),
		MapLatency: MapLatencyStats{
			MinLatencyNs: ^uint64(0), // Set to max value initially / 初始设为最大值
			ReadOps:      OperationStats{MinLatency: ^uint64(0)},
			WriteOps:     OperationStats{MinLatency: ^uint64(0)},
			DeleteOps:    OperationStats{MinLatency: ^uint64(0)},
			IterOps:      OperationStats{MinLatency: ^uint64(0)},
			BlacklistOps: OperationStats{MinLatency: ^uint64(0)},
			WhitelistOps: OperationStats{MinLatency: ^uint64(0)},
			ConntrackOps: OperationStats{MinLatency: ^uint64(0)},
			RateLimitOps: OperationStats{MinLatency: ^uint64(0)},
			RuleMapOps:   OperationStats{MinLatency: ^uint64(0)},
			StatsMapOps:  OperationStats{MinLatency: ^uint64(0)},
		},
	}
}

// RecordMapOperation records a map operation with its latency.
// RecordMapOperation 记录 Map 操作及其延迟。
func (p *PerformanceStats) RecordMapOperation(mapName string, opType string, latencyNs uint64, hasError bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Update total statistics / 更新总计统计
	p.MapLatency.TotalOperations++
	p.MapLatency.TotalLatencyNs += latencyNs

	if hasError {
		p.MapLatency.TotalErrors++
	}

	// Update min/max / 更新最小/最大值
	if latencyNs < p.MapLatency.MinLatencyNs || p.MapLatency.MinLatencyNs == ^uint64(0) {
		p.MapLatency.MinLatencyNs = latencyNs
	}
	if latencyNs > p.MapLatency.MaxLatencyNs {
		p.MapLatency.MaxLatencyNs = latencyNs
	}

	// Calculate average / 计算平均值
	p.MapLatency.AvgLatencyNs = p.MapLatency.TotalLatencyNs / p.MapLatency.TotalOperations

	// Update per-operation type statistics / 更新按操作类型统计
	var opStats *OperationStats
	switch opType {
	case "read":
		opStats = &p.MapLatency.ReadOps
	case "write":
		opStats = &p.MapLatency.WriteOps
	case "delete":
		opStats = &p.MapLatency.DeleteOps
	case "iter":
		opStats = &p.MapLatency.IterOps
	}
	if opStats != nil {
		p.updateOpStats(opStats, latencyNs, hasError)
	}

	// Update per-map statistics / 更新按 Map 统计
	var mapStats *OperationStats
	switch mapName {
	case "blacklist", "static_blacklist", "dynamic_blacklist":
		mapStats = &p.MapLatency.BlacklistOps
	case "whitelist":
		mapStats = &p.MapLatency.WhitelistOps
	case "conntrack":
		mapStats = &p.MapLatency.ConntrackOps
	case "ratelimit":
		mapStats = &p.MapLatency.RateLimitOps
	case "rule_map":
		mapStats = &p.MapLatency.RuleMapOps
	case "stats_global", "top_drop", "top_pass":
		mapStats = &p.MapLatency.StatsMapOps
	}
	if mapStats != nil {
		p.updateOpStats(mapStats, latencyNs, hasError)
	}
}

// updateOpStats updates operation statistics.
// updateOpStats 更新操作统计。
func (p *PerformanceStats) updateOpStats(stats *OperationStats, latencyNs uint64, hasError bool) {
	stats.Count++
	stats.TotalLatency += latencyNs

	if hasError {
		stats.Errors++
	}

	if latencyNs < stats.MinLatency || stats.MinLatency == ^uint64(0) {
		stats.MinLatency = latencyNs
	}
	if latencyNs > stats.MaxLatency {
		stats.MaxLatency = latencyNs
	}

	stats.AvgLatency = stats.TotalLatency / stats.Count
}

// RecordCacheHit records a cache hit for the specified cache type.
// RecordCacheHit 记录指定缓存类型的命中。
func (p *PerformanceStats) RecordCacheHit(cacheType string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.CacheHitRate.TotalHits++

	switch cacheType {
	case "global_stats":
		p.CacheHitRate.GlobalStatsHits++
	case "drop_details":
		p.CacheHitRate.DropDetailsHits++
	case "pass_details":
		p.CacheHitRate.PassDetailsHits++
	case "map_counts":
		p.CacheHitRate.MapCountsHits++
	}

	p.updateCacheHitRates()
}

// RecordCacheMiss records a cache miss for the specified cache type.
// RecordCacheMiss 记录指定缓存类型的未命中。
func (p *PerformanceStats) RecordCacheMiss(cacheType string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.CacheHitRate.TotalMisses++

	switch cacheType {
	case "global_stats":
		p.CacheHitRate.GlobalStatsMisses++
	case "drop_details":
		p.CacheHitRate.DropDetailsMisses++
	case "pass_details":
		p.CacheHitRate.PassDetailsMisses++
	case "map_counts":
		p.CacheHitRate.MapCountsMisses++
	}

	p.updateCacheHitRates()
}

// updateCacheHitRates updates all cache hit rate calculations.
// updateCacheHitRates 更新所有缓存命中率计算。
func (p *PerformanceStats) updateCacheHitRates() {
	// Calculate total hit rate / 计算总命中率
	total := p.CacheHitRate.TotalHits + p.CacheHitRate.TotalMisses
	if total > 0 {
		p.CacheHitRate.TotalHitRate = float64(p.CacheHitRate.TotalHits) / float64(total)
	}

	// Calculate per-cache hit rates / 计算各缓存命中率
	if hits, misses := p.CacheHitRate.GlobalStatsHits, p.CacheHitRate.GlobalStatsMisses; hits+misses > 0 {
		p.CacheHitRate.GlobalStatsHitRate = float64(hits) / float64(hits+misses)
	}
	if hits, misses := p.CacheHitRate.DropDetailsHits, p.CacheHitRate.DropDetailsMisses; hits+misses > 0 {
		p.CacheHitRate.DropDetailsHitRate = float64(hits) / float64(hits+misses)
	}
	if hits, misses := p.CacheHitRate.PassDetailsHits, p.CacheHitRate.PassDetailsMisses; hits+misses > 0 {
		p.CacheHitRate.PassDetailsHitRate = float64(hits) / float64(hits+misses)
	}
	if hits, misses := p.CacheHitRate.MapCountsHits, p.CacheHitRate.MapCountsMisses; hits+misses > 0 {
		p.CacheHitRate.MapCountsHitRate = float64(hits) / float64(hits+misses)
	}
}

// UpdateTrafficStats updates real-time traffic statistics.
// UpdateTrafficStats 更新实时流量统计。
func (p *PerformanceStats) UpdateTrafficStats(totalPackets, totalBytes, totalDrops, totalPasses uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(p.Traffic.LastUpdateTime).Seconds()

	if elapsed > 0 && p.Traffic.LastUpdateTime.After(time.Time{}) {
		// Calculate rates / 计算速率
		packetsDiff := totalPackets - p.Traffic.LastPackets
		bytesDiff := totalBytes - p.Traffic.LastBytes
		dropsDiff := totalDrops - p.Traffic.LastDrops
		passesDiff := totalPasses - p.Traffic.LastPasses

		p.Traffic.CurrentPPS = uint64(float64(packetsDiff) / elapsed)
		p.Traffic.CurrentBPS = uint64(float64(bytesDiff) / elapsed)
		p.Traffic.CurrentDropPPS = uint64(float64(dropsDiff) / elapsed)
		p.Traffic.CurrentPassPPS = uint64(float64(passesDiff) / elapsed)

		// Update peaks / 更新峰值
		if p.Traffic.CurrentPPS > p.Traffic.PeakPPS {
			p.Traffic.PeakPPS = p.Traffic.CurrentPPS
		}
		if p.Traffic.CurrentBPS > p.Traffic.PeakBPS {
			p.Traffic.PeakBPS = p.Traffic.CurrentBPS
		}
		if p.Traffic.CurrentDropPPS > p.Traffic.PeakDropPPS {
			p.Traffic.PeakDropPPS = p.Traffic.CurrentDropPPS
		}
		if p.Traffic.CurrentPassPPS > p.Traffic.PeakPassPPS {
			p.Traffic.PeakPassPPS = p.Traffic.CurrentPassPPS
		}

		// Calculate average / 计算平均值
		uptime := now.Sub(p.StartTime).Seconds()
		if uptime > 0 {
			p.Traffic.AveragePPS = uint64(float64(totalPackets) / uptime)
			p.Traffic.AverageBPS = uint64(float64(totalBytes) / uptime)
		}
	}

	// Update tracking values / 更新跟踪值
	p.Traffic.LastUpdateTime = now
	p.Traffic.LastPackets = totalPackets
	p.Traffic.LastBytes = totalBytes
	p.Traffic.LastDrops = totalDrops
	p.Traffic.LastPasses = totalPasses
	p.Traffic.UptimeSeconds = uint64(now.Sub(p.StartTime).Seconds())
}

// GetStats returns a snapshot of all performance statistics.
// GetStats 返回所有性能统计的快照。
// Note: Returns a pointer to avoid copying the embedded mutex.
// 注意：返回指针以避免复制嵌入的互斥锁。
func (p *PerformanceStats) GetStats() *PerformanceStatsSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return &PerformanceStatsSnapshot{
		MapLatency:   p.MapLatency,
		CacheHitRate: p.CacheHitRate,
		Traffic:      p.Traffic,
		StartTime:    p.StartTime,
	}
}

// PerformanceStatsSnapshot is a snapshot of performance statistics without mutex.
// PerformanceStatsSnapshot 是不含互斥锁的性能统计快照。
type PerformanceStatsSnapshot struct {
	MapLatency   MapLatencyStats   `json:"map_latency"`
	CacheHitRate CacheHitRateStats `json:"cache_hit_rate"`
	Traffic      TrafficStats      `json:"traffic"`
	StartTime    time.Time         `json:"start_time"`
}

// GetLatencyStats returns a snapshot of map latency statistics.
// GetLatencyStats 返回 Map 延迟统计的快照。
func (p *PerformanceStats) GetLatencyStats() MapLatencyStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.MapLatency
}

// GetCacheStats returns a snapshot of cache hit rate statistics.
// GetCacheStats 返回缓存命中率统计的快照。
func (p *PerformanceStats) GetCacheStats() CacheHitRateStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.CacheHitRate
}

// GetTrafficStats returns a snapshot of traffic statistics.
// GetTrafficStats 返回流量统计的快照。
func (p *PerformanceStats) GetTrafficStats() TrafficStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Traffic
}

// Reset resets all performance statistics.
// Reset 重置所有性能统计。
func (p *PerformanceStats) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.MapLatency = MapLatencyStats{
		MinLatencyNs: ^uint64(0),
		ReadOps:      OperationStats{MinLatency: ^uint64(0)},
		WriteOps:     OperationStats{MinLatency: ^uint64(0)},
		DeleteOps:    OperationStats{MinLatency: ^uint64(0)},
		IterOps:      OperationStats{MinLatency: ^uint64(0)},
		BlacklistOps: OperationStats{MinLatency: ^uint64(0)},
		WhitelistOps: OperationStats{MinLatency: ^uint64(0)},
		ConntrackOps: OperationStats{MinLatency: ^uint64(0)},
		RateLimitOps: OperationStats{MinLatency: ^uint64(0)},
		RuleMapOps:   OperationStats{MinLatency: ^uint64(0)},
		StatsMapOps:  OperationStats{MinLatency: ^uint64(0)},
	}
	p.CacheHitRate = CacheHitRateStats{}
	p.Traffic = TrafficStats{}
	p.StartTime = time.Now()
}

const trafficStatsFile = "/var/run/netxfw_traffic_stats.json"

// SaveTrafficStats saves traffic statistics to a shared file.
// SaveTrafficStats 将流量统计保存到共享文件。
func (p *PerformanceStats) SaveTrafficStats() error {
	p.mu.RLock()
	data := p.Traffic
	p.mu.RUnlock()

	fileData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return os.WriteFile(trafficStatsFile, fileData, 0644)
}

// LoadTrafficStats loads traffic statistics from a shared file.
// LoadTrafficStats 从共享文件加载流量统计。
func LoadTrafficStats() (TrafficStats, error) {
	var stats TrafficStats

	data, err := os.ReadFile(trafficStatsFile)
	if err != nil {
		return stats, err
	}

	err = json.Unmarshal(data, &stats)
	return stats, err
}
