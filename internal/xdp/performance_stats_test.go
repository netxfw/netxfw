package xdp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewPerformanceStats tests creating a new performance stats tracker.
// TestNewPerformanceStats 测试创建新的性能统计跟踪器。
func TestNewPerformanceStats(t *testing.T) {
	stats := NewPerformanceStats()
	assert.NotNil(t, stats)
	assert.False(t, stats.StartTime.IsZero())
}

// TestRecordMapOperation tests recording map operations.
// TestRecordMapOperation 测试记录 Map 操作。
func TestRecordMapOperation(t *testing.T) {
	stats := NewPerformanceStats()

	// Record a read operation / 记录读操作
	stats.RecordMapOperation("blacklist", "read", 1000, false)

	assert.Equal(t, uint64(1), stats.MapLatency.TotalOperations)
	assert.Equal(t, uint64(1000), stats.MapLatency.TotalLatencyNs)
	assert.Equal(t, uint64(1000), stats.MapLatency.MinLatencyNs)
	assert.Equal(t, uint64(1000), stats.MapLatency.MaxLatencyNs)
	assert.Equal(t, uint64(0), stats.MapLatency.TotalErrors)

	// Check per-operation stats / 检查按操作统计
	assert.Equal(t, uint64(1), stats.MapLatency.ReadOps.Count)
	assert.Equal(t, uint64(1000), stats.MapLatency.ReadOps.TotalLatency)

	// Check per-map stats / 检查按 Map 统计
	assert.Equal(t, uint64(1), stats.MapLatency.BlacklistOps.Count)
}

// TestRecordMapOperationWithErrors tests recording operations with errors.
// TestRecordMapOperationWithErrors 测试记录带错误的操作。
func TestRecordMapOperationWithErrors(t *testing.T) {
	stats := NewPerformanceStats()

	// Record operation with error / 记录带错误的操作
	stats.RecordMapOperation("whitelist", "write", 2000, true)

	assert.Equal(t, uint64(1), stats.MapLatency.TotalOperations)
	assert.Equal(t, uint64(1), stats.MapLatency.TotalErrors)
	assert.Equal(t, uint64(1), stats.MapLatency.WriteOps.Errors)
	assert.Equal(t, uint64(1), stats.MapLatency.WhitelistOps.Errors)
}

// TestRecordMapOperationMinMax tests min/max latency tracking.
// TestRecordMapOperationMinMax 测试最小/最大延迟跟踪。
func TestRecordMapOperationMinMax(t *testing.T) {
	stats := NewPerformanceStats()

	// Record multiple operations with different latencies / 记录不同延迟的多个操作
	stats.RecordMapOperation("conntrack", "read", 500, false)
	stats.RecordMapOperation("conntrack", "read", 2000, false)
	stats.RecordMapOperation("conntrack", "read", 1000, false)

	assert.Equal(t, uint64(500), stats.MapLatency.MinLatencyNs)
	assert.Equal(t, uint64(2000), stats.MapLatency.MaxLatencyNs)
	assert.Equal(t, uint64(1166), stats.MapLatency.AvgLatencyNs) // (500+2000+1000)/3 = 1166
}

// TestRecordCacheHit tests recording cache hits.
// TestRecordCacheHit 测试记录缓存命中。
func TestRecordCacheHit(t *testing.T) {
	stats := NewPerformanceStats()

	stats.RecordCacheHit("global_stats")
	stats.RecordCacheHit("global_stats")
	stats.RecordCacheHit("drop_details")

	assert.Equal(t, uint64(2), stats.CacheHitRate.GlobalStatsHits)
	assert.Equal(t, uint64(1), stats.CacheHitRate.DropDetailsHits)
	assert.Equal(t, uint64(3), stats.CacheHitRate.TotalHits)
}

// TestRecordCacheMiss tests recording cache misses.
// TestRecordCacheMiss 测试记录缓存未命中。
func TestRecordCacheMiss(t *testing.T) {
	stats := NewPerformanceStats()

	stats.RecordCacheMiss("global_stats")
	stats.RecordCacheMiss("map_counts")

	assert.Equal(t, uint64(1), stats.CacheHitRate.GlobalStatsMisses)
	assert.Equal(t, uint64(1), stats.CacheHitRate.MapCountsMisses)
	assert.Equal(t, uint64(2), stats.CacheHitRate.TotalMisses)
}

// TestCacheHitRate tests cache hit rate calculation.
// TestCacheHitRate 测试缓存命中率计算。
func TestCacheHitRate(t *testing.T) {
	stats := NewPerformanceStats()

	// 3 hits, 1 miss = 75% hit rate / 3 次命中，1 次未命中 = 75% 命中率
	stats.RecordCacheHit("global_stats")
	stats.RecordCacheHit("global_stats")
	stats.RecordCacheHit("global_stats")
	stats.RecordCacheMiss("global_stats")

	assert.Equal(t, 0.75, stats.CacheHitRate.GlobalStatsHitRate)
	assert.Equal(t, 0.75, stats.CacheHitRate.TotalHitRate)
}

// TestUpdateTrafficStats tests traffic statistics update.
// TestUpdateTrafficStats 测试流量统计更新。
func TestUpdateTrafficStats(t *testing.T) {
	stats := NewPerformanceStats()

	// First update (no rate calculation) / 第一次更新（不计算速率）
	stats.UpdateTrafficStats(1000, 50000, 100, 900)

	// Wait a bit / 等待一会
	time.Sleep(100 * time.Millisecond)

	// Second update (rate calculation) / 第二次更新（计算速率）
	stats.UpdateTrafficStats(2000, 100000, 200, 1800)

	// Check that rates are calculated / 检查速率已计算
	assert.Greater(t, stats.Traffic.CurrentPPS, uint64(0))
	assert.Greater(t, stats.Traffic.CurrentBPS, uint64(0))
	assert.Equal(t, uint64(2000), stats.Traffic.LastPackets)
	assert.Equal(t, uint64(100000), stats.Traffic.LastBytes)
}

// TestGetStats tests getting stats snapshot.
// TestGetStats 测试获取统计快照。
func TestGetStats(t *testing.T) {
	stats := NewPerformanceStats()

	stats.RecordMapOperation("blacklist", "read", 1000, false)
	stats.RecordCacheHit("global_stats")

	snapshot := stats.GetStats()

	assert.Equal(t, uint64(1), snapshot.MapLatency.TotalOperations)
	assert.Equal(t, uint64(1), snapshot.CacheHitRate.TotalHits)
}

// TestReset tests resetting statistics.
// TestReset 测试重置统计。
func TestReset(t *testing.T) {
	stats := NewPerformanceStats()

	// Add some data / 添加一些数据
	stats.RecordMapOperation("blacklist", "read", 1000, false)
	stats.RecordCacheHit("global_stats")
	stats.UpdateTrafficStats(1000, 50000, 100, 900)

	// Reset / 重置
	stats.Reset()

	// Verify all stats are reset / 验证所有统计已重置
	assert.Equal(t, uint64(0), stats.MapLatency.TotalOperations)
	assert.Equal(t, uint64(0), stats.CacheHitRate.TotalHits)
	assert.Equal(t, uint64(0), stats.Traffic.LastPackets)
	assert.False(t, stats.StartTime.IsZero())
}

// TestOperationStats tests operation statistics.
// TestOperationStats 测试操作统计。
func TestOperationStats(t *testing.T) {
	stats := NewPerformanceStats()

	// Test different operation types / 测试不同操作类型
	stats.RecordMapOperation("blacklist", "read", 100, false)
	stats.RecordMapOperation("blacklist", "write", 200, false)
	stats.RecordMapOperation("blacklist", "delete", 150, false)
	stats.RecordMapOperation("blacklist", "iter", 300, false)

	assert.Equal(t, uint64(1), stats.MapLatency.ReadOps.Count)
	assert.Equal(t, uint64(1), stats.MapLatency.WriteOps.Count)
	assert.Equal(t, uint64(1), stats.MapLatency.DeleteOps.Count)
	assert.Equal(t, uint64(1), stats.MapLatency.IterOps.Count)
}

// TestPerMapStats tests per-map statistics.
// TestPerMapStats 测试按 Map 统计。
func TestPerMapStats(t *testing.T) {
	stats := NewPerformanceStats()

	// Test different maps / 测试不同 Map
	stats.RecordMapOperation("blacklist", "read", 100, false)
	stats.RecordMapOperation("whitelist", "read", 200, false)
	stats.RecordMapOperation("conntrack", "read", 150, false)
	stats.RecordMapOperation("ratelimit", "read", 250, false)
	stats.RecordMapOperation("rule_map", "read", 300, false)
	stats.RecordMapOperation("stats_global", "read", 350, false)

	assert.Equal(t, uint64(1), stats.MapLatency.BlacklistOps.Count)
	assert.Equal(t, uint64(1), stats.MapLatency.WhitelistOps.Count)
	assert.Equal(t, uint64(1), stats.MapLatency.ConntrackOps.Count)
	assert.Equal(t, uint64(1), stats.MapLatency.RateLimitOps.Count)
	assert.Equal(t, uint64(1), stats.MapLatency.RuleMapOps.Count)
	assert.Equal(t, uint64(1), stats.MapLatency.StatsMapOps.Count)
}

// TestTrafficPeakStats tests traffic peak statistics.
// TestTrafficPeakStats 测试流量峰值统计。
func TestTrafficPeakStats(t *testing.T) {
	stats := NewPerformanceStats()

	// First update / 第一次更新
	stats.UpdateTrafficStats(1000, 50000, 100, 900)
	time.Sleep(50 * time.Millisecond)

	// Second update with higher rate / 第二次更新，更高速率
	stats.UpdateTrafficStats(5000, 250000, 500, 4500)
	assert.Equal(t, stats.Traffic.CurrentPPS, stats.Traffic.PeakPPS)

	time.Sleep(50 * time.Millisecond)

	// Third update with lower rate / 第三次更新，更低速率
	stats.UpdateTrafficStats(6000, 300000, 600, 5400)
	// Peak should still be from second update / 峰值应该仍然是第二次更新
	assert.GreaterOrEqual(t, stats.Traffic.PeakPPS, stats.Traffic.CurrentPPS)
}
