package xdp

import (
	"testing"
	"time"
)

// BenchmarkNewPerformanceStats benchmarks PerformanceStats creation.
// BenchmarkNewPerformanceStats 基准测试 PerformanceStats 创建。
func BenchmarkNewPerformanceStats(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewPerformanceStats()
	}
}

// BenchmarkPerformanceStats_RecordMapOperation benchmarks map operation recording.
// BenchmarkPerformanceStats_RecordMapOperation 基准测试 Map 操作记录。
func BenchmarkPerformanceStats_RecordMapOperation(b *testing.B) {
	ps := NewPerformanceStats()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ps.RecordMapOperation("blacklist", "add", 10000, false)
	}
}

// BenchmarkPerformanceStats_RecordMapOperation_WithError benchmarks map operation recording with error.
// BenchmarkPerformanceStats_RecordMapOperation_WithError 基准测试带错误的 Map 操作记录。
func BenchmarkPerformanceStats_RecordMapOperation_WithError(b *testing.B) {
	ps := NewPerformanceStats()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ps.RecordMapOperation("blacklist", "add", 10000, true)
	}
}

// BenchmarkPerformanceStats_GetStats benchmarks stats retrieval.
// BenchmarkPerformanceStats_GetStats 基准测试统计检索。
func BenchmarkPerformanceStats_GetStats(b *testing.B) {
	ps := NewPerformanceStats()
	ps.RecordMapOperation("blacklist", "add", 10000, false)
	ps.RecordMapOperation("whitelist", "add", 15000, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ps.GetStats()
	}
}

// BenchmarkPerformanceStats_Reset benchmarks stats reset.
// BenchmarkPerformanceStats_Reset 基准测试统计重置。
func BenchmarkPerformanceStats_Reset(b *testing.B) {
	ps := NewPerformanceStats()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ps.Reset()
	}
}

// BenchmarkPerformanceStats_ConcurrentRecord benchmarks concurrent recording.
// BenchmarkPerformanceStats_ConcurrentRecord 基准测试并发记录。
func BenchmarkPerformanceStats_ConcurrentRecord(b *testing.B) {
	ps := NewPerformanceStats()

	maps := []string{"blacklist", "whitelist", "rules", "ports"}
	ops := []string{"add", "remove", "lookup"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapName := maps[i%len(maps)]
		opType := ops[(i/len(maps))%len(ops)]
		ps.RecordMapOperation(mapName, opType, uint64(i%10000), false)
	}
}

// BenchmarkPerformanceStats_ConcurrentRead benchmarks concurrent stats reading.
// BenchmarkPerformanceStats_ConcurrentRead 基准测试并发统计读取。
func BenchmarkPerformanceStats_ConcurrentRead(b *testing.B) {
	ps := NewPerformanceStats()
	ps.RecordMapOperation("blacklist", "add", 10000, false)
	ps.RecordMapOperation("whitelist", "add", 15000, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ps.GetStats()
	}
}

// BenchmarkPerformanceStats_MixedOperations benchmarks mixed read/write operations.
// BenchmarkPerformanceStats_MixedOperations 基准测试混合读写操作。
func BenchmarkPerformanceStats_MixedOperations(b *testing.B) {
	ps := NewPerformanceStats()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			ps.RecordMapOperation("blacklist", "add", uint64(i%10000), false)
		} else {
			_ = ps.GetStats()
		}
	}
}

// BenchmarkPerformanceStats_ManyOperations benchmarks with many operations.
// BenchmarkPerformanceStats_ManyOperations 基准测试大量操作。
func BenchmarkPerformanceStats_ManyOperations(b *testing.B) {
	ps := NewPerformanceStats()

	maps := []string{"blacklist", "whitelist", "rules", "ports", "conntrack"}
	ops := []string{"add", "remove", "lookup", "update"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapName := maps[i%len(maps)]
		opType := ops[(i/len(maps))%len(ops)]
		ps.RecordMapOperation(mapName, opType, uint64(i%10000), i%100 == 0)
	}
}

// BenchmarkPerformanceStats_GetLatencyStats benchmarks latency stats calculation.
// BenchmarkPerformanceStats_GetLatencyStats 基准测试延迟统计计算。
func BenchmarkPerformanceStats_GetLatencyStats(b *testing.B) {
	ps := NewPerformanceStats()
	for i := 0; i < 1000; i++ {
		ps.RecordMapOperation("blacklist", "add", uint64(i%1000), false)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ps.GetStats()
	}
}

// BenchmarkTimeSinceNano benchmarks time.Since for nanosecond precision.
// BenchmarkTimeSinceNano 基准测试 time.Since 的纳秒精度。
func BenchmarkTimeSinceNano(b *testing.B) {
	start := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uint64(time.Since(start).Nanoseconds())
	}
}
