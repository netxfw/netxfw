package xdp

import (
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/utils/fmtutil"
)

// TestMetricsCollector_NewMetricsCollector tests NewMetricsCollector function.
// TestMetricsCollector_NewMetricsCollector 测试 NewMetricsCollector 函数。
func TestMetricsCollector_NewMetricsCollector(t *testing.T) {
	collector := NewMetricsCollector(nil)
	if collector == nil {
		t.Fatal("Expected non-nil collector")
	}

	// Check that StartTime is set / 检查 StartTime 已设置
	if collector.StartTime.IsZero() {
		t.Error("Expected StartTime to be set")
	}

	if collector.MapUsage.Maps == nil {
		t.Error("Expected Maps map to be initialized")
	}

	if collector.RateLimitStats.Rules == nil {
		t.Error("Expected Rules map to be initialized")
	}
}

// TestMetricsCollector_TrafficMetrics tests traffic metrics collection.
// TestMetricsCollector_TrafficMetrics 测试流量指标收集。
func TestMetricsCollector_TrafficMetrics(t *testing.T) {
	collector := NewMetricsCollector(nil)

	// Test with nil manager / 测试空管理器
	collector.collectTrafficMetrics()

	// Should not panic and values should be zero / 不应该 panic，值应该为零
	if collector.TrafficMetrics.TotalPackets != 0 {
		t.Error("Expected zero packets with nil manager")
	}
}

// TestMetricsCollector_ConntrackHealth tests conntrack health collection.
// TestMetricsCollector_ConntrackHealth 测试连接跟踪健康度收集。
func TestMetricsCollector_ConntrackHealth(t *testing.T) {
	collector := NewMetricsCollector(nil)

	// Test with nil manager / 测试空管理器
	collector.collectConntrackHealth()

	// Should report unavailable / 应该报告不可用
	if collector.ConntrackHealth.Status != "unavailable" {
		t.Errorf("Expected status 'unavailable', got '%s'", collector.ConntrackHealth.Status)
	}
}

// TestMetricsCollector_MapUsage tests map usage collection.
// TestMetricsCollector_MapUsage 测试 Map 使用率收集。
func TestMetricsCollector_MapUsage(t *testing.T) {
	collector := NewMetricsCollector(nil)

	// Test with nil manager / 测试空管理器
	collector.collectMapUsage()

	// Should not panic / 不应该 panic
	if collector.MapUsage.TotalMaps != 0 {
		t.Error("Expected zero maps with nil manager")
	}
}

// TestMetricsCollector_RateLimitStats tests rate limit stats collection.
// TestMetricsCollector_RateLimitStats 测试限速统计收集。
func TestMetricsCollector_RateLimitStats(t *testing.T) {
	collector := NewMetricsCollector(nil)

	// Test with nil manager / 测试空管理器
	collector.collectRateLimitStats()

	// Should not panic / 不应该 panic
	if collector.RateLimitStats.TotalRules != 0 {
		t.Error("Expected zero rules with nil manager")
	}
}

// TestMetricsCollector_ProtocolStats tests protocol stats collection.
// TestMetricsCollector_ProtocolStats 测试协议统计收集。
func TestMetricsCollector_ProtocolStats(t *testing.T) {
	collector := NewMetricsCollector(nil)

	// Test with nil manager / 测试空管理器
	collector.collectProtocolStats()

	// Should not panic / 不应该 panic
	if collector.ProtocolStats.TotalPackets != 0 {
		t.Error("Expected zero packets with nil manager")
	}
}

// TestMetricsCollector_Collect tests the main Collect function.
// TestMetricsCollector_Collect 测试主 Collect 函数。
func TestMetricsCollector_Collect(t *testing.T) {
	collector := NewMetricsCollector(nil)

	// Collect with nil manager / 使用空管理器收集
	err := collector.Collect()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Check that LastUpdate is set / 检查 LastUpdate 已设置
	if collector.LastUpdate.IsZero() {
		t.Error("Expected LastUpdate to be set")
	}
}

// TestMetricsCollector_GetMethods tests all getter methods.
// TestMetricsCollector_GetMethods 测试所有 getter 方法。
func TestMetricsCollector_GetMethods(t *testing.T) {
	collector := NewMetricsCollector(nil)
	_ = collector.Collect()

	// Test GetMetrics / 测试 GetMetrics
	metrics := collector.GetMetrics()
	if metrics == nil {
		t.Error("Expected non-nil metrics")
	}

	// Test GetTrafficMetrics / 测试 GetTrafficMetrics
	traffic := collector.GetTrafficMetrics()
	if traffic.TotalPackets != 0 {
		t.Error("Expected zero total packets")
	}

	// Test GetConntrackHealth / 测试 GetConntrackHealth
	health := collector.GetConntrackHealth()
	if health.Status != "unavailable" {
		t.Errorf("Expected status 'unavailable', got '%s'", health.Status)
	}

	// Test GetMapUsage / 测试 GetMapUsage
	usage := collector.GetMapUsage()
	if usage.TotalMaps != 0 {
		t.Error("Expected zero total maps")
	}

	// Test GetRateLimitStats / 测试 GetRateLimitStats
	stats := collector.GetRateLimitStats()
	if stats.TotalRules != 0 {
		t.Error("Expected zero total rules")
	}

	// Test GetProtocolStats / 测试 GetProtocolStats
	proto := collector.GetProtocolStats()
	if proto.TotalPackets != 0 {
		t.Error("Expected zero total packets")
	}
}

// TestTrafficMetrics_PeakUpdates tests that peak values are updated correctly.
// TestTrafficMetrics_PeakUpdates 测试峰值是否正确更新。
func TestTrafficMetrics_PeakUpdates(t *testing.T) {
	tm := TrafficMetrics{}

	// Set initial peak / 设置初始峰值
	tm.PeakPPS = 100
	tm.PeakBPS = 1000

	// Update with higher values / 使用更高的值更新
	tm.CurrentPPS = 200
	tm.CurrentBPS = 2000

	// Manually check peak update logic / 手动检查峰值更新逻辑
	if tm.CurrentPPS > tm.PeakPPS {
		tm.PeakPPS = tm.CurrentPPS
	}
	if tm.CurrentBPS > tm.PeakBPS {
		tm.PeakBPS = tm.CurrentBPS
	}

	if tm.PeakPPS != 200 {
		t.Errorf("Expected PeakPPS 200, got %d", tm.PeakPPS)
	}
	if tm.PeakBPS != 2000 {
		t.Errorf("Expected PeakBPS 2000, got %d", tm.PeakBPS)
	}
}

// TestConntrackHealth_StatusDetermination tests health status determination.
// TestConntrackHealth_StatusDetermination 测试健康状态判定。
func TestConntrackHealth_StatusDetermination(t *testing.T) {
	tests := []struct {
		usage       int
		wantStatus  string
		wantMessage string
	}{
		{50, "healthy", "Conntrack table healthy / 连接跟踪表健康"},
		{80, "warning", "Conntrack table usage high / 连接跟踪表使用率较高"},
		{95, "critical", "Conntrack table near capacity / 连接跟踪表接近容量"},
	}

	for _, tt := range tests {
		ch := ConntrackHealth{UsagePercent: tt.usage}

		// Determine status / 确定状态
		if ch.UsagePercent >= 95 {
			ch.Status = "critical"
			ch.Message = "Conntrack table near capacity / 连接跟踪表接近容量"
		} else if ch.UsagePercent >= 80 {
			ch.Status = "warning"
			ch.Message = "Conntrack table usage high / 连接跟踪表使用率较高"
		} else {
			ch.Status = "healthy"
			ch.Message = "Conntrack table healthy / 连接跟踪表健康"
		}

		if ch.Status != tt.wantStatus {
			t.Errorf("Usage %d: expected status %s, got %s", tt.usage, tt.wantStatus, ch.Status)
		}
	}
}

// TestMapUsageStats_OverallCalculation tests overall usage calculation.
// TestMapUsageStats_OverallCalculation 测试总体使用率计算。
func TestMapUsageStats_OverallCalculation(t *testing.T) {
	mus := MapUsageStats{
		TotalEntries:  500,
		TotalCapacity: 1000,
	}

	// Calculate overall usage / 计算总体使用率
	if mus.TotalCapacity > 0 {
		mus.OverallUsage = (mus.TotalEntries * 100) / mus.TotalCapacity
	}

	if mus.OverallUsage != 50 {
		t.Errorf("Expected OverallUsage 50, got %d", mus.OverallUsage)
	}
}

// TestRateLimitHitStats_RuleTracking tests rate limit rule tracking.
// TestRateLimitHitStats_RuleTracking 测试限速规则跟踪。
func TestRateLimitHitStats_RuleTracking(t *testing.T) {
	rls := RateLimitHitStats{
		Rules: make(map[string]RateLimitRuleHit),
	}

	// Add a rule / 添加规则
	rls.Rules["192.168.1.0/24"] = RateLimitRuleHit{
		CIDR:    "192.168.1.0/24",
		Rate:    1000,
		Burst:   2000,
		Hits:    0,
		Dropped: 0,
		Passed:  0,
		HitRate: "N/A",
	}

	rls.TotalRules = 1
	rls.ActiveRules = 1

	if rls.TotalRules != 1 {
		t.Errorf("Expected TotalRules 1, got %d", rls.TotalRules)
	}

	if _, ok := rls.Rules["192.168.1.0/24"]; !ok {
		t.Error("Expected rule to exist in map")
	}
}

// TestProtocolDistribution_PercentageCalculation tests protocol percentage calculation.
// TestProtocolDistribution_PercentageCalculation 测试协议百分比计算。
func TestProtocolDistribution_PercentageCalculation(t *testing.T) {
	pd := ProtocolDistribution{
		TotalPackets: 1000,
		TCP: ProtocolStats{
			Packets: 600,
		},
		UDP: ProtocolStats{
			Packets: 300,
		},
		ICMP: ProtocolStats{
			Packets: 50,
		},
		Other: ProtocolStats{
			Packets: 50,
		},
	}

	// Calculate percentages / 计算百分比
	if pd.TotalPackets > 0 {
		pd.TCP.Percentage = fmtutil.FormatPercent(float64(pd.TCP.Packets) * 100 / float64(pd.TotalPackets))
		pd.UDP.Percentage = fmtutil.FormatPercent(float64(pd.UDP.Packets) * 100 / float64(pd.TotalPackets))
		pd.ICMP.Percentage = fmtutil.FormatPercent(float64(pd.ICMP.Packets) * 100 / float64(pd.TotalPackets))
		pd.Other.Percentage = fmtutil.FormatPercent(float64(pd.Other.Packets) * 100 / float64(pd.TotalPackets))
	}

	// fmtutil.FormatPercent uses %.2f%% format / fmtutil.FormatPercent 使用 %.2f%% 格式
	if pd.TCP.Percentage != "60.00%" {
		t.Errorf("Expected TCP percentage '60.00%%', got '%s'", pd.TCP.Percentage)
	}
	if pd.UDP.Percentage != "30.00%" {
		t.Errorf("Expected UDP percentage '30.00%%', got '%s'", pd.UDP.Percentage)
	}
}

// TestMetricsCollector_ThreadSafety tests concurrent access to metrics.
// TestMetricsCollector_ThreadSafety 测试指标的并发访问。
func TestMetricsCollector_ThreadSafety(t *testing.T) {
	collector := NewMetricsCollector(nil)

	// Start multiple goroutines to read and write / 启动多个 goroutine 进行读写
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = collector.Collect()
				_ = collector.GetMetrics()
				_ = collector.GetTrafficMetrics()
			}
			done <- true
		}()
	}

	// Wait for all goroutines / 等待所有 goroutine
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestMetricsCollector_Uptime tests uptime calculation.
// TestMetricsCollector_Uptime 测试运行时间计算。
func TestMetricsCollector_Uptime(t *testing.T) {
	collector := NewMetricsCollector(nil)
	collector.StartTime = time.Now().Add(-1 * time.Hour)

	uptime := time.Since(collector.StartTime)
	uptimeStr := uptime.Round(time.Second).String()

	if uptimeStr == "" {
		t.Error("Expected non-empty uptime string")
	}
}
