package xdp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/livp123/netxfw/pkg/sdk"
)

// BenchmarkIPPortRuleKeyConstruction benchmarks the key construction for IP+Port rules.
// BenchmarkIPPortRuleKeyConstruction 基准测试 IP+端口规则的键构造。
func BenchmarkIPPortRuleKeyConstruction(b *testing.B) {
	_, ipNet, _ := net.ParseCIDR("192.168.20.0/24")
	port := uint16(80)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ones, _ := ipNet.Mask.Size()
		var key NetXfwLpmIpPortKey
		key.Port = port
		key.Prefixlen = uint32(96 + ones)
		key.Ip.In6U.U6Addr8[10] = 0xff
		key.Ip.In6U.U6Addr8[11] = 0xff
		copy(key.Ip.In6U.U6Addr8[12:], ipNet.IP.To4())
		_ = key
	}
}

// BenchmarkIPPortRuleKeyConstructionIPv6 benchmarks the key construction for IPv6 IP+Port rules.
// BenchmarkIPPortRuleKeyConstructionIPv6 基准测试 IPv6 IP+端口规则的键构造。
func BenchmarkIPPortRuleKeyConstructionIPv6(b *testing.B) {
	_, ipNet, _ := net.ParseCIDR("2001:db8::/32")
	port := uint16(443)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ones, _ := ipNet.Mask.Size()
		var key NetXfwLpmIpPortKey
		key.Port = port
		key.Prefixlen = uint32(ones)
		copy(key.Ip.In6U.U6Addr8[:], ipNet.IP.To16())
		_ = key
	}
}

// BenchmarkLpmKeyConstruction benchmarks the LPM key construction.
// BenchmarkLpmKeyConstruction 基准测试 LPM 键构造。
func BenchmarkLpmKeyConstruction(b *testing.B) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ones, _ := ipNet.Mask.Size()
		var key NetXfwLpmKey
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			key.Prefixlen = uint32(96 + ones)
			key.Data.In6U.U6Addr8[10] = 0xff
			key.Data.In6U.U6Addr8[11] = 0xff
			copy(key.Data.In6U.U6Addr8[12:], ip4)
		}
		_ = key
	}
}

// BenchmarkRateLimitKeyConstruction benchmarks the rate limit key construction.
// BenchmarkRateLimitKeyConstruction 基准测试限速键构造。
func BenchmarkRateLimitKeyConstruction(b *testing.B) {
	_, ipNet, _ := net.ParseCIDR("192.168.13.100/32")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ones, _ := ipNet.Mask.Size()
		var key NetXfwLpmKey
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			key.Prefixlen = uint32(96 + ones)
			key.Data.In6U.U6Addr8[10] = 0xff
			key.Data.In6U.U6Addr8[11] = 0xff
			copy(key.Data.In6U.U6Addr8[12:], ip4)
		}
		_ = key
	}
}

// BenchmarkMapCountCalculation benchmarks the map count calculation logic.
// BenchmarkMapCountCalculation 基准测试 Map 计数计算逻辑。
func BenchmarkMapCountCalculation(b *testing.B) {
	counts := MapCounts{
		Blacklist:        1000,
		Whitelist:        500,
		Conntrack:        5000,
		DynamicBlacklist: 300,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		total := counts.Blacklist + counts.Whitelist + counts.Conntrack + counts.DynamicBlacklist
		_ = total
	}
}

// BenchmarkProtocolStatsUpdate benchmarks protocol statistics update.
// BenchmarkProtocolStatsUpdate 基准测试协议统计更新。
func BenchmarkProtocolStatsUpdate(b *testing.B) {
	stats := &ProtocolStats{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.Packets++
	}
}

// BenchmarkDropReasonStatsUpdate benchmarks drop reason statistics update.
// BenchmarkDropReasonStatsUpdate 基准测试丢弃原因统计更新。
func BenchmarkDropReasonStatsUpdate(b *testing.B) {
	reasons := make(map[uint32]uint64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reason := uint32(i % 20)
		reasons[reason]++
	}
}

// BenchmarkIPConversion benchmarks IP address conversion.
// BenchmarkIPConversion 基准测试 IP 地址转换。
func BenchmarkIPConversion(b *testing.B) {
	ips := []string{
		"192.168.19.1",
		"10.0.0.1",
		"172.16.0.1",
		"2001:db8::1",
		"::1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := net.ParseIP(ips[i%len(ips)])
		_ = ip
	}
}

// BenchmarkCIDRParsing benchmarks CIDR parsing.
// BenchmarkCIDRParsing 基准测试 CIDR 解析。
func BenchmarkCIDRParsing(b *testing.B) {
	cidrs := []string{
		"192.168.18.0/24",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"2001:db8::/32",
		"::/0",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ipNet, err := net.ParseCIDR(cidrs[i%len(cidrs)])
		if err != nil {
			b.Fatal(err)
		}
		_ = ipNet
	}
}

// BenchmarkIPv4ToIPv6Mapping benchmarks IPv4 to IPv6 mapping.
// BenchmarkIPv4ToIPv6Mapping 基准测试 IPv4 到 IPv6 映射。
func BenchmarkIPv4ToIPv6Mapping(b *testing.B) {
	ip4 := net.ParseIP("192.168.1.1").To4()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var ipv6 [16]byte
		ipv6[10] = 0xff
		ipv6[11] = 0xff
		copy(ipv6[12:], ip4)
		_ = ipv6
	}
}

// BenchmarkMapUsageCalculation benchmarks map usage percentage calculation.
// BenchmarkMapUsageCalculation 基准测试 Map 使用率计算。
func BenchmarkMapUsageCalculation(b *testing.B) {
	stats := MapUsageStats{
		TotalMaps:     6,
		TotalEntries:  5000,
		TotalCapacity: 100000,
		OverallUsage:  5,
		HealthyMaps:   4,
		WarningMaps:   2,
		CriticalMaps:  0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		avgUsage := stats.OverallUsage / stats.TotalMaps
		_ = avgUsage
	}
}

// BenchmarkHealthCheckStatus benchmarks health check status creation.
// BenchmarkHealthCheckStatus 基准测试健康检查状态创建。
func BenchmarkHealthCheckStatus(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status := HealthStatus{
			Uptime:        "1h0m0s",
			BPFMaps:       make(map[string]MapHealthStatus),
			OverallStatus: "ok",
			TotalMaps:     6,
			HealthyMaps:   4,
			WarningMaps:   2,
			CriticalMaps:  0,
			TotalEntries:  5000,
		}
		status.BPFMaps["blacklist"] = MapHealthStatus{
			Name:       "blacklist",
			Type:       "hash",
			Entries:    1000,
			MaxEntries: 10000,
			UsagePct:   10,
			Status:     "ok",
			Message:    "healthy",
		}
		_ = status
	}
}

// BenchmarkFormatMapSize benchmarks map size formatting.
// BenchmarkFormatMapSize 基准测试 Map 大小格式化。
func BenchmarkFormatMapSize(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000, 1000000}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		size := sizes[i%len(sizes)]
		_ = fmt.Sprintf("%d entries", size)
	}
}

// BenchmarkMapOperationLatencyRecording benchmarks latency recording for map operations.
// BenchmarkMapOperationLatencyRecording 基准测试 Map 操作延迟记录。
func BenchmarkMapOperationLatencyRecording(b *testing.B) {
	ps := NewPerformanceStats()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ps.RecordMapOperation("blacklist", "add", uint64(i%10000), false)
	}
}

// BenchmarkMapOperationLatencyWithPercentile benchmarks latency percentile calculation.
// BenchmarkMapOperationLatencyWithPercentile 基准测试延迟百分位计算。
func BenchmarkMapOperationLatencyWithPercentile(b *testing.B) {
	ps := NewPerformanceStats()
	for i := 0; i < 1000; i++ {
		ps.RecordMapOperation("blacklist", "add", uint64(i*100), false)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ps.GetStats()
	}
}

// BenchmarkNewLpmKey benchmarks LPM key creation using utility function.
// BenchmarkNewLpmKey 基准测试使用工具函数创建 LPM 键。
func BenchmarkNewLpmKey(b *testing.B) {
	cidrs := []string{
		"192.168.17.0/24",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"2001:db8::/32",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewLpmKey(cidrs[i%len(cidrs)])
	}
}

// BenchmarkNewLpmIPPortKey benchmarks LPM IP+Port key creation using utility function.
// BenchmarkNewLpmIPPortKey 基准测试使用工具函数创建 LPM IP+端口键。
func BenchmarkNewLpmIPPortKey(b *testing.B) {
	cidrs := []string{
		"192.168.16.0/24",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"2001:db8::/32",
	}
	ports := []uint16{80, 443, 22, 3306}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewLpmIPPortKey(cidrs[i%len(cidrs)], ports[i%len(ports)])
	}
}

// BenchmarkFormatLpmKey benchmarks LPM key formatting.
// BenchmarkFormatLpmKey 基准测试 LPM 键格式化。
func BenchmarkFormatLpmKey(b *testing.B) {
	key, _ := NewLpmKey("192.168.15.0/24")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatLpmKey(&key)
	}
}

// BenchmarkMapUsageDetailCreation benchmarks MapUsageDetail creation.
// BenchmarkMapUsageDetailCreation 基准测试 MapUsageDetail 创建。
func BenchmarkMapUsageDetailCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detail := MapUsageDetail{
			Name:       "blacklist",
			Type:       "hash",
			Entries:    1000,
			MaxEntries: 10000,
			UsagePct:   10,
			Status:     "ok",
			Message:    "healthy",
		}
		_ = detail
	}
}

// BenchmarkTrafficMetricsUpdate benchmarks traffic metrics update.
// BenchmarkTrafficMetricsUpdate 基准测试流量指标更新。
func BenchmarkTrafficMetricsUpdate(b *testing.B) {
	metrics := &TrafficMetrics{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.TotalPackets++
		metrics.TotalBytes += 1500
	}
}

// BenchmarkConntrackHealthUpdate benchmarks conntrack health update.
// BenchmarkConntrackHealthUpdate 基准测试连接跟踪健康状态更新。
func BenchmarkConntrackHealthUpdate(b *testing.B) {
	health := &ConntrackHealth{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		health.ActiveConnections++
		health.NewConnections++
	}
}

// BenchmarkRateLimitHitStatsUpdate benchmarks rate limit hit stats update.
// BenchmarkRateLimitHitStatsUpdate 基准测试限速命中统计更新。
func BenchmarkRateLimitHitStatsUpdate(b *testing.B) {
	stats := &RateLimitHitStats{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.TotalHits++
		stats.TotalDropped++
	}
}

// BenchmarkProtocolDistributionUpdate benchmarks protocol distribution update.
// BenchmarkProtocolDistributionUpdate 基准测试协议分布更新。
func BenchmarkProtocolDistributionUpdate(b *testing.B) {
	dist := &ProtocolDistribution{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proto := uint8(i % 4)
		switch proto {
		case 6:
			dist.TCP.Packets++
		case 17:
			dist.UDP.Packets++
		case 1:
			dist.ICMP.Packets++
		default:
			dist.Other.Packets++
		}
	}
}

// BenchmarkMapHealthStatusCreation benchmarks MapHealthStatus creation.
// BenchmarkMapHealthStatusCreation 基准测试 MapHealthStatus 创建。
func BenchmarkMapHealthStatusCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status := MapHealthStatus{
			Name:       "blacklist",
			Type:       "hash",
			Entries:    1000,
			MaxEntries: 10000,
			UsagePct:   10,
			Status:     "ok",
			Message:    "healthy",
		}
		_ = status
	}
}

// BenchmarkGlobalStatsUpdate benchmarks global stats update.
// BenchmarkGlobalStatsUpdate 基准测试全局统计更新。
func BenchmarkGlobalStatsUpdate(b *testing.B) {
	stats := &GlobalStats{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.TotalPackets++
		stats.TotalDrop++
	}
}

// BenchmarkDropDetailEntryCreation benchmarks DropDetailEntry creation.
// BenchmarkDropDetailEntryCreation 基准测试 DropDetailEntry 创建。
func BenchmarkDropDetailEntryCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry := sdk.DropDetailEntry{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.1",
			DstIP:     "10.0.0.1",
			SrcPort:   12345,
			DstPort:   80,
		}
		_ = entry
	}
}

// BenchmarkRateLimitRuleHitCreation benchmarks RateLimitRuleHit creation.
// BenchmarkRateLimitRuleHitCreation 基准测试 RateLimitRuleHit 创建。
func BenchmarkRateLimitRuleHitCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hit := RateLimitRuleHit{
			CIDR:    "192.168.14.0/24",
			Rate:    1000,
			Burst:   2000,
			Hits:    1000,
			Dropped: 500,
			Passed:  500,
			HitRate: "10.5",
			LastHit: "2024-01-01T00:00:00Z",
		}
		_ = hit
	}
}
