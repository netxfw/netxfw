package agent

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/netxfw/netxfw/internal/application/services"
	"github.com/netxfw/netxfw/pkg/sdk"
)

/*
system_display.go - System Status Display Functions / 系统状态显示函数

Provides display functions for 'netxfw system status' command.
为 'netxfw system status' 命令提供显示函数。

Display Order / 显示顺序:
  1. Traffic Rate / 流量速率
  2. Drop Statistics / 丢弃统计
  3. Pass Statistics / 通过统计
  4. Protocol Distribution / 协议分布
  5. Conntrack Health / 连接跟踪健康度
  6. Map Statistics / BPF Map 统计
  7. Policy Configuration / 策略配置
  8. Attached Interfaces / 已附加接口
  9. Summary Statistics / 总结统计
*/

func showStatus(ctx context.Context, w io.Writer, s *sdk.SDK) error {
	_ = ctx
	fmt.Fprintln(w, "[OK] XDP Program Status: Loaded and Running")

	mgr := s.GetManager()
	pass, drops, err := s.Stats.GetCounters()
	if err != nil {
		fmt.Fprintf(w, "[WARN]  Could not retrieve statistics: %v\n", err)
		return nil
	}

	showDropStatistics(w, s.Stats, drops, pass)
	showPassStatistics(w, s.Stats, pass, drops)
	showProtocolDistribution(w, s.Stats, pass, drops)
	showConntrackHealth(w, mgr)
	showPolicyConfiguration(w)
	showConclusionStatistics(w, mgr, s.Stats)
	showMapStatistics(w, mgr)
	showTrafficMetrics(w, pass, drops)
	showAttachedInterfaces(w)

	return nil
}

func showPolicyConfiguration(w io.Writer) {
	cfg, err := systemQueryService.LoadConfig()
	if err != nil || cfg == nil {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[CONFIG]  Policy Configuration:")

	items := []struct {
		icon  string
		name  string
		value string
	}{
		{"SHIELD", "Default Deny", boolStr(cfg.Base.DefaultDeny, "Enabled (Deny by default)", "Disabled (Allow by default)")},
		{"RELOAD", "Allow Return Traffic", boolStr(cfg.Base.AllowReturnTraffic, "Enabled", "Disabled")},
		{"PING", "Allow ICMP (Ping)", boolStr(cfg.Base.AllowICMP, "Enabled", "Disabled")},
		{"LOCK", "Strict TCP", boolStr(cfg.Base.StrictTCP, "Enabled", "Disabled")},
		{"PROTECT", "SYN Flood Protection", boolStr(cfg.Base.SYNLimit, "Enabled", "Disabled")},
		{"WEB", "Bogon Filter", boolStr(cfg.Base.BogonFilter, "Enabled", "Disabled")},
	}

	for i, item := range items {
		printConfigItem(w, item.icon, item.name, item.value, i == len(items)-1)
	}

	printConntrackConfig(w, cfg)
	printRateLimitConfig(w, cfg)
	printLogEngineConfig(w, cfg)
	printWebConfig(w, cfg)
}

func showAttachedInterfaces(w io.Writer) {
	fmt.Fprintln(w, "\n[LINK] Attached Interfaces:")
	ifaceInfos, err := systemQueryService.GetAttachedInterfaceInfos()
	if err != nil || len(ifaceInfos) == 0 {
		fmt.Fprintln(w, "  - None")
		return
	}

	for _, info := range ifaceInfos {
		uptime := "N/A"
		if !info.LoadTime.IsZero() {
			uptime = systemQueryService.FormatDuration(time.Since(info.LoadTime))
		}
		fmt.Fprintf(w, "  - %s (Mode: %s, ProgID: %d, Uptime: %s)\n", info.Name, info.Mode, info.ProgramID, uptime)
	}
}

func showTrafficMetrics(w io.Writer, pass, drops uint64) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[RATE] Traffic Rate:")

	total := pass + drops
	fmt.Fprintf(w, "   ├─ Total RX: %s packets\n", systemQueryService.FormatNumberWithComma(total))
	fmt.Fprintf(w, "   ├─ Total Pass: %s (%.2f%%)\n", systemQueryService.FormatNumberWithComma(pass), calculatePercentGeneric(pass, total))
	fmt.Fprintf(w, "   ├─ Total Drop: %s (%.2f%%)\n", systemQueryService.FormatNumberWithComma(drops), calculatePercentGeneric(drops, total))

	trafficStats, err := systemQueryService.LoadTrafficStats()
	if err != nil || !trafficStats.LastUpdateTime.After(time.Time{}) || (trafficStats.CurrentPPS == 0 && trafficStats.CurrentBPS == 0) {
		fmt.Fprintln(w, "   └─ Real-time rates: Unavailable (daemon not running)")
		return
	}

	pps := trafficStats.CurrentPPS
	var dropRate, passRate float64
	if pps > 0 {
		dropRate = float64(trafficStats.CurrentDropPPS) / float64(pps) * 100
		passRate = float64(trafficStats.CurrentPassPPS) / float64(pps) * 100
	}

	fmt.Fprintf(w, "   ├─ PPS: %s pkt/s\n", systemQueryService.FormatNumberWithComma(pps))
	fmt.Fprintf(w, "   ├─ BPS: %s\n", systemQueryService.FormatBPS(trafficStats.CurrentBPS))
	fmt.Fprintf(w, "   ├─ Pass PPS: %s pkt/s (%.2f%%)\n", systemQueryService.FormatNumberWithComma(trafficStats.CurrentPassPPS), passRate)
	fmt.Fprintf(w, "   └─ Drop PPS: %s pkt/s (%.2f%%)\n", systemQueryService.FormatNumberWithComma(trafficStats.CurrentDropPPS), dropRate)
}

func showConntrackHealth(w io.Writer, mgr sdk.ManagerInterface) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[TRACK]  Conntrack Health:")

	count, err := mgr.GetConntrackCount()
	if err != nil {
		fmt.Fprintln(w, "   └─ Status: Unavailable")
		return
	}

	maxVal := getConntrackMax()
	entries, _ := mgr.ListAllConntrackEntries()

	fmt.Fprintf(w, "   ├─ Active Connections: %d / %d (%.1f%%)\n", count, maxVal, calculatePercentGeneric(count, uint64(maxVal)))

	if entries != nil {
		tcp, udp, icmp, other := getConntrackProtocolStats(entries)
		fmt.Fprintf(w, "   ├─ TCP: %d (%.1f%%)  UDP: %d (%.1f%%)  ICMP: %d (%.1f%%)  Other: %d\n",
			tcp, calculatePercentGeneric(uint64(tcp), uint64(count)),
			udp, calculatePercentGeneric(uint64(udp), uint64(count)),
			icmp, calculatePercentGeneric(uint64(icmp), uint64(count)),
			other)
	}

	trafficStats, err := systemQueryService.LoadTrafficStats()
	hasRate := err == nil && trafficStats.LastUpdateTime.After(time.Time{})
	if hasRate {
		fmt.Fprintf(w, "   ├─ New/s: %s  Evict/s: %s\n",
			systemQueryService.FormatNumberWithComma(trafficStats.CurrentConntrackNew),
			systemQueryService.FormatNumberWithComma(trafficStats.CurrentConntrackEvict))
	}

	fmt.Fprintf(w, "   └─ %s\n", getConntrackHealthStatus(uint64(count), uint64(maxVal), hasRate, trafficStats))
}

func getConntrackMax() int {
	return systemQueryService.GetConntrackMax()
}

func getConntrackProtocolStats(entries []sdk.ConntrackEntry) (tcp, udp, icmp, other int) {
	for _, e := range entries {
		switch e.Protocol {
		case 6:
			tcp++
		case 17:
			udp++
		case 1:
			icmp++
		default:
			other++
		}
	}
	return
}

func getConntrackHealthStatus(count, maxVal uint64, hasRate bool, stats services.TrafficStats) string {
	usage := calculatePercentGeneric(count, maxVal)
	critical, high, _ := getThresholdsFromConfig()

	switch {
	case hasRate && stats.CurrentConntrackEvict > uint64(maxVal/10):
		return "[WARN]  Status: STRESSED - High eviction rate"
	case usage >= 99.9:
		return "[OK] Status: Healthy (LRU Full)"
	case usage >= float64(critical):
		return "[WARN]  Status: CRITICAL - Near capacity"
	case usage >= float64(high):
		return "[WARN]  Status: HIGH - Approaching capacity"
	default:
		return "[OK] Status: Healthy"
	}
}

func showProtocolDistribution(w io.Writer, s StatsAPI, pass, drops uint64) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[PROTO] Protocol Distribution:")

	dropDetails, err := s.GetDropDetails()
	if err != nil {
		fmt.Fprintln(w, "   └─ Status: Unavailable")
		return
	}
	passDetails, err := s.GetPassDetails()
	if err != nil {
		fmt.Fprintln(w, "   └─ Status: Unavailable")
		return
	}

	protoStats := make(map[uint8]struct{ dropped, passed uint64 })
	for _, d := range dropDetails {
		stats := protoStats[d.Protocol]
		stats.dropped += d.Count
		protoStats[d.Protocol] = stats
	}
	for _, p := range passDetails {
		stats := protoStats[p.Protocol]
		stats.passed += p.Count
		protoStats[p.Protocol] = stats
	}

	if len(protoStats) == 0 {
		fmt.Fprintln(w, "   └─ No protocol data available")
		return
	}

	fmt.Fprintf(w, "   %-10s %-15s %-15s %-10s\n", "Protocol", "Dropped", "Passed", "Percent")
	fmt.Fprintf(w, "   %s\n", strings.Repeat("-", 50))

	type stat struct {
		proto                  uint8
		dropped, passed, total uint64
	}
	stats := make([]stat, 0, len(protoStats))
	for p, s := range protoStats {
		stats = append(stats, stat{p, s.dropped, s.passed, s.dropped + s.passed})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].total > stats[j].total })

	total := pass + drops
	for _, s := range stats {
		fmt.Fprintf(w, "   %-10s %-15d %-15d %.1f%%\n", protocolToString(s.proto), s.dropped, s.passed, calculatePercentGeneric(s.total, total))
	}
}

func boolStr(cond bool, trueVal, falseVal string) string {
	if cond {
		return trueVal
	}
	return falseVal
}

func printConfigItem(w io.Writer, icon, name, value string, last bool) {
	prefix := "   ├─"
	if last {
		prefix = "   └─"
	}
	fmt.Fprintf(w, "%s [%s] %s: %s\n", prefix, icon, name, value)
}

func printConntrackConfig(w io.Writer, cfg *sdk.GlobalConfig) {
	if cfg.Conntrack.Enabled {
		fmt.Fprintf(w, "   ├─ [TRACK]  Connection Tracking: Enabled")
		if cfg.Conntrack.TCPTimeout != "" {
			fmt.Fprintf(w, " (TCP: %s", cfg.Conntrack.TCPTimeout)
			if cfg.Conntrack.UDPTimeout != "" {
				fmt.Fprintf(w, ", UDP: %s", cfg.Conntrack.UDPTimeout)
			}
			fmt.Fprint(w, ")")
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, "   ├─ [TRACK]  Connection Tracking: Disabled")
	}
}

func printRateLimitConfig(w io.Writer, cfg *sdk.GlobalConfig) {
	if cfg.RateLimit.Enabled {
		fmt.Fprintf(w, "   ├─ [START] Rate Limiting: Enabled")
		if cfg.RateLimit.AutoBlock {
			fmt.Fprintf(w, " (Auto Block: %s)", cfg.RateLimit.AutoBlockExpiry)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, "   ├─ [START] Rate Limiting: Disabled")
	}
}

func printLogEngineConfig(w io.Writer, cfg *sdk.GlobalConfig) {
	if cfg.LogEngine.Enabled {
		fmt.Fprintf(w, "   ├─ [LOG] Log Engine: Enabled (%d rules)\n", len(cfg.LogEngine.Rules))
	} else {
		fmt.Fprintln(w, "   ├─ [LOG] Log Engine: Disabled")
	}
}

func printWebConfig(w io.Writer, cfg *sdk.GlobalConfig) {
	if cfg.Web.Enabled {
		fmt.Fprintf(w, "   └─ [WEB] Web Interface: Enabled (Port: %d)\n", cfg.Web.Port)
	} else {
		fmt.Fprintln(w, "   └─ [WEB] Web Interface: Disabled")
	}
}
