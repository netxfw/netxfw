package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/fmtutil"
	"github.com/netxfw/netxfw/internal/xdp"
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

func showStatus(ctx context.Context, s *sdk.SDK) error {
	fmt.Println("[OK] XDP Program Status: Loaded and Running")

	mgr := s.GetManager()
	pass, drops, err := s.Stats.GetCounters()
	if err != nil {
		fmt.Printf("[WARN]  Could not retrieve statistics: %v\n", err)
		return nil
	}

	showTrafficMetrics(pass, drops)
	showDropStatistics(s.Stats, drops, pass)
	showPassStatistics(s.Stats, pass, drops)
	showProtocolDistribution(s.Stats, pass, drops)
	showConntrackHealth(mgr)
	showMapStatistics(mgr)
	showPolicyConfiguration()
	showAttachedInterfaces()
	showConclusionStatistics(mgr, s.Stats)

	return nil
}

func showPolicyConfiguration() {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err != nil {
		return
	}

	cfg := cfgManager.GetConfig()
	if cfg == nil {
		return
	}

	fmt.Println()
	fmt.Println("[CONFIG]  Policy Configuration:")

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
		printConfigItem(item.icon, item.name, item.value, i == len(items)-1)
	}

	printConntrackConfig(cfg)
	printRateLimitConfig(cfg)
	printLogEngineConfig(cfg)
	printWebConfig(cfg)
}

func showAttachedInterfaces() {
	fmt.Println("\n[LINK] Attached Interfaces:")
	ifaceInfos, err := xdp.GetAttachedInterfacesWithInfo(config.GetPinPath())
	if err != nil || len(ifaceInfos) == 0 {
		fmt.Println("  - None")
		return
	}

	for _, info := range ifaceInfos {
		uptime := "N/A"
		if !info.LoadTime.IsZero() {
			uptime = fmtutil.FormatDuration(time.Since(info.LoadTime))
		}
		fmt.Printf("  - %s (Mode: %s, ProgID: %d, Uptime: %s)\n", info.Name, info.Mode, info.ProgramID, uptime)
	}
}

func showTrafficMetrics(pass, drops uint64) {
	fmt.Println()
	fmt.Println("[RATE] Traffic Rate:")

	total := pass + drops
	fmt.Printf("   ├─ Total RX: %s packets\n", fmtutil.FormatNumberWithComma(total))
	fmt.Printf("   ├─ Total Pass: %s (%.2f%%)\n", fmtutil.FormatNumberWithComma(pass), calculatePercentGeneric(pass, total))
	fmt.Printf("   ├─ Total Drop: %s (%.2f%%)\n", fmtutil.FormatNumberWithComma(drops), calculatePercentGeneric(drops, total))

	trafficStats, err := xdp.LoadTrafficStats()
	if err != nil || !trafficStats.LastUpdateTime.After(time.Time{}) || (trafficStats.CurrentPPS == 0 && trafficStats.CurrentBPS == 0) {
		fmt.Println("   └─ Real-time rates: Unavailable (daemon not running)")
		return
	}

	pps := trafficStats.CurrentPPS
	var dropRate, passRate float64
	if pps > 0 {
		dropRate = float64(trafficStats.CurrentDropPPS) / float64(pps) * 100
		passRate = float64(trafficStats.CurrentPassPPS) / float64(pps) * 100
	}

	fmt.Printf("   ├─ PPS: %s pkt/s\n", fmtutil.FormatNumberWithComma(pps))
	fmt.Printf("   ├─ BPS: %s\n", fmtutil.FormatBPS(trafficStats.CurrentBPS))
	fmt.Printf("   ├─ Pass PPS: %s pkt/s (%.2f%%)\n", fmtutil.FormatNumberWithComma(trafficStats.CurrentPassPPS), passRate)
	fmt.Printf("   └─ Drop PPS: %s pkt/s (%.2f%%)\n", fmtutil.FormatNumberWithComma(trafficStats.CurrentDropPPS), dropRate)
}

func showConntrackHealth(mgr sdk.ManagerInterface) {
	fmt.Println()
	fmt.Println("[TRACK]  Conntrack Health:")

	count, err := mgr.GetConntrackCount()
	if err != nil {
		fmt.Println("   └─ Status: Unavailable")
		return
	}

	maxVal := getConntrackMax()
	entries, _ := mgr.ListAllConntrackEntries()

	fmt.Printf("   ├─ Active Connections: %d / %d (%.1f%%)\n", count, maxVal, calculatePercentGeneric(count, uint64(maxVal)))

	if entries != nil {
		tcp, udp, icmp, other := getConntrackProtocolStats(entries)
		fmt.Printf("   ├─ TCP: %d (%.1f%%)  UDP: %d (%.1f%%)  ICMP: %d (%.1f%%)  Other: %d\n",
			tcp, calculatePercentGeneric(uint64(tcp), uint64(count)),
			udp, calculatePercentGeneric(uint64(udp), uint64(count)),
			icmp, calculatePercentGeneric(uint64(icmp), uint64(count)),
			other)
	}

	trafficStats, err := xdp.LoadTrafficStats()
	hasRate := err == nil && trafficStats.LastUpdateTime.After(time.Time{})
	if hasRate {
		fmt.Printf("   ├─ New/s: %s  Evict/s: %s\n",
			fmtutil.FormatNumberWithComma(trafficStats.CurrentConntrackNew),
			fmtutil.FormatNumberWithComma(trafficStats.CurrentConntrackEvict))
	}

	fmt.Printf("   └─ %s\n", getConntrackHealthStatus(uint64(count), uint64(maxVal), hasRate, trafficStats))
}

func getConntrackMax() int {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err == nil {
		if cfg := cfgManager.GetCapacityConfig(); cfg != nil && cfg.Conntrack > 0 {
			return cfg.Conntrack
		}
	}
	return 100000
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

func getConntrackHealthStatus(count, maxVal uint64, hasRate bool, stats xdp.TrafficStats) string {
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

func showProtocolDistribution(s StatsAPI, pass, drops uint64) {
	fmt.Println()
	fmt.Println("[PROTO] Protocol Distribution:")

	dropDetails, err := s.GetDropDetails()
	if err != nil {
		fmt.Println("   └─ Status: Unavailable")
		return
	}
	passDetails, err := s.GetPassDetails()
	if err != nil {
		fmt.Println("   └─ Status: Unavailable")
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
		fmt.Println("   └─ No protocol data available")
		return
	}

	fmt.Printf("   %-10s %-15s %-15s %-10s\n", "Protocol", "Dropped", "Passed", "Percent")
	fmt.Printf("   %s\n", strings.Repeat("-", 50))

	type stat struct {
		proto                  uint8
		dropped, passed, total uint64
	}
	var stats []stat
	for p, s := range protoStats {
		stats = append(stats, stat{p, s.dropped, s.passed, s.dropped + s.passed})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].total > stats[j].total })

	total := pass + drops
	for _, s := range stats {
		fmt.Printf("   %-10s %-15d %-15d %.1f%%\n", protocolToString(s.proto), s.dropped, s.passed, calculatePercentGeneric(s.total, total))
	}
}

func getUsageIndicator(current, maximum int, isLRU bool) string {
	if maximum == 0 {
		return ""
	}
	usage := float64(current) / float64(maximum) * 100
	critical, high, medium := getThresholdsFromConfig()

	switch {
	case isLRU && usage >= 99.0:
		return "[OK (LRU Full)]"
	case usage >= float64(critical):
		return "[CRITICAL]"
	case usage >= float64(high):
		return "[HIGH]"
	case usage >= float64(medium):
		return "[MEDIUM]"
	default:
		return "[OK]"
	}
}

func boolStr(cond bool, trueVal, falseVal string) string {
	if cond {
		return trueVal
	}
	return falseVal
}

func printConfigItem(icon, name, value string, last bool) {
	prefix := "   ├─"
	if last {
		prefix = "   └─"
	}
	fmt.Printf("%s [%s] %s: %s\n", prefix, icon, name, value)
}

func printConntrackConfig(cfg *types.GlobalConfig) {
	if cfg.Conntrack.Enabled {
		fmt.Printf("   ├─ [TRACK]  Connection Tracking: Enabled")
		if cfg.Conntrack.TCPTimeout != "" {
			fmt.Printf(" (TCP: %s", cfg.Conntrack.TCPTimeout)
			if cfg.Conntrack.UDPTimeout != "" {
				fmt.Printf(", UDP: %s", cfg.Conntrack.UDPTimeout)
			}
			fmt.Print(")")
		}
		fmt.Println()
	} else {
		fmt.Println("   ├─ [TRACK]  Connection Tracking: Disabled")
	}
}

func printRateLimitConfig(cfg *types.GlobalConfig) {
	if cfg.RateLimit.Enabled {
		fmt.Printf("   ├─ [START] Rate Limiting: Enabled")
		if cfg.RateLimit.AutoBlock {
			fmt.Printf(" (Auto Block: %s)", cfg.RateLimit.AutoBlockExpiry)
		}
		fmt.Println()
	} else {
		fmt.Println("   ├─ [START] Rate Limiting: Disabled")
	}
}

func printLogEngineConfig(cfg *types.GlobalConfig) {
	if cfg.LogEngine.Enabled {
		fmt.Printf("   ├─ [LOG] Log Engine: Enabled (%d rules)\n", len(cfg.LogEngine.Rules))
	} else {
		fmt.Println("   ├─ [LOG] Log Engine: Disabled")
	}
}

func printWebConfig(cfg *types.GlobalConfig) {
	if cfg.Web.Enabled {
		fmt.Printf("   └─ [WEB] Web Interface: Enabled (Port: %d)\n", cfg.Web.Port)
	} else {
		fmt.Println("   └─ [WEB] Web Interface: Disabled")
	}
}
