package agent

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

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

	snapshot, snapshotErr := systemQueryService.LoadStatusSnapshot(s)
	pluginSnapshot, pluginErr := loadPluginStatusSnapshot(ctx, snapshot, snapshotErr)
	pluginHealth := systemQueryService.LoadPluginHealth(pluginSnapshot)
	metrics, metricsErr := systemQueryService.LoadMetrics(s)
	pass, drops, err := s.Stats.GetCounters()
	if err != nil {
		fmt.Fprintf(w, "[WARN]  Could not retrieve statistics: %v\n", err)
		return nil
	}

	showDropStatistics(w, s.Stats, drops, pass)
	showPassStatistics(w, s.Stats, pass, drops)
	if !showProtocolDistributionFromMetrics(w, metrics, metricsErr, pass, drops) {
		showProtocolDistribution(w, s.Stats, pass, drops)
	}
	if !showConntrackHealthFromMetrics(w, metrics, metricsErr) {
		showConntrackHealth(w, s)
	}
	showPolicyConfiguration(w, snapshot, snapshotErr)
	showPluginStatus(w, pluginSnapshot, pluginHealth, pluginErr)
	showConclusionStatistics(w, s, s.Stats)
	if !showMapStatisticsFromMetrics(w, s, metrics, metricsErr) {
		showMapStatistics(w, s)
	}
	showTrafficMetrics(w, pass, drops)
	showAttachedInterfaces(w)

	return nil
}

func loadPluginStatusSnapshot(ctx context.Context, snapshot StatusSnapshot, snapshotErr error) (PluginStatusSnapshot, error) {
	cfg := snapshot.Config
	if cfg == nil || snapshotErr != nil {
		var err error
		cfg, err = systemQueryService.LoadConfig()
		if err != nil {
			return PluginStatusSnapshot{}, err
		}
	}
	return systemQueryService.LoadPluginStatus(ctx, cfg)
}

func showPolicyConfiguration(w io.Writer, snapshot StatusSnapshot, snapshotErr error) {
	if snapshotErr != nil || snapshot.Config == nil {
		return
	}
	cfg := snapshot.Config
	desired := snapshot.Desired

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[CONFIG]  Policy Configuration:")

	items := []struct {
		icon  string
		name  string
		value string
	}{
		{"SHIELD", "Default Deny", boolStr(desired.DefaultDeny, "Enabled (Deny by default)", "Disabled (Allow by default)")},
		{"RELOAD", "Allow Return Traffic", boolStr(desired.AllowReturnTraffic, "Enabled", "Disabled")},
		{"PING", "Allow ICMP (Ping)", boolStr(desired.AllowICMP, "Enabled", "Disabled")},
		{"LOCK", "Strict TCP", boolStr(desired.StrictTCP, "Enabled", "Disabled")},
		{"PROTECT", "SYN Flood Protection", boolStr(desired.SYNLimit, "Enabled", "Disabled")},
		{"WEB", "Bogon Filter", boolStr(desired.BogonFilter, "Enabled", "Disabled")},
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

func showPluginStatus(w io.Writer, snapshot PluginStatusSnapshot, health PluginHealthSnapshot, snapshotErr error) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[PLUGIN] Plugin Status:")

	if snapshotErr != nil && len(snapshot.Runtime) == 0 && len(snapshot.Datapath) == 0 {
		fmt.Fprintf(w, "   └─ Status: Unavailable (%v)\n", snapshotErr)
		return
	}

	fmt.Fprintf(w, "   ├─ Runtime: %s - %s\n", strings.ToUpper(string(health.Runtime.Status)), health.Runtime.Message)
	if len(snapshot.Runtime) == 0 {
		fmt.Fprintln(w, "   │  - none")
	} else {
		for _, item := range snapshot.Runtime {
			state := "disabled"
			if item.Enabled && item.Healthy {
				state = "enabled"
			} else if item.Enabled {
				state = "unhealthy"
			}
			fmt.Fprintf(w, "   │  - %s [%s]: %s\n", item.Name, state, item.Message)
		}
	}

	fmt.Fprintf(w, "   └─ Datapath: %s - %s\n", strings.ToUpper(string(health.Datapath.Status)), health.Datapath.Message)
	if len(snapshot.Datapath) == 0 {
		fmt.Fprintln(w, "      - none")
		return
	}
	for _, item := range snapshot.Datapath {
		path := item.Path
		if path == "" {
			path = "(unconfigured)"
		}
		state := "not loaded"
		if item.Loaded && item.Healthy {
			state = "loaded"
		} else if item.Loaded {
			state = "drift"
		}
		fmt.Fprintf(w, "      - slot %d [%s]: %s (%s)\n", item.Index, state, path, item.Message)
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

func showConntrackHealth(w io.Writer, s *sdk.SDK) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[TRACK]  Conntrack Health:")

	count, err := s.Conntrack.Count()
	if err != nil {
		fmt.Fprintln(w, "   └─ Status: Unavailable")
		return
	}

	maxVal := getConntrackMax()
	entries, _ := s.Conntrack.List()

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

func getConntrackHealthStatus(count, maxVal uint64, hasRate bool, stats TrafficStats) string {
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

func showProtocolDistributionFromMetrics(w io.Writer, metrics *MetricsData, metricsErr error, pass, drops uint64) bool {
	if metricsErr != nil || metrics == nil {
		return false
	}

	total := pass + drops
	proto := metrics.ProtocolStats
	if total == 0 && proto.TotalPackets == 0 {
		return false
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[PROTO] Protocol Distribution:")
	fmt.Fprintf(w, "   %-10s %-15s %-15s %-10s\n", "Protocol", "Dropped", "Passed", "Percent")
	fmt.Fprintf(w, "   %s\n", strings.Repeat("-", 50))

	rows := []struct {
		name    string
		dropped uint64
		passed  uint64
		total   uint64
	}{
		{"TCP", proto.TCP.Dropped, proto.TCP.Passed, proto.TCP.Packets},
		{"UDP", proto.UDP.Dropped, proto.UDP.Passed, proto.UDP.Packets},
		{"ICMP", proto.ICMP.Dropped, proto.ICMP.Passed, proto.ICMP.Packets},
		{"Other", proto.Other.Dropped, proto.Other.Passed, proto.Other.Packets},
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].total > rows[j].total })

	printed := false
	for _, row := range rows {
		if row.total == 0 {
			continue
		}
		printed = true
		fmt.Fprintf(w, "   %-10s %-15d %-15d %.1f%%\n", row.name, row.dropped, row.passed, calculatePercentGeneric(row.total, total))
	}

	if !printed {
		fmt.Fprintln(w, "   └─ No protocol data available")
	}

	return true
}

func showConntrackHealthFromMetrics(w io.Writer, metrics *MetricsData, metricsErr error) bool {
	if metricsErr != nil || metrics == nil {
		return false
	}

	conntrack := metrics.ConntrackHealth
	if conntrack.MaxEntries == 0 && conntrack.CurrentEntries == 0 && conntrack.Status == "" {
		return false
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[TRACK]  Conntrack Health:")
	fmt.Fprintf(w, "   ├─ Active Connections: %d / %d (%.1f%%)\n",
		conntrack.CurrentEntries, conntrack.MaxEntries,
		calculatePercentGeneric(uint64(conntrack.CurrentEntries), uint64(conntrack.MaxEntries)))
	fmt.Fprintf(w, "   ├─ TCP: %d (%.1f%%)  UDP: %d (%.1f%%)  ICMP: %d (%.1f%%)  Other: %d\n",
		conntrack.TCPConnections, calculatePercentGeneric(conntrack.TCPConnections, uint64(conntrack.CurrentEntries)),
		conntrack.UDPConnections, calculatePercentGeneric(conntrack.UDPConnections, uint64(conntrack.CurrentEntries)),
		conntrack.ICMPConnections, calculatePercentGeneric(conntrack.ICMPConnections, uint64(conntrack.CurrentEntries)),
		conntrack.OtherConnections)

	trafficStats, err := systemQueryService.LoadTrafficStats()
	hasRate := err == nil && trafficStats.LastUpdateTime.After(time.Time{})
	if hasRate {
		fmt.Fprintf(w, "   ├─ New/s: %s  Evict/s: %s\n",
			systemQueryService.FormatNumberWithComma(trafficStats.CurrentConntrackNew),
			systemQueryService.FormatNumberWithComma(trafficStats.CurrentConntrackEvict))
	}

	fmt.Fprintf(w, "   └─ %s\n", getConntrackHealthStatus(uint64(conntrack.CurrentEntries), uint64(conntrack.MaxEntries), hasRate, trafficStats))
	return true
}

func showMapStatisticsFromMetrics(w io.Writer, s *sdk.SDK, metrics *MetricsData, metricsErr error) bool {
	if metricsErr != nil || metrics == nil {
		return false
	}

	blacklist, okBlacklist := metrics.MapUsage.Maps["static_blacklist"]
	dynBlacklist, okDyn := metrics.MapUsage.Maps["dynamic_blacklist"]
	whitelist, okWhitelist := metrics.MapUsage.Maps["whitelist"]
	ruleMap, okRuleMap := metrics.MapUsage.Maps["rule_map"]
	rateLimit, okRateLimit := metrics.MapUsage.Maps["ratelimit_map"]
	if !okBlacklist || !okDyn || !okWhitelist || !okRuleMap || !okRateLimit {
		return false
	}

	allowedPorts, _ := s.Rule.ListAllowedPorts()

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[DATA] Map Statistics:")
	fmt.Fprintf(w, "   %-18s %12s / %-12s %s\n", "Map", "Used", "Max", "Usage")
	fmt.Fprintf(w, "   %s\n", strings.Repeat("-", 70))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[LOCK] Blacklist", blacklist.Entries, blacklist.MaxEntries,
		renderUsageBar(blacklist.Entries, blacklist.MaxEntries, 20))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[DYNDYNLOCK] Dyn Blacklist", dynBlacklist.Entries, dynBlacklist.MaxEntries,
		renderUsageBar(dynBlacklist.Entries, dynBlacklist.MaxEntries, 20))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[WHITE] Whitelist", whitelist.Entries, whitelist.MaxEntries,
		renderUsageBar(whitelist.Entries, whitelist.MaxEntries, 20))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[IPPort] IP+Port Rules", ruleMap.Entries, ruleMap.MaxEntries,
		renderUsageBar(ruleMap.Entries, ruleMap.MaxEntries, 20))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[Limit]  Rate Limits", rateLimit.Entries, rateLimit.MaxEntries,
		renderUsageBar(rateLimit.Entries, rateLimit.MaxEntries, 20))
	fmt.Fprintf(w, "   %-18s %12d\n", "[Allowport] Allowed Ports", len(allowedPorts))

	return true
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
