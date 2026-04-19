package agent

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	datapathstats "github.com/netxfw/netxfw/internal/datapath/xdp/stats"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

// mapCapacity holds the maximum capacity for each BPF map.
// mapCapacity 保存每个 BPF Map 的最大容量。
type mapCapacity struct {
	Blacklist    int
	Whitelist    int
	DynBlacklist int
	IPPortRules  int
	RateLimits   int
}

// getMapCapacity reads map capacity from config with sensible defaults.
// getMapCapacity 从配置读取 Map 容量，使用合理的默认值。
func getMapCapacity() mapCapacity {
	capacity := mapCapacity{
		Blacklist:    2000000,
		Whitelist:    65536,
		DynBlacklist: 2000000,
		IPPortRules:  65536,
		RateLimits:   1000,
	}

	cfg, err := systemQueryService.LoadConfig()
	if err == nil && cfg != nil {
		if cfg.Capacity.LockList > 0 {
			capacity.Blacklist = cfg.Capacity.LockList
		}
		if cfg.Capacity.Whitelist > 0 {
			capacity.Whitelist = cfg.Capacity.Whitelist
		}
		if cfg.Capacity.DynLockList > 0 {
			capacity.DynBlacklist = cfg.Capacity.DynLockList
		}
		if cfg.Capacity.IPPortRules > 0 {
			capacity.IPPortRules = cfg.Capacity.IPPortRules
		}
		if cfg.Capacity.RateLimits > 0 {
			capacity.RateLimits = cfg.Capacity.RateLimits
		}
	}
	return capacity
}

// showDropStatistics 显示带百分比的丢弃统计
func showDropStatistics(w io.Writer, s StatsAPI, drops, pass uint64) {
	trafficStats, err := systemQueryService.LoadTrafficStats()
	var currentDropPPS uint64
	if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
		currentDropPPS = trafficStats.CurrentDropPPS
	}

	dropDetails, err := datapathstats.LoadDropDetails(s)
	if err != nil || len(dropDetails) == 0 {
		return
	}

	wrappedDetails := make([]DropDetailEntryWrapper, len(dropDetails))
	for i, d := range dropDetails {
		wrappedDetails[i] = DropDetailEntryWrapper{d}
	}

	showDetailStatistics(w, wrappedDetails, detailStatsConfig{
		title:      "[BLOCK] Drop Statistics:",
		subTitle:   "[BLOCK] Top Drops by Reason & Source:",
		reasonFunc: dropReasonToString,
		totalCount: drops,
		currentPPS: currentDropPPS,
		showRate:   true,
	})
}

// showPassStatistics displays pass statistics with percentages
// showPassStatistics 显示带百分比的通过统计
func showPassStatistics(w io.Writer, s StatsAPI, pass, drops uint64) {
	trafficStats, err := systemQueryService.LoadTrafficStats()
	var currentPassPPS uint64
	if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
		currentPassPPS = trafficStats.CurrentPassPPS
	}

	passDetails, err := datapathstats.LoadPassDetails(s)
	if err != nil || len(passDetails) == 0 {
		return
	}

	wrappedDetails := make([]PassDetailEntryWrapper, len(passDetails))
	for i, d := range passDetails {
		wrappedDetails[i] = PassDetailEntryWrapper{d}
	}

	showDetailStatistics(w, wrappedDetails, detailStatsConfig{
		title:      "[OK] Pass Statistics:",
		subTitle:   "[OK] Top Allowed by Reason & Source:",
		reasonFunc: passReasonToString,
		totalCount: pass,
		currentPPS: currentPassPPS,
		showRate:   true,
	})
}

// showMapStatistics displays BPF map statistics
// showMapStatistics 显示 BPF Map 统计和使用率
func showMapStatistics(w io.Writer, s *sdk.SDK) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[DATA] Map Statistics:")

	mapCap := getMapCapacity()

	blacklistCount, _ := s.Stats.GetLockedIPCount()
	whitelistCount, _ := s.Stats.GetWhitelistCount()
	dynBlacklistCount, _ := s.Stats.GetDynamicLockedIPCount()
	rateLimitRules, _, _ := s.Rule.ListRateLimitRules(0, "")
	ipPortRules, _, _ := s.Rule.List(false, 0, "")
	allowedPorts, _ := s.Rule.ListAllowedPorts()

	fmt.Fprintf(w, "   %-18s %12s / %-12s %s\n", "Map", "Used", "Max", "Usage")
	fmt.Fprintf(w, "   %s\n", strings.Repeat("-", 70))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[LOCK] Blacklist", blacklistCount, mapCap.Blacklist,
		renderUsageBar(blacklistCount, mapCap.Blacklist, 20))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[DYNDYNLOCK] Dyn Blacklist", dynBlacklistCount, mapCap.DynBlacklist,
		renderUsageBar(int(dynBlacklistCount), mapCap.DynBlacklist, 20))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[WHITE] Whitelist", whitelistCount, mapCap.Whitelist,
		renderUsageBar(whitelistCount, mapCap.Whitelist, 20))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[IPPort] IP+Port Rules", len(ipPortRules), mapCap.IPPortRules,
		renderUsageBar(len(ipPortRules), mapCap.IPPortRules, 20))
	fmt.Fprintf(w, "   %-18s %12d / %-12d %s\n",
		"[Limit]  Rate Limits", len(rateLimitRules), mapCap.RateLimits,
		renderUsageBar(len(rateLimitRules), mapCap.RateLimits, 20))
	fmt.Fprintf(w, "   %-18s %12d\n", "[Allowport] Allowed Ports", len(allowedPorts))
}

// renderUsageBar renders a visual progress bar like top command
// renderUsageBar 渲染类似 top 命令的可视化进度条
func renderUsageBar(current, maximum int, width int) string {
	if maximum == 0 {
		return "[ N/A ]"
	}

	usage := float64(current) / float64(maximum) * 100
	filled := int(usage / 100 * float64(width))
	if filled > width {
		filled = width
	}

	var bar strings.Builder
	bar.WriteString("[")
	for i := 0; i < width; i++ {
		if i < filled {
			bar.WriteString("#")
		} else {
			bar.WriteString("-")
		}
	}
	bar.WriteString("] ")

	critical, high, medium := getThresholdsFromConfig()
	var status string
	if usage >= float64(critical) {
		status = "[CRITICAL]"
	} else if usage >= float64(high) {
		status = "[HIGH]"
	} else if usage >= float64(medium) {
		status = "[MEDIUM]"
	} else {
		status = "[OK]"
	}

	return fmt.Sprintf("%s %5.1f%% %s", bar.String(), usage, status)
}

// showCompactMapStatistics displays compact map statistics in single line format
// showCompactMapStatistics 以紧凑格式显示 Map 统计
func showCompactMapStatistics(w io.Writer, s *sdk.SDK) {
	mapCap := getMapCapacity()

	blacklistCount, _ := s.Stats.GetLockedIPCount()
	whitelistCount, _ := s.Stats.GetWhitelistCount()
	dynBlacklistCount, _ := s.Stats.GetDynamicLockedIPCount()
	rateLimitRules, _, _ := s.Rule.ListRateLimitRules(0, "")
	ipPortRules, _, _ := s.Rule.List(false, 0, "")

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[DATA] Map Usage:")
	fmt.Fprintf(w, "   %-16s %s\n", "[LOCK] Blacklist:", renderMiniBar(blacklistCount, mapCap.Blacklist))
	fmt.Fprintf(w, "   %-16s %s\n", "[DynLOCK] Dyn:", renderMiniBar(int(dynBlacklistCount), mapCap.DynBlacklist))
	fmt.Fprintf(w, "   %-16s %s\n", "[WHITE] Whitelist:", renderMiniBar(whitelistCount, mapCap.Whitelist))
	fmt.Fprintf(w, "   %-16s %s\n", "[IPPort] IP+Port:", renderMiniBar(len(ipPortRules), mapCap.IPPortRules))
	fmt.Fprintf(w, "   %-16s %s\n", "[Limit] RateLimit:", renderMiniBar(len(rateLimitRules), mapCap.RateLimits))
}

// renderMiniBar renders a mini progress bar for compact display
// renderMiniBar 渲染用于紧凑显示的迷你进度条
func renderMiniBar(current, maximum int) string {
	if maximum == 0 {
		return "N/A"
	}

	usage := float64(current) / float64(maximum) * 100
	filled := int(usage / 100 * 10)
	if filled > 10 {
		filled = 10
	}

	var bar strings.Builder
	for i := 0; i < 10; i++ {
		if i < filled {
			bar.WriteString("#")
		} else {
			bar.WriteString("-")
		}
	}

	return fmt.Sprintf("[%s] %d/%d", bar.String(), current, maximum)
}

// showTopBlockedIPs displays top blocked attacker IPs
// showTopBlockedIPs 显示被拦截最多的攻击 IP
func showTopBlockedIPs(w io.Writer, s StatsAPI, drops uint64) {
	if drops == 0 {
		return
	}

	dropDetails, err := datapathstats.LoadDropDetails(s)
	if err != nil || len(dropDetails) == 0 {
		return
	}

	ipCounts := make(map[string]uint64)
	for _, d := range dropDetails {
		ipCounts[d.SrcIP] += d.Count
	}

	type ipCount struct {
		ip    string
		count uint64
	}
	sorted := make([]ipCount, 0, len(ipCounts))
	for ip, count := range ipCounts {
		sorted = append(sorted, ipCount{ip, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	if len(sorted) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "[ALERT] Top Blocked Attackers:")
		maxShow := 3
		if len(sorted) < maxShow {
			maxShow = len(sorted)
		}
		for i := 0; i < maxShow; i++ {
			percent := float64(sorted[i].count) / float64(drops) * 100
			fmt.Fprintf(w, "   %d. %s - %s drops (%.1f%%)\n", i+1, sorted[i].ip,
				systemQueryService.FormatNumberWithComma(sorted[i].count), percent)
		}
	}
}

// showConclusionStatistics displays summary statistics at the end
// showConclusionStatistics 在末尾显示汇总统计
func showConclusionStatistics(w io.Writer, fw *sdk.SDK, s StatsAPI) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[SUMMARY] System Summary:")

	blacklistCount, _ := fw.Stats.GetLockedIPCount()
	dynBlacklistCount, _ := fw.Stats.GetDynamicLockedIPCount()
	whitelistCount, _ := fw.Stats.GetWhitelistCount()

	fmt.Fprintf(w, "   ├─ Blacklisted IPs: %d (static) + %d (dynamic) = %d total\n",
		blacklistCount, dynBlacklistCount, blacklistCount+int(dynBlacklistCount))
	fmt.Fprintf(w, "   └─ Whitelisted IPs: %d\n", whitelistCount)

	showTopBlockedIPs(w, s, 0)
}
