package agent

import (
	"fmt"
	"io"
	"strings"
	"time"

	datapathstats "github.com/netxfw/netxfw/internal/datapath/xdp/stats"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
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
	def := domainconfig.DefaultConfig().Capacity
	capacity := mapCapacity{
		Blacklist:    def.LockList,
		Whitelist:    def.Whitelist,
		DynBlacklist: def.DynLockList,
		IPPortRules:  def.IPPortRules,
		RateLimits:   def.RateLimits,
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

// showDropStatistics displays drop statistics with percentages.
// showDropStatistics 显示带百分比的丢弃统计。
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

// mapCountsSnapshot holds pre-computed map entry counts to avoid redundant BPF map iterations.
// mapCountsSnapshot 保存预计算的 Map 条目计数，避免重复遍历 BPF Map。
type mapCountsSnapshot struct {
	Blacklist    int
	DynBlacklist int
	Whitelist    int
	IPPortRules  int
	RateLimits   int
}

// showCompactMapStatistics displays compact map statistics using pre-computed counts.
// Uses limit=1 for rule listing to avoid loading all rules into memory just for counting.
// showCompactMapStatistics 使用预计算计数显示紧凑的 Map 统计。
// 规则列表使用 limit=1 以避免仅为计数而加载所有规则到内存。
func showCompactMapStatistics(w io.Writer, s *sdk.SDK, counts mapCountsSnapshot) {
	mapCap := getMapCapacity()

	// Use limit=1: the function returns total count via second return value
	// while only allocating at most 1 entry in the slice
	// 使用 limit=1：函数通过第二个返回值返回总数，切片最多只分配 1 个条目
	_, ipPortCount, _ := s.Rule.List(false, 1, "")
	_, rateLimitCount, _ := s.Rule.ListRateLimitRules(1, "")

	if ipPortCount > 0 {
		counts.IPPortRules = ipPortCount
	}
	if rateLimitCount > 0 {
		counts.RateLimits = rateLimitCount
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[DATA] Map Usage:")
	fmt.Fprintf(w, "   %-16s %s\n", "[LOCK] Blacklist:", renderMiniBar(counts.Blacklist, mapCap.Blacklist))
	fmt.Fprintf(w, "   %-16s %s\n", "[DynLOCK] Dyn:", renderMiniBar(counts.DynBlacklist, mapCap.DynBlacklist))
	fmt.Fprintf(w, "   %-16s %s\n", "[WHITE] Whitelist:", renderMiniBar(counts.Whitelist, mapCap.Whitelist))
	fmt.Fprintf(w, "   %-16s %s\n", "[IPPort] IP+Port:", renderMiniBar(counts.IPPortRules, mapCap.IPPortRules))
	fmt.Fprintf(w, "   %-16s %s\n", "[Limit] RateLimit:", renderMiniBar(counts.RateLimits, mapCap.RateLimits))
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

// showTopDropDetails displays top N drop details with bounded memory usage.
// showTopDropDetails 以有限的内存使用量显示 Top N 拦截详情。
func showTopDropDetails(w io.Writer, s StatsAPI, drops uint64) {
	if drops == 0 {
		return
	}

	topN := getTopNFromConfig()
	dropDetails, err := s.GetTopDropDetails(topN)
	if err != nil || len(dropDetails) == 0 {
		return
	}

	wrappedDetails := make([]DropDetailEntryWrapper, len(dropDetails))
	for i, d := range dropDetails {
		wrappedDetails[i] = DropDetailEntryWrapper{d}
	}

	trafficStats, _ := systemQueryService.LoadTrafficStats()
	var currentDropPPS uint64
	if trafficStats.LastUpdateTime.After(time.Time{}) {
		currentDropPPS = trafficStats.CurrentDropPPS
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

// showTopPassDetails displays top N pass details with bounded memory usage.
// showTopPassDetails 以有限的内存使用量显示 Top N 放行详情。
func showTopPassDetails(w io.Writer, s StatsAPI, pass uint64) {
	if pass == 0 {
		return
	}

	topN := getTopNFromConfig()
	passDetails, err := s.GetTopPassDetails(topN)
	if err != nil || len(passDetails) == 0 {
		return
	}

	wrappedDetails := make([]PassDetailEntryWrapper, len(passDetails))
	for i, d := range passDetails {
		wrappedDetails[i] = PassDetailEntryWrapper{d}
	}

	trafficStats, _ := systemQueryService.LoadTrafficStats()
	var currentPassPPS uint64
	if trafficStats.LastUpdateTime.After(time.Time{}) {
		currentPassPPS = trafficStats.CurrentPassPPS
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

	// Aggregate counts by source IP, then find top 3 without full sort
	// 按源 IP 聚合计数，然后不求全序直接找 Top 3
	ipCounts := make(map[string]uint64)
	for _, d := range dropDetails {
		ipCounts[d.SrcIP] += d.Count
	}

	// Track top 3 in a single pass — avoids allocating and sorting a full slice
	// 单次遍历跟踪 Top 3 — 避免分配和排序完整切片
	const maxShow = 3
	var top [maxShow]struct {
		ip    string
		count uint64
	}
	for ip, count := range ipCounts {
		for i := 0; i < maxShow; i++ {
			if count > top[i].count {
				// Shift down and insert
				for j := maxShow - 1; j > i; j-- {
					top[j] = top[j-1]
				}
				top[i] = struct {
					ip    string
					count uint64
				}{ip, count}
				break
			}
		}
	}

	if top[0].count == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[ALERT] Top Blocked Attackers:")
	for i := 0; i < maxShow; i++ {
		if top[i].count == 0 {
			break
		}
		percent := float64(top[i].count) / float64(drops) * 100
		fmt.Fprintf(w, "   %d. %s - %s drops (%.1f%%)\n", i+1, top[i].ip,
			systemQueryService.FormatNumberWithComma(top[i].count), percent)
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

// showConclusionStatisticsFromMetrics displays summary statistics reusing
// already-loaded metrics data, avoiding redundant BPF map iterations.
// showConclusionStatisticsFromMetrics 复用已加载的指标数据显示汇总统计，
// 避免重复遍历 BPF Map。
func showConclusionStatisticsFromMetrics(w io.Writer, metrics *MetricsData, metricsErr error) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[SUMMARY] System Summary:")

	if metricsErr != nil || metrics == nil {
		fmt.Fprintln(w, "   └─ Statistics unavailable")
		return
	}

	blacklist := metrics.MapUsage.Maps["static_blacklist"].Entries
	dynBlacklist := metrics.MapUsage.Maps["dynamic_blacklist"].Entries
	whitelist := metrics.MapUsage.Maps["whitelist"].Entries

	fmt.Fprintf(w, "   ├─ Blacklisted IPs: %d (static) + %d (dynamic) = %d total\n",
		blacklist, dynBlacklist, blacklist+dynBlacklist)
	fmt.Fprintf(w, "   └─ Whitelisted IPs: %d\n", whitelist)
}
