package agent

import (
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

// showDropStatistics 显示带百分比的丢弃统计
func showDropStatistics(s StatsAPI, drops, pass uint64) {
	trafficStats, err := xdp.LoadTrafficStats()
	var currentDropPPS uint64
	if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
		currentDropPPS = trafficStats.CurrentDropPPS
	}

	dropDetails, err := s.GetDropDetails()
	if err != nil || len(dropDetails) == 0 {
		return
	}

	wrappedDetails := make([]DropDetailEntryWrapper, len(dropDetails))
	for i, d := range dropDetails {
		wrappedDetails[i] = DropDetailEntryWrapper{d}
	}

	showDetailStatistics(wrappedDetails, detailStatsConfig{
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
func showPassStatistics(s StatsAPI, pass, drops uint64) {
	trafficStats, err := xdp.LoadTrafficStats()
	var currentPassPPS uint64
	if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
		currentPassPPS = trafficStats.CurrentPassPPS
	}

	passDetails, err := s.GetPassDetails()
	if err != nil || len(passDetails) == 0 {
		return
	}

	wrappedDetails := make([]PassDetailEntryWrapper, len(passDetails))
	for i, d := range passDetails {
		wrappedDetails[i] = PassDetailEntryWrapper{d}
	}

	showDetailStatistics(wrappedDetails, detailStatsConfig{
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
func showMapStatistics(mgr sdk.ManagerInterface) {
	fmt.Println()
	fmt.Println("[DATA] Map Statistics:")

	cfgManager := config.GetConfigManager()
	var capacityCfg *types.CapacityConfig
	if err := cfgManager.LoadConfig(); err == nil {
		capacityCfg = cfgManager.GetCapacityConfig()
	}

	blacklistCount, _ := mgr.GetLockedIPCount()
	whitelistCount, _ := mgr.GetWhitelistCount()
	dynBlacklistCount, _ := mgr.GetDynLockListCount()
	rateLimitRules, _, _ := mgr.ListRateLimitRules(0, "")
	ipPortRules, _, _ := mgr.ListIPPortRules(false, 0, "")
	allowedPorts, _ := mgr.ListAllowedPorts()

	maxBlacklist := 2000000
	maxWhitelist := 65536
	maxDynBlacklist := 2000000
	maxIPPortRules := 65536
	maxRateLimits := 1000

	if capacityCfg != nil {
		if capacityCfg.LockList > 0 {
			maxBlacklist = capacityCfg.LockList
		}
		if capacityCfg.Whitelist > 0 {
			maxWhitelist = capacityCfg.Whitelist
		}
		if capacityCfg.DynLockList > 0 {
			maxDynBlacklist = capacityCfg.DynLockList
		}
		if capacityCfg.IPPortRules > 0 {
			maxIPPortRules = capacityCfg.IPPortRules
		}
		if capacityCfg.RateLimits > 0 {
			maxRateLimits = capacityCfg.RateLimits
		}
	}

	fmt.Printf("   %-18s %12s / %-12s %s\n", "Map", "Used", "Max", "Usage")
	fmt.Printf("   %s\n", strings.Repeat("-", 70))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[LOCK] Blacklist", blacklistCount, maxBlacklist,
		renderUsageBar(blacklistCount, maxBlacklist, 20))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[DYNDYNLOCK] Dyn Blacklist", dynBlacklistCount, maxDynBlacklist,
		renderUsageBar(int(dynBlacklistCount), maxDynBlacklist, 20))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[WHITE] Whitelist", whitelistCount, maxWhitelist,
		renderUsageBar(whitelistCount, maxWhitelist, 20))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[IPPort] IP+Port Rules", len(ipPortRules), maxIPPortRules,
		renderUsageBar(len(ipPortRules), maxIPPortRules, 20))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[Limit]  Rate Limits", len(rateLimitRules), maxRateLimits,
		renderUsageBar(len(rateLimitRules), maxRateLimits, 20))
	fmt.Printf("   %-18s %12d\n", "[Allowport] Allowed Ports", len(allowedPorts))
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
func showCompactMapStatistics(mgr sdk.ManagerInterface) {
	cfgManager := config.GetConfigManager()
	var capacityCfg *types.CapacityConfig
	if err := cfgManager.LoadConfig(); err == nil {
		capacityCfg = cfgManager.GetCapacityConfig()
	}

	blacklistCount, _ := mgr.GetLockedIPCount()
	whitelistCount, _ := mgr.GetWhitelistCount()
	dynBlacklistCount, _ := mgr.GetDynLockListCount()
	rateLimitRules, _, _ := mgr.ListRateLimitRules(0, "")
	ipPortRules, _, _ := mgr.ListIPPortRules(false, 0, "")

	maxBlacklist := 2000000
	maxWhitelist := 65536
	maxDynBlacklist := 2000000
	maxIPPortRules := 65536
	maxRateLimits := 1000

	if capacityCfg != nil {
		if capacityCfg.LockList > 0 {
			maxBlacklist = capacityCfg.LockList
		}
		if capacityCfg.Whitelist > 0 {
			maxWhitelist = capacityCfg.Whitelist
		}
		if capacityCfg.DynLockList > 0 {
			maxDynBlacklist = capacityCfg.DynLockList
		}
		if capacityCfg.IPPortRules > 0 {
			maxIPPortRules = capacityCfg.IPPortRules
		}
		if capacityCfg.RateLimits > 0 {
			maxRateLimits = capacityCfg.RateLimits
		}
	}

	fmt.Println()
	fmt.Println("[DATA] Map Usage:")
	fmt.Printf("   %-16s %s\n", "[LOCK] Blacklist:", renderMiniBar(blacklistCount, maxBlacklist))
	fmt.Printf("   %-16s %s\n", "[DynLOCK] Dyn:", renderMiniBar(int(dynBlacklistCount), maxDynBlacklist))
	fmt.Printf("   %-16s %s\n", "[WHITE] Whitelist:", renderMiniBar(whitelistCount, maxWhitelist))
	fmt.Printf("   %-16s %s\n", "[IPPort] IP+Port:", renderMiniBar(len(ipPortRules), maxIPPortRules))
	fmt.Printf("   %-16s %s\n", "[Limit] RateLimit:", renderMiniBar(len(rateLimitRules), maxRateLimits))
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
func showTopBlockedIPs(s StatsAPI, drops uint64) {
	if drops == 0 {
		return
	}

	dropDetails, err := s.GetDropDetails()
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
	var sorted []ipCount
	for ip, count := range ipCounts {
		sorted = append(sorted, ipCount{ip, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	if len(sorted) > 0 {
		fmt.Println()
		fmt.Println("[ALERT] Top Blocked Attackers:")
		maxShow := 3
		if len(sorted) < maxShow {
			maxShow = len(sorted)
		}
		for i := 0; i < maxShow; i++ {
			percent := float64(sorted[i].count) / float64(drops) * 100
			fmt.Printf("   %d. %s - %s drops (%.1f%%)\n", i+1, sorted[i].ip,
				fmtutil.FormatNumberWithComma(sorted[i].count), percent)
		}
	}
}

// showConclusionStatistics displays summary statistics at the end
// showConclusionStatistics 在末尾显示汇总统计
func showConclusionStatistics(mgr sdk.ManagerInterface, s StatsAPI) {
	fmt.Println()
	fmt.Println("[SUMMARY] System Summary:")

	blacklistCount, _ := mgr.GetLockedIPCount()
	dynBlacklistCount, _ := mgr.GetDynLockListCount()
	whitelistCount, _ := mgr.GetWhitelistCount()

	fmt.Printf("   ├─ Blacklisted IPs: %d (static) + %d (dynamic) = %d total\n",
		blacklistCount, dynBlacklistCount, blacklistCount+int(dynBlacklistCount))
	fmt.Printf("   └─ Whitelisted IPs: %d\n", whitelistCount)

	showTopBlockedIPs(s, 0)
}
