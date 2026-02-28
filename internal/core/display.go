package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// Protocol string constants.
// 协议字符串常量。
const (
	protoTCP          = "TCP"
	protoUDP          = "UDP"
	protoICMP         = "ICMP"
	protoICMPv6       = "ICMPv6"
	statusEnabled     = "Enabled"
	statusDisabled    = "Disabled"
	maxDisplayEntries = 10
)

// dropReasonStr converts drop reason code to string.
// dropReasonStr 将丢弃原因代码转换为字符串。
func dropReasonStr(r uint32) string {
	reasons := map[uint32]string{
		0:  "UNKNOWN",
		1:  "INVALID",
		2:  "PROTOCOL",
		3:  "BLACKLIST",
		4:  "RATELIMIT",
		5:  "STRICT_TCP",
		6:  "DEFAULT_DENY",
		7:  "LAND_ATTACK",
		8:  "BOGON",
		9:  "FRAGMENT",
		10: "BAD_HEADER",
		11: "TCP_FLAGS",
		12: "SPOOF",
		13: "GEOIP",
	}
	if s, ok := reasons[r]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN(%d)", r)
}

// passReasonStr converts pass reason code to string.
// passReasonStr 将通过原因代码转换为字符串。
func passReasonStr(r uint32) string {
	reasons := map[uint32]string{
		100: "UNKNOWN",
		101: "WHITELIST",
		102: "RETURN",
		103: "CONNTRACK",
		104: "DEFAULT_ALLOW",
	}
	if s, ok := reasons[r]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN(%d)", r)
}

// protoStr converts protocol number to string.
// protoStr 将协议号转换为字符串。
func protoStr(p uint8) string {
	switch p {
	case 6:
		return protoTCP
	case 17:
		return protoUDP
	case 1:
		return protoICMP
	default:
		return fmt.Sprintf("%d", p)
	}
}

// displayDetailStats displays detailed statistics with header.
// displayDetailStats 显示带有标题的详细统计。
func displayDetailStats(details []sdk.DropDetailEntry, reasonFunc func(uint32) string, header string) {
	if len(details) == 0 {
		return
	}

	sort.Slice(details, func(i, j int) bool {
		return details[i].Count > details[j].Count
	})

	fmt.Printf("\n   %s:\n", header)
	fmt.Printf("   %-20s %-8s %-40s %-8s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count")
	fmt.Printf("   %s\n", strings.Repeat("-", 90))

	for i, d := range details {
		if i >= maxDisplayEntries {
			fmt.Printf("   ... and more\n")
			break
		}
		fmt.Printf("   %-20s %-8s %-40s %-8d %d\n",
			reasonFunc(d.Reason),
			protoStr(d.Protocol),
			d.SrcIP,
			d.DstPort,
			d.Count,
		)
	}
}

// showDropStats displays drop statistics.
// showDropStats 显示丢弃统计。
func showDropStats(xdpMgr XDPManager) {
	drops, err := xdpMgr.GetDropCount()
	if err != nil {
		fmt.Printf("[WARN]  Could not retrieve drop statistics: %v\n", err)
		return
	}

	fmt.Printf("[STATS] Global Drop Count: %d packets\n", drops)

	details, err := xdpMgr.GetDropDetails()
	if err == nil && len(details) > 0 {
		displayDetailStats(details, dropReasonStr, "[BLOCK] Top Drops by Reason & Source")
	}
}

// showPassStats displays pass statistics.
// showPassStats 显示通过统计。
func showPassStats(xdpMgr XDPManager) {
	passes, err := xdpMgr.GetPassCount()
	if err != nil {
		fmt.Printf("[WARN]  Could not retrieve pass statistics: %v\n", err)
		return
	}

	fmt.Printf("[STATS] Global Pass Count: %d packets\n", passes)

	details, err := xdpMgr.GetPassDetails()
	if err == nil && len(details) > 0 {
		displayDetailStats(details, passReasonStr, "[OK] Top Allowed by Reason & Source")
	}
}

// showGlobalConfig displays global configuration.
// showGlobalConfig 显示全局配置。
func showGlobalConfig(globalConfig *ebpf.Map) {
	if globalConfig == nil {
		return
	}

	var key uint32
	var val uint64

	// Default deny policy
	key = 0
	if err := globalConfig.Lookup(&key, &val); err == nil {
		status := statusDisabled
		if val == 1 {
			status = statusEnabled
		}
		fmt.Printf("[SHIELD]  Default Deny Policy: %s\n", status)
	}

	// Allow return traffic
	key = 1
	if err := globalConfig.Lookup(&key, &val); err == nil {
		status := statusDisabled
		if val == 1 {
			status = statusEnabled
		}
		fmt.Printf("[RELOAD] Allow Return Traffic: %s\n", status)
	}

	// Allow ICMP
	key = 2
	if err := globalConfig.Lookup(&key, &val); err == nil {
		status := statusDisabled
		if val == 1 {
			status = statusEnabled
		}
		fmt.Printf("[PING] Allow ICMP (Ping): %s\n", status)

		if val == 1 {
			showICMPRateLimit(globalConfig)
		}
	}

	// Conntrack
	key = 3
	if err := globalConfig.Lookup(&key, &val); err == nil {
		status := statusDisabled
		if val == 1 {
			status = statusEnabled
		}
		fmt.Printf("[TRACK]  Connection Tracking: %s\n", status)

		if val == 1 {
			showConntrackTimeout(globalConfig)
		}
	}

	// Global rate limit
	key = 10
	if err := globalConfig.Lookup(&key, &val); err == nil {
		status := statusDisabled
		if val == 1 {
			status = statusEnabled
		}
		fmt.Printf("[START] Global Rate Limiting: %s\n", status)
	}
}

// showICMPRateLimit displays ICMP rate limit configuration.
// showICMPRateLimit 显示 ICMP 速率限制配置。
func showICMPRateLimit(globalConfig *ebpf.Map) {
	var rate, burst uint64
	kRate := uint32(5)
	kBurst := uint32(6)

	if err := globalConfig.Lookup(&kRate, &rate); err == nil {
		if err := globalConfig.Lookup(&kBurst, &burst); err == nil {
			fmt.Printf("   ├─ Rate Limit: %d packets/sec\n", rate)
			fmt.Printf("   └─ Burst Limit: %d packets\n", burst)
		}
	}
}

// showConntrackTimeout displays conntrack timeout configuration.
// showConntrackTimeout 显示连接跟踪超时配置。
func showConntrackTimeout(globalConfig *ebpf.Map) {
	kTimeout := uint32(4)
	var timeoutNs uint64

	if err := globalConfig.Lookup(&kTimeout, &timeoutNs); err == nil {
		fmt.Printf("   └─ Idle Timeout: %v\n", time.Duration(timeoutNs)) // nolint:gosec // G115: timeout is always valid
	}
}

// showCounts displays locked IP, whitelist, and conntrack counts.
// showCounts 显示锁定 IP、白名单和连接跟踪计数。
func showCounts(xdpMgr XDPManager) {
	lockedCount, err := xdpMgr.GetLockedIPCount()
	if err == nil {
		fmt.Printf("[LOCK] Locked IP Count: %d addresses\n", lockedCount)
	}

	whitelistCount, err := xdpMgr.GetWhitelistCount()
	if err == nil {
		fmt.Printf("[WHITE] Whitelist Count: %d addresses\n", whitelistCount)
	}

	ctCount, err := xdpMgr.GetConntrackCount()
	if err == nil {
		fmt.Printf("[TRACK]  Active Connections: %d\n", ctCount)
	}
}

// showAttachedInterfaces displays attached interfaces.
// showAttachedInterfaces 显示已附加的接口。
func showAttachedInterfaces() {
	fmt.Println("\n[LINK] Attached Interfaces:")
	files, err := os.ReadDir(config.GetPinPath())
	if err != nil {
		fmt.Println(" - Unable to read pin path")
		return
	}

	attachedCount := 0
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "link_") {
			iface := strings.TrimPrefix(f.Name(), "link_")
			mode := getXDPMode(iface)
			fmt.Printf(" - %s (Mode: %s)\n", iface, mode)
			attachedCount++
		}
	}

	if attachedCount == 0 {
		fmt.Println(" - None (Program is loaded but not attached to any interface)")
	}
}

/**
 * getXDPMode returns the XDP attachment mode for a given interface.
 * getXDPMode 返回给定接口的 XDP 附加模式。
 */
func getXDPMode(iface string) string {
	cmd := exec.Command("ip", "link", "show", iface) // #nosec G204 // iface is controlled interface name from system
	out, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}

	output := string(out)
	if strings.Contains(output, "xdpoffload") {
		return "Offload"
	} else if strings.Contains(output, "xdpdrv") {
		return "Native (Driver)"
	} else if strings.Contains(output, "xdpgeneric") {
		return "Generic (SKB)"
	} else if strings.Contains(output, "xdp") {
		return "Native"
	}

	return "None"
}

/**
 * ShowWhitelist reads and prints all whitelisted ranges.
 * ShowWhitelist 读取并打印所有白名单范围。
 */
func ShowWhitelist(ctx context.Context, xdpMgr XDPManager, limit int, search string) error {
	ips, total, err := xdpMgr.ListWhitelistIPs(limit, search)
	if err != nil {
		return fmt.Errorf("failed to list whitelisted IPs: %v", err)
	}

	if len(ips) == 0 {
		fmt.Println("Empty whitelist.")
		return nil
	}

	header := "[WHITE] Currently whitelisted IPs/ranges"
	if search != "" {
		header += fmt.Sprintf(" (searching for: %s)", search)
	}
	fmt.Printf("%s:\n", header)

	for _, ip := range ips {
		fmt.Printf(" - %s\n", ip)
	}

	if limit > 0 && total >= limit {
		fmt.Printf("\n[WARN]  Showing up to %d entries (limit reached).\n", limit)
	}
	return nil
}

/**
 * ShowTopStats displays the top IPs by traffic and drop counts.
 * ShowTopStats 显示按流量和丢弃计数排序的前几名 IP。
 */
func ShowTopStats(ctx context.Context, xdpMgr XDPManager, limit int, sortBy string) error {
	log := logger.Get(ctx)
	// 1. Fetch Stats / 获取统计信息
	dropDetails, err := xdpMgr.GetDropDetails()
	if err != nil {
		log.Warnf("[WARN]  Could not retrieve drop details: %v", err)
	}

	passDetails, err := xdpMgr.GetPassDetails()
	if err != nil {
		log.Warnf("[WARN]  Could not retrieve pass details: %v", err)
	}

	if dropDetails == nil && passDetails == nil {
		fmt.Println("[ERROR] No stats available (maps not loaded?)")
		return nil
	}

	// 2. Aggregate by IP / 按 IP 聚合
	type IPStats struct {
		IP    string
		Pass  uint64
		Drop  uint64
		Total uint64
	}
	agg := make(map[string]*IPStats)

	// 3. Process Drop Stats / 3. 处理丢弃统计
	for _, s := range dropDetails {
		if _, ok := agg[s.SrcIP]; !ok {
			agg[s.SrcIP] = &IPStats{IP: s.SrcIP}
		}
		agg[s.SrcIP].Drop += s.Count
		agg[s.SrcIP].Total += s.Count
	}

	// 4. Process Pass Stats / 4. 处理通过统计
	for _, s := range passDetails {
		if _, ok := agg[s.SrcIP]; !ok {
			agg[s.SrcIP] = &IPStats{IP: s.SrcIP}
		}
		agg[s.SrcIP].Pass += s.Count
		agg[s.SrcIP].Total += s.Count
	}

	// 5. Convert to slice and sort / 5. 转换为切片并排序
	statsList := make([]*IPStats, 0, len(agg))
	for _, s := range agg {
		statsList = append(statsList, s)
	}

	sort.Slice(statsList, func(i, j int) bool {
		if sortBy == "drop" {
			return statsList[i].Drop > statsList[j].Drop
		} else if sortBy == "pass" {
			return statsList[i].Pass > statsList[j].Pass
		}
		return statsList[i].Total > statsList[j].Total
	})

	// 6. Print / 6. 打印
	fmt.Printf("\n%-20s | %-12s | %-12s | %-12s\n", "IP ADDRESS", "PASS (PKTS)", "DROP (PKTS)", "TOTAL (PKTS)")
	fmt.Println(strings.Repeat("-", 65))

	for i, s := range statsList {
		if i >= limit {
			break
		}
		fmt.Printf("%-20s | %-12d | %-12d | %-12d\n", s.IP, s.Pass, s.Drop, s.Total)
	}

	return nil
}

/**
 * ShowConntrack reads and prints all active connections.
 * ShowConntrack 读取并打印所有活动连接。
 */
func ShowConntrack(ctx context.Context, xdpMgr XDPManager) error {
	entries, err := xdpMgr.ListAllConntrackEntries()
	if err != nil {
		return fmt.Errorf("failed to list conntrack entries: %v", err)
	}

	fmt.Println("[TRACK]  Active Connections (Conntrack):")
	if len(entries) == 0 {
		fmt.Println(" - No active connections.")
		return nil
	}

	fmt.Printf("%-40s %-5s %-40s %-5s %-8s\n", "Source", "Port", "Destination", "Port", "Protocol")
	fmt.Println(strings.Repeat("-", 110))

	// Sort entries for better display / 排序条目以获得更好的显示效果
	// In a real scenario, we might want to group by src/dst / 在实际场景中，我们可能希望按源/目的分组
	for _, e := range entries {
		proto := fmt.Sprintf("%d", e.Protocol)
		if e.Protocol == 6 {
			proto = protoTCP
		} else if e.Protocol == 17 {
			proto = protoUDP
		} else if e.Protocol == 1 {
			proto = protoICMP
		} else if e.Protocol == 58 {
			proto = protoICMPv6
		}
		fmt.Printf("%-40s %-5d %-40s %-5d %-8s\n", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, proto)
	}
	fmt.Printf("\nTotal active connections: %d\n", len(entries))
	return nil
}

/**
 * ShowIPPortRules reads and prints all IP+Port rules.
 * ShowIPPortRules 读取并打印所有 IP+端口规则。
 */
func ShowIPPortRules(ctx context.Context, xdpMgr XDPManager, limit int, search string) error {
	rules, total, err := xdpMgr.ListIPPortRules(false, limit, search)
	if err != nil {
		return fmt.Errorf("failed to list IP+Port rules: %v", err)
	}

	ports, err := xdpMgr.ListAllowedPorts()
	if err != nil {
		return fmt.Errorf("failed to list allowed ports: %v", err)
	}

	fmt.Println("[SHIELD] Current IP+Port Rules:")
	if len(rules) == 0 {
		fmt.Println(" - No IP+Port rules.")
	} else {
		for _, rule := range rules {
			actionStr := "Deny"
			if rule.Action == 1 {
				actionStr = "Allow"
			}
			fmt.Printf(" - %s:%d -> %s\n", rule.IP, rule.Port, actionStr)
		}
	}

	if limit > 0 && total >= limit {
		fmt.Printf("\n[WARN]  Showing up to %d entries (limit reached).\n", limit)
	}

	fmt.Println("\n[UNLOCK] Globally Allowed Ports:")
	if len(ports) == 0 {
		fmt.Println(" - No ports globally allowed.")
	} else {
		for _, port := range ports {
			fmt.Printf(" - Port %d\n", port)
		}
	}
	return nil
}

/**
 * ShowRateLimitRules reads and prints all rate limit rules.
 * ShowRateLimitRules 读取并打印所有速率限制规则。
 */
func ShowRateLimitRules(ctx context.Context, xdpMgr XDPManager) error {
	rules, _, err := xdpMgr.ListRateLimitRules(0, "")
	if err != nil {
		return fmt.Errorf("failed to list rate limit rules: %v", err)
	}

	fmt.Println("[START] Current Rate Limit Rules (Traffic Control):")
	if len(rules) == 0 {
		fmt.Println(" - No rate limit rules defined.")
		return nil
	}

	fmt.Printf("%-30s %-15s %-15s\n", "IP/CIDR", "Rate (PPS)", "Burst")
	fmt.Println(strings.Repeat("-", 60))

	for target, conf := range rules {
		fmt.Printf("%-30s %-15d %-15d\n", target, conf.Rate, conf.Burst)
	}
	return nil
}

/**
 * ShowStatus displays the current firewall status and statistics.
 * ShowStatus 显示当前的防火墙状态和统计信息。
 */
func ShowStatus(ctx context.Context, xdpMgr XDPManager) error {
	log := logger.Get(ctx)
	_, loadErr := types.LoadGlobalConfig(config.GetConfigPath())
	if loadErr != nil {
		log.Warnf("[WARN]  Could not load global config: %v", loadErr)
	}

	fmt.Println("[OK] XDP Program Status: Loaded and Running")

	showDropStats(xdpMgr)
	showPassStats(xdpMgr)
	showCounts(xdpMgr)
	showGlobalConfig(xdpMgr.GlobalConfig())
	showAttachedInterfaces()

	return nil
}
