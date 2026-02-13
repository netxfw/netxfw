package core

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

/**
 * getXDPMode returns the XDP attachment mode for a given interface.
 */
func getXDPMode(iface string) string {
	cmd := exec.Command("ip", "link", "show", iface)
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
 */
func ShowWhitelist(limit int, search string) {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load whitelist map: %v", err)
	}
	defer m.Close()

	ips, total, err := xdp.ListWhitelistedIPs(m, false, limit, search)
	if err != nil {
		log.Fatalf("❌ Failed to list whitelisted IPs: %v", err)
	}

	if len(ips) == 0 {
		fmt.Println("Empty whitelist.")
		return
	}

	header := "⚪ Currently whitelisted IPs/ranges"
	if search != "" {
		header += fmt.Sprintf(" (searching for: %s)", search)
	}
	fmt.Printf("%s:\n", header)

	for _, ip := range ips {
		fmt.Printf(" - %s\n", ip)
	}

	if limit > 0 && total >= limit {
		fmt.Printf("\n⚠️  Showing up to %d entries (limit reached).\n", limit)
	}
}

/**
 * ShowTopStats displays the top IPs by traffic and drop counts.
 */
func ShowTopStats(limit int, sortBy string) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		fmt.Println("❌ XDP Program Status: Not Loaded (or maps not pinned)")
		return
	}
	defer m.Close()

	// 1. Fetch Stats
	dropDetails, err := m.GetDropDetails()
	if err != nil {
		fmt.Printf("⚠️  Could not retrieve drop details: %v\n", err)
	}
	passDetails, err := m.GetPassDetails()
	if err != nil {
		fmt.Printf("⚠️  Could not retrieve pass details: %v\n", err)
	}

	// 2. Aggregate by IP
	type IpStats struct {
		IP    string
		Pass  uint64
		Drop  uint64
		Total uint64
	}
	statsMap := make(map[string]*IpStats)

	for _, d := range dropDetails {
		if _, ok := statsMap[d.SrcIP]; !ok {
			statsMap[d.SrcIP] = &IpStats{IP: d.SrcIP}
		}
		statsMap[d.SrcIP].Drop += d.Count
		statsMap[d.SrcIP].Total += d.Count
	}

	for _, p := range passDetails {
		if _, ok := statsMap[p.SrcIP]; !ok {
			statsMap[p.SrcIP] = &IpStats{IP: p.SrcIP}
		}
		statsMap[p.SrcIP].Pass += p.Count
		statsMap[p.SrcIP].Total += p.Count
	}

	// 3. Convert to Slice
	var statsList []*IpStats
	for _, s := range statsMap {
		statsList = append(statsList, s)
	}

	// 4. Sort
	sort.Slice(statsList, func(i, j int) bool {
		if sortBy == "drop" {
			return statsList[i].Drop > statsList[j].Drop
		}
		return statsList[i].Total > statsList[j].Total
	})

	// 5. Display
	fmt.Printf("📊 Top %d IPs by %s (Total Traffic/Drops)\n", limit, sortBy)
	fmt.Printf("%-40s %-15s %-15s %-15s\n", "Source IP", "Total Packets", "Pass", "Drop")
	fmt.Println(strings.Repeat("-", 90))

	count := 0
	for _, s := range statsList {
		if count >= limit {
			break
		}
		fmt.Printf("%-40s %-15d %-15d %-15d\n", s.IP, s.Total, s.Pass, s.Drop)
		count++
	}
}

/**
 * ShowConntrack reads and prints all active connections.
 */
func ShowConntrack() {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		fmt.Println("❌ XDP Program Status: Not Loaded (or maps not pinned)")
		return
	}
	defer m.Close()

	entries, err := m.ListConntrackEntries()
	if err != nil {
		log.Fatalf("❌ Failed to list conntrack entries: %v", err)
	}

	fmt.Println("🕵️  Active Connections (Conntrack):")
	if len(entries) == 0 {
		fmt.Println(" - No active connections.")
		return
	}

	fmt.Printf("%-40s %-5s %-40s %-5s %-8s\n", "Source", "Port", "Destination", "Port", "Protocol")
	fmt.Println(strings.Repeat("-", 110))

	// Sort entries for better display
	// In a real scenario, we might want to group by src/dst
	for _, e := range entries {
		proto := fmt.Sprintf("%d", e.Protocol)
		if e.Protocol == 6 {
			proto = "TCP"
		} else if e.Protocol == 17 {
			proto = "UDP"
		} else if e.Protocol == 1 {
			proto = "ICMP"
		} else if e.Protocol == 58 {
			proto = "ICMPv6"
		}
		fmt.Printf("%-40s %-5d %-40s %-5d %-8s\n", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, proto)
	}
	fmt.Printf("\nTotal active connections: %d\n", len(entries))
}

/**
 * ShowIPPortRules reads and prints all IP+Port rules.
 */
func ShowIPPortRules(limit int, search string) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	rules, total, err := m.ListIPPortRules(false, limit, search)
	if err != nil {
		log.Fatalf("❌ Failed to list IP+Port rules: %v", err)
	}

	ports, err := m.ListAllowedPorts()
	if err != nil {
		log.Fatalf("❌ Failed to list allowed ports: %v", err)
	}

	fmt.Println("🛡️ Current IP+Port Rules:")
	if len(rules) == 0 {
		fmt.Println(" - No IP+Port rules.")
	} else {
		for target, action := range rules {
			fmt.Printf(" - %s -> %s\n", target, action)
		}
	}

	if limit > 0 && total >= limit {
		fmt.Printf("\n⚠️  Showing up to %d entries (limit reached).\n", limit)
	}

	fmt.Println("\n🔓 Globally Allowed Ports:")
	if len(ports) == 0 {
		fmt.Println(" - No ports globally allowed.")
	} else {
		for _, port := range ports {
			fmt.Printf(" - Port %d\n", port)
		}
	}
}

/**
 * ShowRateLimitRules reads and prints all rate limit rules.
 */
func ShowRateLimitRules() {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	rules, _, err := m.ListRateLimitRules(0, "")
	if err != nil {
		log.Fatalf("❌ Failed to list rate limit rules: %v", err)
	}

	fmt.Println("🚀 Current Rate Limit Rules (Traffic Control):")
	if len(rules) == 0 {
		fmt.Println(" - No rate limit rules defined.")
		return
	}

	fmt.Printf("%-30s %-15s %-15s\n", "IP/CIDR", "Rate (PPS)", "Burst")
	fmt.Println(strings.Repeat("-", 60))

	for target, conf := range rules {
		fmt.Printf("%-30s %-15d %-15d\n", target, conf.Rate, conf.Burst)
	}
}

/**
 * ShowStatus displays the current firewall status and statistics.
 */
func ShowStatus() {
	cfg, _ := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	edition := "standalone"
	if cfg != nil && cfg.Edition != "" {
		edition = cfg.Edition
	}

	fmt.Printf("🚀 netxfw Edition: %s\n", edition)

	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		fmt.Println("❌ XDP Program Status: Not Loaded (or maps not pinned)")
		return
	}
	defer m.Close()

	fmt.Println("✅ XDP Program Status: Loaded and Running")

	// Get drop stats
	drops, err := m.GetDropCount()
	if err != nil {
		fmt.Printf("⚠️  Could not retrieve drop statistics: %v\n", err)
	} else {
		fmt.Printf("📊 Global Drop Count: %d packets\n", drops)

		// Show detailed drop stats
		details, err := m.GetDropDetails()
		if err == nil && len(details) > 0 {
			// Sort by count descending
			sort.Slice(details, func(i, j int) bool {
				return details[i].Count > details[j].Count
			})

			fmt.Println("\n   🚫 Top Drops by Reason & Source:")
			// Aggregate by reason for summary, or show top N entries
			// Let's just list them nicely formatted
			fmt.Printf("   %-20s %-8s %-40s %-8s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count")
			fmt.Printf("   %s\n", strings.Repeat("-", 90))

			// Simple map to string
			reasonStr := func(r uint32) string {
				switch r {
				case 0:
					return "UNKNOWN"
				case 1:
					return "INVALID"
				case 2:
					return "PROTOCOL"
				case 3:
					return "BLACKLIST"
				case 4:
					return "RATELIMIT"
				case 5:
					return "STRICT_TCP"
				case 6:
					return "DEFAULT_DENY"
				case 7:
					return "LAND_ATTACK"
				case 8:
					return "BOGON"
				case 9:
					return "FRAGMENT"
				case 10:
					return "BAD_HEADER"
				case 11:
					return "TCP_FLAGS"
				case 12:
					return "SPOOF"
				case 13:
					return "GEOIP"
				default:
					return fmt.Sprintf("UNKNOWN(%d)", r)
				}
			}

			protoStr := func(p uint32) string {
				switch p {
				case 6:
					return "TCP"
				case 17:
					return "UDP"
				case 1:
					return "ICMP"
				default:
					return fmt.Sprintf("%d", p)
				}
			}

			count := 0
			for _, d := range details {
				if count >= 10 {
					fmt.Printf("   ... and more\n")
					break
				}
				fmt.Printf("   %-20s %-8s %-40s %-8d %d\n",
					reasonStr(d.Reason),
					protoStr(d.Protocol),
					d.SrcIP,
					d.DstPort,
					d.Count,
				)
				count++
			}
		}
	}

	// Get pass stats
	passes, err := m.GetPassCount()
	if err != nil {
		fmt.Printf("⚠️  Could not retrieve pass statistics: %v\n", err)
	} else {
		fmt.Printf("📊 Global Pass Count: %d packets\n", passes)

		// Show detailed pass stats
		details, err := m.GetPassDetails()
		if err == nil && len(details) > 0 {
			// Sort by count descending
			sort.Slice(details, func(i, j int) bool {
				return details[i].Count > details[j].Count
			})

			fmt.Println("\n   ✅ Top Allowed by Reason & Source:")
			fmt.Printf("   %-20s %-8s %-40s %-8s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count")
			fmt.Printf("   %s\n", strings.Repeat("-", 90))

			reasonStr := func(r uint32) string {
				switch r {
				case 100:
					return "UNKNOWN"
				case 101:
					return "WHITELIST"
				case 102:
					return "RETURN"
				case 103:
					return "CONNTRACK"
				case 104:
					return "DEFAULT_ALLOW"
				default:
					return fmt.Sprintf("UNKNOWN(%d)", r)
				}
			}

			protoStr := func(p uint32) string {
				switch p {
				case 6:
					return "TCP"
				case 17:
					return "UDP"
				case 1:
					return "ICMP"
				default:
					return fmt.Sprintf("%d", p)
				}
			}

			count := 0
			for _, d := range details {
				if count >= 10 {
					fmt.Printf("   ... and more\n")
					break
				}
				fmt.Printf("   %-20s %-8s %-40s %-8d %d\n",
					reasonStr(d.Reason),
					protoStr(d.Protocol),
					d.SrcIP,
					d.DstPort,
					d.Count,
				)
				count++
			}
		}
	}

	// Get locked IP count
	lockedCount, err := m.GetLockedIPCount()
	if err == nil {
		fmt.Printf("🔒 Locked IP Count: %d addresses\n", lockedCount)
	}

	// Get whitelist count
	whitelistCount, err := m.GetWhitelistCount()
	if err == nil {
		fmt.Printf("⚪ Whitelist Count: %d addresses\n", whitelistCount)
	}

	// Get conntrack count
	ctCount, err := m.GetConntrackCount()
	if err == nil {
		fmt.Printf("🕵️  Active Connections: %d\n", ctCount)
	}

	// Check default deny policy
	var key uint32 = 0 // CONFIG_DEFAULT_DENY
	var val uint64
	if err := m.GlobalConfig().Lookup(&key, &val); err == nil {
		status := "Disabled (Allow by default)"
		if val == 1 {
			status = "Enabled (Deny by default)"
		}
		fmt.Printf("🛡️  Default Deny Policy: %s\n", status)
	}

	// Check allow return traffic
	key = 1 // CONFIG_ALLOW_RETURN_TRAFFIC
	if err := m.GlobalConfig().Lookup(&key, &val); err == nil {
		status := "Disabled"
		if val == 1 {
			status = "Enabled"
		}
		fmt.Printf("🔄 Allow Return Traffic: %s\n", status)
	}

	// Check allow ICMP
	key = 2 // CONFIG_ALLOW_ICMP
	if err := m.GlobalConfig().Lookup(&key, &val); err == nil {
		status := "Disabled"
		if val == 1 {
			status = "Enabled"
		}
		fmt.Printf("🏓 Allow ICMP (Ping): %s\n", status)

		if val == 1 {
			// Check rate limits
			var rate, burst uint64
			kRate := uint32(5)  // CONFIG_ICMP_RATE
			kBurst := uint32(6) // CONFIG_ICMP_BURST
			if err := m.GlobalConfig().Lookup(&kRate, &rate); err == nil {
				if err := m.GlobalConfig().Lookup(&kBurst, &burst); err == nil {
					fmt.Printf("   ├─ Rate Limit: %d packets/sec\n", rate)
					fmt.Printf("   └─ Burst Limit: %d packets\n", burst)
				}
			}
		}
	}

	// Check conntrack
	key = 3 // CONFIG_ENABLE_CONNTRACK
	if err := m.GlobalConfig().Lookup(&key, &val); err == nil {
		status := "Disabled"
		if val == 1 {
			status = "Enabled"
		}
		fmt.Printf("🕵️  Connection Tracking: %s\n", status)

		if val == 1 {
			kTimeout := uint32(4) // CONFIG_CONNTRACK_TIMEOUT
			var timeoutNs uint64
			if err := m.GlobalConfig().Lookup(&kTimeout, &timeoutNs); err == nil {
				fmt.Printf("   └─ Idle Timeout: %v\n", time.Duration(timeoutNs))
			}
		}
	}

	// Check global ratelimit
	key = 10 // CONFIG_ENABLE_RATELIMIT
	if err := m.GlobalConfig().Lookup(&key, &val); err == nil {
		status := "Disabled"
		if val == 1 {
			status = "Enabled"
		}
		fmt.Printf("🚀 Global Rate Limiting: %s\n", status)
	}

	// Check attached interfaces
	fmt.Println("\n🔗 Attached Interfaces:")
	files, _ := os.ReadDir("/sys/fs/bpf/netxfw")
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
