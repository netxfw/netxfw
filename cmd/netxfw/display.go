package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
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
 * showWhitelist reads and prints all whitelisted ranges.
 */
func showWhitelist(limit int, search string) {
	type result struct {
		ver   int
		ips   []string
		total int
		err   error
	}
	resChan := make(chan result, 2)

	go func() {
		m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
		if err != nil {
			resChan <- result{ver: 4, err: err}
			return
		}
		defer m4.Close()
		ips, total, err := xdp.ListWhitelistedIPs(m4, false, limit, search)
		resChan <- result{ver: 4, ips: ips, total: total, err: err}
	}()

	go func() {
		m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist6", nil)
		if err != nil {
			resChan <- result{ver: 6, err: err}
			return
		}
		defer m6.Close()
		ips, total, err := xdp.ListWhitelistedIPs(m6, true, limit, search)
		resChan <- result{ver: 6, ips: ips, total: total, err: err}
	}()

	var ips4, ips6 []string
	var total4, total6 int
	for i := 0; i < 2; i++ {
		res := <-resChan
		if res.err != nil {
			log.Fatalf("❌ Failed to list IPv%d whitelisted IPs: %v", res.ver, res.err)
		}
		if res.ver == 4 {
			ips4, total4 = res.ips, res.total
		} else {
			ips6, total6 = res.ips, res.total
		}
	}

	if len(ips4) == 0 && len(ips6) == 0 {
		fmt.Println("Empty whitelist.")
		return
	}

	header := "⚪ Currently whitelisted IPs/ranges"
	if search != "" {
		header += fmt.Sprintf(" (searching for: %s)", search)
	}
	fmt.Printf("%s:\n", header)

	for _, ip := range ips4 {
		fmt.Printf(" - [IPv4] %s\n", ip)
	}
	for _, ip := range ips6 {
		fmt.Printf(" - [IPv6] %s\n", ip)
	}

	total := total4 + total6
	if limit > 0 && total >= limit {
		fmt.Printf("\n⚠️  Showing up to %d entries (limit reached).\n", limit)
	}
}

/**
 * showConntrack reads and prints all active connections.
 */
func showConntrack() {
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
 * showLockList reads and prints all blocked ranges and their stats.
 */
func showLockList(limit int, search string) {
	type result struct {
		ver   int
		ips   map[string]uint64
		total int
		err   error
	}
	resChan := make(chan result, 2)

	go func() {
		m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
		if err != nil {
			resChan <- result{ver: 4, err: err}
			return
		}
		defer m4.Close()
		ips, total, err := xdp.ListBlockedIPs(m4, false, limit, search)

		// Also check dyn_lock_list
		md4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/dyn_lock_list", nil)
		if err == nil {
			defer md4.Close()
			dynIps, dynTotal, _ := xdp.ListBlockedIPs(md4, false, limit, search)
			for k, v := range dynIps {
				ips[k+" (auto)"] = v
			}
			total += dynTotal
		}

		resChan <- result{ver: 4, ips: ips, total: total, err: err}
	}()

	go func() {
		m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
		if err != nil {
			resChan <- result{ver: 6, err: err}
			return
		}
		defer m6.Close()
		ips, total, err := xdp.ListBlockedIPs(m6, true, limit, search)

		// Also check dyn_lock_list6
		md6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/dyn_lock_list6", nil)
		if err == nil {
			defer md6.Close()
			dynIps, dynTotal, _ := xdp.ListBlockedIPs(md6, true, limit, search)
			for k, v := range dynIps {
				ips[k+" (auto)"] = v
			}
			total += dynTotal
		}

		resChan <- result{ver: 6, ips: ips, total: total, err: err}
	}()

	var ips4, ips6 map[string]uint64
	var total4, total6 int
	for i := 0; i < 2; i++ {
		res := <-resChan
		if res.err != nil {
			log.Fatalf("❌ Failed to list IPv%d locked IPs: %v", res.ver, res.err)
		}
		if res.ver == 4 {
			ips4, total4 = res.ips, res.total
		} else {
			ips6, total6 = res.ips, res.total
		}
	}

	if len(ips4) == 0 && len(ips6) == 0 {
		fmt.Println("Empty lock list.")
		return
	}

	header := "🛡️ Currently locked IPs/ranges and drop counts"
	if search != "" {
		header += fmt.Sprintf(" (searching for: %s)", search)
	}
	fmt.Printf("%s:\n", header)

	for ip, count := range ips4 {
		fmt.Printf(" - [IPv4] %s: %d drops\n", ip, count)
	}
	for ip, count := range ips6 {
		fmt.Printf(" - [IPv6] %s: %d drops\n", ip, count)
	}

	total := total4 + total6
	if limit > 0 && total >= limit {
		fmt.Printf("\n⚠️  Showing up to %d entries (limit reached).\n", limit)
	}
}

/**
 * showIPPortRules reads and prints all IP+Port rules.
 */
func showIPPortRules(limit int, search string) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	rules4, total4, err := m.ListIPPortRules(false, limit, search)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv4 IP+Port rules: %v", err)
	}

	rules6, total6, err := m.ListIPPortRules(true, limit, search)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv6 IP+Port rules: %v", err)
	}

	ports, err := m.ListAllowedPorts()
	if err != nil {
		log.Fatalf("❌ Failed to list allowed ports: %v", err)
	}

	fmt.Println("🛡️ Current IP+Port Rules:")
	if len(rules4) == 0 && len(rules6) == 0 {
		fmt.Println(" - No IP+Port rules.")
	} else {
		for target, action := range rules4 {
			fmt.Printf(" - [IPv4] %s -> %s\n", target, action)
		}
		for target, action := range rules6 {
			fmt.Printf(" - [IPv6] %s -> %s\n", target, action)
		}
	}

	total := total4 + total6
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
 * showRateLimitRules reads and prints all rate limit rules.
 */
func showRateLimitRules() {
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
 * showStatus displays the current firewall status and statistics.
 */
func showStatus() {
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
	}

	// Get pass stats
	passes, err := m.GetPassCount()
	if err == nil {
		fmt.Printf("📊 Global Pass Count: %d packets\n", passes)
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
