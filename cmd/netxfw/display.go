package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/cilium/ebpf"
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
func showIPPortRules() {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	rules4, err := m.ListIPPortRules(false)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv4 IP+Port rules: %v", err)
	}

	rules6, err := m.ListIPPortRules(true)
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
 * showStatus displays the current firewall status and statistics.
 */
func showStatus() {
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

	// Check default deny policy
	var key uint32 = 0 // CONFIG_DEFAULT_DENY
	var val uint32
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

