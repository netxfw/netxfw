package core

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

// SyncToConfig dumps current BPF map states to configuration files.
// This is useful if the config files were lost or if changes were made directly to maps.
func SyncToConfig() {
	log.Println("🔄 Syncing BPF Maps to Configuration Files...")
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	// 1. Sync Blacklist (lock_list) -> rules.deny.txt (or configured file)
	syncBlacklistToConfig(globalCfg)

	// 2. Sync Whitelist (whitelist) -> config.yaml
	syncWhitelistToConfig(globalCfg)

	// 3. Sync IP Port Rules -> config.yaml
	syncIPPortRulesToConfig(globalCfg)

	// 4. Sync Allowed Ports -> config.yaml
	syncAllowedPortsToConfig(globalCfg)

	// 5. Sync Rate Limits -> config.yaml
	syncRateLimitsToConfig(globalCfg)

	// Save final config
	if err := types.SaveGlobalConfig(configPath, globalCfg); err != nil {
		log.Fatalf("❌ Failed to save config: %v", err)
	}
	log.Println("✅ Configuration files updated successfully.")
}

// SyncToMap applies the current configuration files to the BPF maps.
// This overwrites the runtime state with what is in the files.
func SyncToMap() {
	log.Println("🔄 Syncing Configuration Files to BPF Maps...")
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	// 1. Sync Blacklist
	// We use ImportLockListFromFile which merges with existing map, but for "SyncToMap"
	// we arguably should clear and reload, or just ensure everything in file is in map.
	// Users usually expect "apply this config".
	if globalCfg.Base.LockListFile != "" {
		log.Printf("📥 Importing Blacklist from %s...", globalCfg.Base.LockListFile)
		ImportLockListFromFile(globalCfg.Base.LockListFile)
	}

	// 2. Sync Whitelist
	// We need to ensure everything in config is in map.
	// Ideally we should also remove things NOT in config?
	// "SyncToMap" usually implies "Make Map match Config".
	// So we should probably clear maps first or carefully diff.
	// For safety, let's add missing entries first.
	// If strict sync is needed (remove extras), we need to clear map.
	// Let's go with "Clear and Load" for true sync.

	log.Println("🧹 Clearing and reloading Whitelist...")
	mWhitelist, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
	if err == nil {
		xdp.ClearMap(mWhitelist)
		mWhitelist.Close()
	}
	for _, ip := range globalCfg.Base.Whitelist {
		// Handle port logic if embedded in string
		// Reusing ImportWhitelistFromFile logic or calling SyncWhitelistMap
		var port uint16
		cidr := ip
		// Simple parsing (same as in rules.go)
		if strings.HasPrefix(ip, "[") && strings.Contains(ip, "]:") {
			endBracket := strings.LastIndex(ip, "]")
			portStr := ip[endBracket+2:]
			cidr = ip[1:endBracket]
			fmt.Sscanf(portStr, "%d", &port)
		} else if strings.Contains(ip, "/") {
			lastColon := strings.LastIndex(ip, ":")
			if lastColon > strings.LastIndex(ip, "/") {
				cidr = ip[:lastColon]
				portStr := ip[lastColon+1:]
				fmt.Sscanf(portStr, "%d", &port)
			}
		} else if !IsIPv6(ip) && strings.Contains(ip, ":") {
			parts := strings.Split(ip, ":")
			if len(parts) == 2 {
				cidr = parts[0]
				fmt.Sscanf(parts[1], "%d", &port)
			}
		}
		SyncWhitelistMap(cidr, port, true)
	}

	// 3. Sync IP Port Rules
	log.Println("🧹 Clearing and reloading IP Port Rules...")
	mIPPort, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/ip_port_rules", nil)
	if err == nil {
		xdp.ClearMap(mIPPort)
		mIPPort.Close()
	}
	for _, r := range globalCfg.Port.IPPortRules {
		SyncIPPortRule(r.IP, r.Port, r.Action, true)
	}

	// 4. Sync Allowed Ports
	log.Println("🧹 Clearing and reloading Allowed Ports...")
	mPorts, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/allowed_ports", nil)
	if err == nil {
		xdp.ClearMap(mPorts)
		mPorts.Close()
	}
	for _, p := range globalCfg.Port.AllowedPorts {
		// Re-implement simplified version of SyncAllowedPort to avoid config write-back loop
		// or just use xdp directly
		mp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/allowed_ports", nil)
		if err == nil {
			xdp.AllowPort(mp, p)
			mp.Close()
		}
	}

	// 5. Sync Rate Limits
	log.Println("🧹 Clearing and reloading Rate Limits...")
	mRate, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/ratelimit_config", nil)
	if err == nil {
		xdp.ClearMap(mRate)
		mRate.Close()
	}
	for _, r := range globalCfg.RateLimit.Rules {
		SyncRateLimitRule(r.IP, r.Rate, r.Burst, true)
	}

	log.Println("✅ BPF Maps synced from configuration.")
}

// Helpers

func syncBlacklistToConfig(cfg *types.GlobalConfig) {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err != nil {
		log.Printf("⚠️  Failed to load lock_list map: %v", err)
		return
	}
	defer m.Close()

	ips, _, err := xdp.ListBlockedIPs(m, false, 0, "")
	if err != nil {
		log.Printf("⚠️  Failed to list blocked IPs: %v", err)
		return
	}

	// Also get dynamic lock list if exists
	md, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/dyn_lock_list", nil)
	if err == nil {
		defer md.Close()
		dynIps, _, _ := xdp.ListBlockedIPs(md, false, 0, "")
		for _, ip := range dynIps {
			ips = append(ips, ip)
		}
	}

	// Extract just the IP strings from the first list too
	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.IP)
	}

	sort.Strings(ipStrings)

	if cfg.Base.LockListFile != "" {
		err := os.WriteFile(cfg.Base.LockListFile, []byte(strings.Join(ipStrings, "\n")+"\n"), 0644)
		if err != nil {
			log.Printf("❌ Failed to write blacklist file: %v", err)
		} else {
			log.Printf("📄 Exported %d blacklist rules to %s", len(ips), cfg.Base.LockListFile)
		}
	}
}

func syncWhitelistToConfig(cfg *types.GlobalConfig) {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
	if err != nil {
		log.Printf("⚠️  Failed to load whitelist map: %v", err)
		return
	}
	defer m.Close()

	// Need to implement ListWhitelistIPs similar to ListBlockedIPs but handling port value
	// For now, we reuse xdp.ListBlockedIPs which handles the key iteration.
	// But the value in whitelist map is port (uint16), while ListBlockedIPs expects NetXfwRuleValue.
	// Wait, whitelist map is LPM key -> uint32 value (port).
	// xdp.ListBlockedIPs might fail if value size is different?
	// Let's check maps.bpf.h
	// struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); ... __type(value, __u32); } whitelist;
	// struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); ... __type(value, struct rule_value); } lock_list;
	// rule_value is { u64 counter, u64 expires_at } (16 bytes).
	// whitelist value is u32 (4 bytes).
	// So ListBlockedIPs will fail on value unmarshal.

	// We need a specific lister for whitelist.
	ips, err := listWhitelistEntries(m)
	if err != nil {
		log.Printf("⚠️  Failed to list whitelist IPs: %v", err)
		return
	}

	cfg.Base.Whitelist = ips
	log.Printf("📄 Updated config whitelist with %d entries", len(ips))
}

func listWhitelistEntries(m *ebpf.Map) ([]string, error) {
	var ips []string
	iter := m.Iterate()
	var key xdp.NetXfwLpmKey
	var val xdp.NetXfwRuleValue // Correct value type

	for iter.Next(&key, &val) {
		ipStr := xdp.FormatLpmKey(&key)
		// val.Counter holds the port number if > 1 (0 or 1 means all ports/wildcard)
		if val.Counter > 1 {
			if strings.Contains(ipStr, ":") && !strings.Contains(ipStr, ".") {
				// IPv6
				ipStr = fmt.Sprintf("[%s]:%d", ipStr, val.Counter)
			} else {
				ipStr = fmt.Sprintf("%s:%d", ipStr, val.Counter)
			}
		}
		ips = append(ips, ipStr)
	}
	return ips, iter.Err()
}

func syncIPPortRulesToConfig(cfg *types.GlobalConfig) {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/ip_port_rules", nil)
	if err != nil {
		return
	}
	defer m.Close()

	var rules []types.IPPortRule
	iter := m.Iterate()
	var key xdp.NetXfwLpmIpPortKey
	var val xdp.NetXfwRuleValue

	for iter.Next(&key, &val) {
		// Convert IP
		ip := xdp.FormatIn6Addr(&key.Ip)
		rules = append(rules, types.IPPortRule{
			IP:     ip,
			Port:   key.Port,
			Action: uint8(val.Counter), // 1=Allow, 2=Deny
		})
	}
	cfg.Port.IPPortRules = rules
	log.Printf("📄 Updated config IP Port Rules with %d entries", len(rules))
}

func syncAllowedPortsToConfig(cfg *types.GlobalConfig) {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/allowed_ports", nil)
	if err != nil {
		return
	}
	defer m.Close()

	var ports []uint16
	iter := m.Iterate()
	var port uint16
	var val uint8 // 1

	for iter.Next(&port, &val) {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	cfg.Port.AllowedPorts = ports
	log.Printf("📄 Updated config Allowed Ports with %d entries", len(ports))
}

func syncRateLimitsToConfig(cfg *types.GlobalConfig) {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/ratelimit_config", nil)
	if err != nil {
		return
	}
	defer m.Close()

	var rules []types.RateLimitRule
	iter := m.Iterate()
	var key xdp.NetXfwLpmKey
	var val struct {
		Rate  uint64
		Burst uint64
	}

	for iter.Next(&key, &val) {
		ip := xdp.FormatLpmKey(&key)
		rules = append(rules, types.RateLimitRule{
			IP:    ip,
			Rate:  val.Rate,
			Burst: val.Burst,
		})
	}
	cfg.RateLimit.Rules = rules
	log.Printf("📄 Updated config Rate Limits with %d entries", len(rules))
}
