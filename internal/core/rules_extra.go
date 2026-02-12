package core

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/xdp"
)

// SyncIPPortRule updates the ip_port_rules map and config.
// action: 1 = Allow, 2 = Deny (mapped from CLI)
func SyncIPPortRule(ip string, port uint16, action uint8, add bool) {
	mapPath := "/sys/fs/bpf/netxfw/ip_port_rules"
	if IsIPv6(ip) {
		mapPath = "/sys/fs/bpf/netxfw/ip_port_rules6"
	}

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the daemon running?): %v", err)
	}
	defer m.Close()

	cidr := ensureCIDR(ip)

	if add {
		if err := xdp.AddIPPortRule(m, cidr, port, action); err != nil {
			log.Fatalf("❌ Failed to add rule %s:%d: %v", cidr, port, err)
		}
		log.Printf("🛡️ Added IP+Port rule: %s:%d -> Action %d", cidr, port, action)
	} else {
		if err := xdp.RemoveIPPortRule(m, cidr, port); err != nil {
			log.Printf("⚠️  Failed to remove rule %s:%d: %v", cidr, port, err)
		} else {
			log.Printf("🛡️ Removed IP+Port rule: %s:%d", cidr, port)
		}
	}

	// Update Config
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		newRules := []types.IPPortRule{}
		modified := false
		targetCIDR := ensureCIDR(ip)

		for _, r := range globalCfg.Port.IPPortRules {
			// Normalize existing rule IP
			ruleCIDR := ensureCIDR(r.IP)
			if ruleCIDR == targetCIDR && r.Port == port {
				if add {
					// Update existing if action changed
					if r.Action != action {
						r.Action = action
						modified = true
					}
					newRules = append(newRules, r) // Keep it (updated or same)
				} else {
					modified = true // Remove it (skip append)
				}
			} else {
				newRules = append(newRules, r)
			}
		}

		if add && !modified {
			// Check if we found it in the loop (if add=true and not modified, it means we didn't find it to update, so append new)
			// Actually the logic above: if found, we append it. If not found, we haven't appended it.
			// Let's rewrite:
			found := false
			for i, r := range newRules {
				if ensureCIDR(r.IP) == targetCIDR && r.Port == port {
					found = true
					if r.Action != action {
						newRules[i].Action = action
						modified = true
					}
					break
				}
			}
			if !found {
				newRules = append(newRules, types.IPPortRule{
					IP:     ip, // Use original input string for config readability if possible, or cidr
					Port:   port,
					Action: action,
				})
				modified = true
			}
		}

		if modified {
			globalCfg.Port.IPPortRules = newRules
			OptimizeIPPortRulesConfig(globalCfg)
			types.SaveGlobalConfig(configPath, globalCfg)
		}
	}
}

// SyncAllowedPort updates the allowed_ports map and config.
func SyncAllowedPort(port uint16, add bool) {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/allowed_ports", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map: %v", err)
	}
	defer m.Close()

	if add {
		if err := xdp.AllowPort(m, port); err != nil {
			log.Fatalf("❌ Failed to allow port %d: %v", port, err)
		}
		log.Printf("🔓 Allowed global port: %d", port)
	} else {
		if err := xdp.RemoveAllowedPort(m, port); err != nil {
			log.Printf("⚠️  Failed to remove allowed port %d: %v", port, err)
		} else {
			log.Printf("🔒 Removed allowed global port: %d", port)
		}
	}

	// Update Config
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		newPorts := []uint16{}
		modified := false
		found := false
		for _, p := range globalCfg.Port.AllowedPorts {
			if p == port {
				found = true
				if !add {
					modified = true // Remove
					continue
				}
			}
			newPorts = append(newPorts, p)
		}

		if add && !found {
			newPorts = append(newPorts, port)
			modified = true
		}

		if modified {
			globalCfg.Port.AllowedPorts = newPorts
			types.SaveGlobalConfig(configPath, globalCfg)
		}
	}
}

// SyncRateLimitRule updates the rate_limit_rules map and config.
func SyncRateLimitRule(ip string, rate uint64, burst uint64, add bool) {
	// Rate limit rules map handles both v4 and v6 keys if using LPM, but usually we separate them.
	// Let's check xdp_manager.go or netxfw.bpf.c.
	// Looking at netxfw.bpf.c, we have `rate_limit_rules` (LPM Trie) with generic key?
	// Usually LPM Tries are specific to key size (4 or 16 bytes).
	// Let's assume we have `rate_limit_rules` for IPv4 and `rate_limit_rules6` for IPv6.
	mapPath := "/sys/fs/bpf/netxfw/ratelimit_config"
	if IsIPv6(ip) {
		mapPath = "/sys/fs/bpf/netxfw/ratelimit_config6"
	}

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map: %v", err)
	}
	defer m.Close()

	cidr := ensureCIDR(ip)

	if add {
		if err := xdp.AddRateLimitRule(m, cidr, rate, burst); err != nil {
			log.Fatalf("❌ Failed to add rate limit rule %s: %v", cidr, err)
		}
		log.Printf("🚀 Added rate limit: %s -> %d pps (burst %d)", cidr, rate, burst)
	} else {
		if err := xdp.RemoveRateLimitRule(m, cidr); err != nil {
			log.Printf("⚠️  Failed to remove rate limit rule %s: %v", cidr, err)
		} else {
			log.Printf("🚀 Removed rate limit: %s", cidr)
		}
	}

	// Update Config
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		newRules := []types.RateLimitRule{}
		modified := false
		targetCIDR := ensureCIDR(ip)

		for _, r := range globalCfg.RateLimit.Rules {
			if ensureCIDR(r.IP) == targetCIDR {
				if add {
					// Update
					if r.Rate != rate || r.Burst != burst {
						r.Rate = rate
						r.Burst = burst
						modified = true
					}
					newRules = append(newRules, r)
				} else {
					modified = true // Remove
				}
			} else {
				newRules = append(newRules, r)
			}
		}

		if add && !modified {
			found := false
			for _, r := range newRules {
				if ensureCIDR(r.IP) == targetCIDR {
					found = true
					break
				}
			}
			if !found {
				newRules = append(newRules, types.RateLimitRule{
					IP:    ip,
					Rate:  rate,
					Burst: burst,
				})
				modified = true
			}
		}

		if modified {
			globalCfg.RateLimit.Rules = newRules
			types.SaveGlobalConfig(configPath, globalCfg)
		}
	}
}

// SyncAutoBlock updates the auto-block setting in config.
func SyncAutoBlock(enable bool) {
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.AutoBlock = enable
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Printf("🛡️ Auto Block set to: %v", enable)
	} else {
		log.Fatalf("❌ Failed to load config: %v", err)
	}
}

// SyncAutoBlockExpiry updates the auto-block expiry time in config.
func SyncAutoBlockExpiry(seconds uint32) {
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.AutoBlockExpiry = fmt.Sprintf("%ds", seconds)
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Printf("🛡️ Auto Block Expiry set to: %d seconds", seconds)
	} else {
		log.Fatalf("❌ Failed to load config: %v", err)
	}
}

// ClearBlacklist clears all entries from lock_list and lock_list6.
func ClearBlacklist() {
	log.Println("🧹 Clearing blacklist...")

	// Clear IPv4
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err == nil {
		if _, err := xdp.ClearMap(m4); err != nil {
			log.Printf("⚠️  Failed to clear IPv4 blacklist: %v", err)
		} else {
			log.Println("✅ IPv4 Blacklist cleared.")
		}
		m4.Close()
	}

	// Clear IPv6
	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err == nil {
		if _, err := xdp.ClearMap(m6); err != nil {
			log.Printf("⚠️  Failed to clear IPv6 blacklist: %v", err)
		} else {
			log.Println("✅ IPv6 Blacklist cleared.")
		}
		m6.Close()
	}

	// Clear persistence file
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil && globalCfg.Base.LockListFile != "" {
		if err := os.WriteFile(globalCfg.Base.LockListFile, []byte(""), 0644); err == nil {
			log.Printf("📄 Cleared persistence file: %s", globalCfg.Base.LockListFile)
		} else {
			log.Printf("⚠️  Failed to clear persistence file: %v", err)
		}
	}
}

// ImportLockListFromFile imports IPs from a file to the blacklist.
func ImportLockListFromFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ Failed to open file: %v", err)
	}
	defer file.Close()

	log.Printf("📦 Importing blacklist from %s...", path)
	scanner := bufio.NewScanner(file)
	count := 0

	// Use batch loading by reading all valid lines first
	var cidrs []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			cidrs = append(cidrs, line)
		}
	}

	// We reuse SyncLockMap for simplicity, but for performance with huge lists,
	// we should batch update. SyncLockMap handles conflict checks and persistence.
	// Since SyncLockMap writes to file every time, calling it in a loop is slow for persistence.
	// Better approach:
	// 1. Load Maps
	// 2. Iterate and update Maps directly
	// 3. Update persistence file once at the end

	m4, _ := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if m4 != nil {
		defer m4.Close()
	}
	m6, _ := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if m6 != nil {
		defer m6.Close()
	}

	// Prepare persistence update
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	var persistentLines []string
	if globalCfg != nil && globalCfg.Base.LockListFile != "" {
		// Read existing
		if content, err := os.ReadFile(globalCfg.Base.LockListFile); err == nil {
			lines := strings.Split(string(content), "\n")
			for _, l := range lines {
				if strings.TrimSpace(l) != "" {
					persistentLines = append(persistentLines, strings.TrimSpace(l))
				}
			}
		}
	}

	for _, cidr := range cidrs {
		// Check valid CIDR/IP
		if !strings.Contains(cidr, "/") {
			if IsIPv6(cidr) {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}

		// Update BPF
		var m *ebpf.Map
		if IsIPv6(cidr) {
			m = m6
		} else {
			m = m4
		}

		if m != nil {
			if err := xdp.LockIP(m, cidr); err != nil {
				log.Printf("⚠️  Failed to lock %s: %v", cidr, err)
			} else {
				count++
			}
		}

		// Update persistent list
		if globalCfg != nil && globalCfg.Base.PersistRules {
			persistentLines = append(persistentLines, cidr)
		}
	}

	// Save persistence
	if globalCfg != nil && globalCfg.Base.PersistRules && globalCfg.Base.LockListFile != "" {
		// Merge/Deduplicate
		merged, err := ipmerge.MergeCIDRsWithThreshold(persistentLines, globalCfg.Base.LockListMergeThreshold, globalCfg.Base.LockListV4Mask, globalCfg.Base.LockListV6Mask)
		if err != nil {
			merged = persistentLines
		}
		os.WriteFile(globalCfg.Base.LockListFile, []byte(strings.Join(merged, "\n")+"\n"), 0644)
		log.Printf("📄 Persisted %d rules to %s", len(merged), globalCfg.Base.LockListFile)
	}

	log.Printf("✅ Imported %d rules.", count)
}

// ImportWhitelistFromFile imports IPs from a file to the whitelist.
func ImportWhitelistFromFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ Failed to open file: %v", err)
	}
	defer file.Close()

	log.Printf("📦 Importing whitelist from %s...", path)
	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Format: IP or IP:Port
			var ip string
			var port uint16

			// Handle IPv6 [IP]:Port
			if strings.HasPrefix(line, "[") {
				end := strings.LastIndex(line, "]")
				if end != -1 {
					ip = line[1:end]
					if len(line) > end+2 && line[end+1] == ':' {
						fmt.Sscanf(line[end+2:], "%d", &port)
					}
				}
			} else {
				// IPv4 or IPv6 without brackets (if no port)
				// If contains slash (CIDR), assume no port unless :port is after CIDR
				// Actually SyncWhitelistMap expects "IP" or "CIDR" string and port uint16.

				// Try to parse as IP:Port
				host, portStr, err := net.SplitHostPort(line)
				if err == nil {
					ip = host
					p, _ := strconv.Atoi(portStr)
					port = uint16(p)
				} else {
					ip = line
					port = 0
				}
			}

			SyncWhitelistMap(ip, port, true)
			count++
		}
	}
	log.Printf("✅ Imported %d whitelist rules.", count)
}

// ImportIPPortRulesFromFile imports IP+Port rules.
func ImportIPPortRulesFromFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ Failed to open file: %v", err)
	}
	defer file.Close()

	log.Printf("📦 Importing IP+Port rules from %s...", path)
	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Format: IP Port Action (allow/deny)
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ip := parts[0]
				port, _ := strconv.Atoi(parts[1])
				actionStr := strings.ToLower(parts[2])
				action := uint8(2) // Deny
				if actionStr == "allow" {
					action = 1
				}

				SyncIPPortRule(ip, uint16(port), action, true)
				count++
			}
		}
	}
	log.Printf("✅ Imported %d IP+Port rules.", count)
}
