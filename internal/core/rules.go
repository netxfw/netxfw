package core

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/xdp"
)

/**
 * SyncLockMap interacts with pinned BPF maps to block/unblock ranges.
 */
func SyncLockMap(cidrStr string, lock bool) {
	mapPath := "/sys/fs/bpf/netxfw/lock_list"
	if IsIPv6(cidrStr) {
		mapPath = "/sys/fs/bpf/netxfw/lock_list6"
	}

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the daemon running?): %v", err)
	}
	defer m.Close()

	if lock {
		// Check for conflict in whitelist
		oppositeMapPath := "/sys/fs/bpf/netxfw/whitelist"
		if IsIPv6(cidrStr) {
			oppositeMapPath = "/sys/fs/bpf/netxfw/whitelist6"
		}
		if opM, err := ebpf.LoadPinnedMap(oppositeMapPath, nil); err == nil {
			if conflict, msg := xdp.CheckConflict(opM, cidrStr, true); conflict {
				fmt.Printf("⚠️  [Conflict] %s (Already in whitelist).\n", msg)
				if !AskConfirmation("Do you want to remove it from whitelist and add to blacklist?") {
					fmt.Println("Aborted.")
					opM.Close()
					return
				}
				// Remove from whitelist
				if err := xdp.UnlockIP(opM, cidrStr); err != nil {
					log.Printf("⚠️  Failed to remove from whitelist: %v", err)
				} else {
					log.Printf("🔓 Removed %s from whitelist", cidrStr)
					// Also update config
					globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
					if err == nil {
						newWhitelist := []string{}
						for _, ip := range globalCfg.Base.Whitelist {
							if ip != cidrStr && !strings.HasPrefix(ip, cidrStr+":") {
								newWhitelist = append(newWhitelist, ip)
							}
						}
						globalCfg.Base.Whitelist = newWhitelist
						types.SaveGlobalConfig("/etc/netxfw/config.yaml", globalCfg)
					}
				}
			}
			opM.Close()
		}

		if err := xdp.LockIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to lock %s: %v", cidrStr, err)
		}
		log.Printf("🛡️ Locked: %s", cidrStr)

		// Persist to LockListFile if enabled
		globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
		if err == nil && globalCfg.Base.PersistRules && globalCfg.Base.LockListFile != "" {
			filePath := globalCfg.Base.LockListFile

			// Read existing lines
			var lines []string
			if content, err := os.ReadFile(filePath); err == nil {
				for _, line := range strings.Split(string(content), "\n") {
					trimmed := strings.TrimSpace(line)
					if trimmed != "" {
						lines = append(lines, trimmed)
					}
				}
			}

			// Add new CIDR
			lines = append(lines, cidrStr)

			// Merge
			merged, err := ipmerge.MergeCIDRsWithThreshold(lines, globalCfg.Base.LockListMergeThreshold, globalCfg.Base.LockListV4Mask, globalCfg.Base.LockListV6Mask)
			if err != nil {
				log.Printf("⚠️  Failed to merge IPs for persistence: %v", err)
				merged = lines
			}

			// Write back
			if err := os.WriteFile(filePath, []byte(strings.Join(merged, "\n")+"\n"), 0644); err == nil {
				log.Printf("📄 Persisted %s to %s (Optimized to %d rules)", cidrStr, filePath, len(merged))

				// Runtime Optimization: Sync BPF with merged list if rules were reduced
				if len(merged) < len(lines) {
					log.Println("🔄 Optimizing runtime BPF map...")
					// 1. Add all merged rules (ensure broad subnets are added)
					for _, cidr := range merged {
						xdp.LockIP(m, cidr)
					}
					// 2. Remove obsolete rules (redundant small IPs)
					mergedSet := make(map[string]bool)
					for _, c := range merged {
						mergedSet[c] = true
					}
					for _, line := range lines {
						// Normalize line to CIDR format for comparison
						checkLine := line
						if !strings.Contains(line, "/") {
							if IsIPv6(line) {
								checkLine = line + "/128"
							} else {
								checkLine = line + "/32"
							}
						}
						if !mergedSet[checkLine] {
							xdp.UnlockIP(m, line)
						}
					}
				}
			} else {
				log.Printf("❌ Failed to write to %s: %v", filePath, err)
			}
		}
	} else {
		if err := xdp.UnlockIP(m, cidrStr); err != nil {
			if !strings.Contains(err.Error(), "key does not exist") {
				log.Printf("⚠️  Failed to unlock %s: %v", cidrStr, err)
			}
		} else {
			log.Printf("🔓 Unlocked: %s", cidrStr)
		}

		// Remove from LockListFile if enabled
		globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
		if err == nil && globalCfg.Base.PersistRules && globalCfg.Base.LockListFile != "" {
			filePath := globalCfg.Base.LockListFile
			if _, err := os.Stat(filePath); err == nil {
				// Read all lines except the one to remove
				input, _ := os.ReadFile(filePath)
				lines := strings.Split(string(input), "\n")
				var newLines []string
				modified := false
				for _, line := range lines {
					trimmed := strings.TrimSpace(line)
					if trimmed != "" && trimmed != cidrStr {
						newLines = append(newLines, trimmed)
					} else if trimmed == cidrStr {
						modified = true
					}
				}
				if modified {
					os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
					log.Printf("📄 Removed %s from %s", cidrStr, filePath)
				}
			}
		}
	}
}

func OptimizeWhitelistConfig(cfg *types.GlobalConfig) {
	rulesByPort := make(map[uint16][]string)
	for _, line := range cfg.Base.Whitelist {
		cidr := line
		var port uint16
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]:") {
			endBracket := strings.LastIndex(line, "]")
			portStr := line[endBracket+2:]
			cidr = line[1:endBracket]
			fmt.Sscanf(portStr, "%d", &port)
		} else if strings.Contains(line, "/") {
			lastColon := strings.LastIndex(line, ":")
			if lastColon > strings.LastIndex(line, "/") {
				portStr := line[lastColon+1:]
				cidr = line[:lastColon]
				fmt.Sscanf(portStr, "%d", &port)
			}
		} else if !IsIPv6(line) && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				cidr = parts[0]
				fmt.Sscanf(parts[1], "%d", &port)
			}
		}
		rulesByPort[port] = append(rulesByPort[port], cidr)
	}

	var newWhitelist []string
	for port, cidrs := range rulesByPort {
		merged, err := ipmerge.MergeCIDRs(cidrs)
		if err != nil {
			merged = cidrs
		}
		for _, cidr := range merged {
			entry := cidr
			if port > 0 {
				entry = fmt.Sprintf("%s:%d", cidr, port)
			}
			newWhitelist = append(newWhitelist, entry)
		}
	}
	cfg.Base.Whitelist = newWhitelist
}

func OptimizeIPPortRulesConfig(cfg *types.GlobalConfig) {
	type ruleKey struct {
		port   uint16
		action uint8
	}
	rulesByGroup := make(map[ruleKey][]string)

	for _, r := range cfg.Port.IPPortRules {
		key := ruleKey{r.Port, r.Action}
		rulesByGroup[key] = append(rulesByGroup[key], r.IP)
	}

	var newRules []types.IPPortRule
	for key, cidrs := range rulesByGroup {
		merged, err := ipmerge.MergeCIDRs(cidrs)
		if err != nil {
			merged = cidrs
		}
		for _, cidr := range merged {
			newRules = append(newRules, types.IPPortRule{
				IP:     cidr,
				Port:   key.port,
				Action: key.action,
			})
		}
	}
	cfg.Port.IPPortRules = newRules
}

/**
 * SyncWhitelistMap interacts with pinned BPF maps to allow/unallow ranges.
 */
func SyncWhitelistMap(cidrStr string, port uint16, allow bool) {
	mapPath := "/sys/fs/bpf/netxfw/whitelist"
	if IsIPv6(cidrStr) {
		mapPath = "/sys/fs/bpf/netxfw/whitelist6"
	}

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the daemon running?): %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)

	if allow {
		oppositeMapPath := "/sys/fs/bpf/netxfw/lock_list"
		if IsIPv6(cidrStr) {
			oppositeMapPath = "/sys/fs/bpf/netxfw/lock_list6"
		}
		if opM, err := ebpf.LoadPinnedMap(oppositeMapPath, nil); err == nil {
			if conflict, msg := xdp.CheckConflict(opM, cidrStr, false); conflict {
				fmt.Printf("⚠️  [Conflict] %s (Already in blacklist).\n", msg)
				if !AskConfirmation("Do you want to remove it from blacklist and add to whitelist?") {
					fmt.Println("Aborted.")
					opM.Close()
					return
				}
				if err := xdp.UnlockIP(opM, cidrStr); err != nil {
					log.Printf("⚠️  Failed to remove from blacklist: %v", err)
				} else {
					log.Printf("🔓 Removed %s from blacklist", cidrStr)
				}
			}
			opM.Close()
		}

		if err := xdp.AllowIP(m, cidrStr, port); err != nil {
			log.Fatalf("❌ Failed to allow %s: %v", cidrStr, err)
		}
		if port > 0 {
			log.Printf("⚪ Whitelisted: %s (port: %d)", cidrStr, port)
		} else {
			log.Printf("⚪ Whitelisted: %s", cidrStr)
		}

		if err == nil {
			entry := cidrStr
			if port > 0 {
				entry = fmt.Sprintf("%s:%d", cidrStr, port)
			}
			found := false
			for _, ip := range globalCfg.Base.Whitelist {
				if ip == entry {
					found = true
					break
				}
			}
			if !found {
				// Backup list before optimization to track changes
				oldWhitelist := make([]string, len(globalCfg.Base.Whitelist))
				copy(oldWhitelist, globalCfg.Base.Whitelist)

				globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, entry)
				OptimizeWhitelistConfig(globalCfg)
				types.SaveGlobalConfig(configPath, globalCfg)

				// Cleanup BPF: Remove rules that were merged into larger subnets
				newSet := make(map[string]bool)
				for _, ip := range globalCfg.Base.Whitelist {
					newSet[ip] = true
				}

				for _, oldEntry := range oldWhitelist {
					if !newSet[oldEntry] {
						// This entry was merged. Remove it from BPF.
						// Parse CIDR from entry (handling port if present)
						cidrToRemove := oldEntry
						if strings.HasPrefix(oldEntry, "[") && strings.Contains(oldEntry, "]:") {
							endBracket := strings.LastIndex(oldEntry, "]")
							cidrToRemove = oldEntry[1:endBracket]
						} else if strings.Contains(oldEntry, "/") {
							lastColon := strings.LastIndex(oldEntry, ":")
							if lastColon > strings.LastIndex(oldEntry, "/") {
								cidrToRemove = oldEntry[:lastColon]
							}
						} else if !IsIPv6(oldEntry) && strings.Contains(oldEntry, ":") {
							parts := strings.Split(oldEntry, ":")
							if len(parts) == 2 {
								cidrToRemove = parts[0]
							}
						}

						if err := xdp.UnlockIP(m, cidrToRemove); err != nil {
							// Ignore if already gone
						} else {
							log.Printf("🧹 Optimized runtime: Removed subsumed whitelist rule %s", cidrToRemove)
						}
					}
				}

				// Ensure merged rules are in BPF (in case a NEW merged rule was created)
				// E.g. added 1.2.3.4, merged with 1.2.3.5 -> 1.2.3.4/31.
				// We added 1.2.3.4. We removed 1.2.3.5 (if it was in oldList).
				// We need to add 1.2.3.4/31.
				for _, newEntry := range globalCfg.Base.Whitelist {
					// We can blindly add/update.
					// But we need to parse port.
					cidrToAdd := newEntry
					var portToAdd uint16

					if strings.HasPrefix(newEntry, "[") && strings.Contains(newEntry, "]:") {
						endBracket := strings.LastIndex(newEntry, "]")
						portStr := newEntry[endBracket+2:]
						cidrToAdd = newEntry[1:endBracket]
						fmt.Sscanf(portStr, "%d", &portToAdd)
					} else if strings.Contains(newEntry, "/") {
						lastColon := strings.LastIndex(newEntry, ":")
						if lastColon > strings.LastIndex(newEntry, "/") {
							cidrToAdd = newEntry[:lastColon]
							portStr := newEntry[lastColon+1:]
							fmt.Sscanf(portStr, "%d", &portToAdd)
						}
					} else if !IsIPv6(newEntry) && strings.Contains(newEntry, ":") {
						parts := strings.Split(newEntry, ":")
						if len(parts) == 2 {
							cidrToAdd = parts[0]
							fmt.Sscanf(parts[1], "%d", &portToAdd)
						}
					}

					// We only need to add if it wasn't the one we just added (which is already in BPF)
					// But it's safer to just ensure it's there.
					if err := xdp.AllowIP(m, cidrToAdd, portToAdd); err != nil {
						log.Printf("⚠️ Failed to sync merged rule to BPF: %s", cidrToAdd)
					}
				}
			}
		}
	} else {
		if err := xdp.UnlockIP(m, cidrStr); err != nil {
			if !strings.Contains(err.Error(), "key does not exist") {
				log.Printf("⚠️  Failed to unallow %s: %v", cidrStr, err)
			}
		} else {
			log.Printf("❌ Removed from whitelist: %s", cidrStr)
		}

		// Always try to remove from config if it exists there
		newWhitelist := []string{}
		modified := false
		for _, ip := range globalCfg.Base.Whitelist {
			if ip != cidrStr && !strings.HasPrefix(ip, cidrStr+":") {
				newWhitelist = append(newWhitelist, ip)
			} else {
				modified = true
			}
		}
		if modified {
			globalCfg.Base.Whitelist = newWhitelist
			types.SaveGlobalConfig(configPath, globalCfg)
			log.Printf("📄 Updated whitelist in config: removed %s", cidrStr)
		}
	}
}

func SyncDefaultDeny(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetDefaultDeny(enable); err != nil {
		log.Fatalf("❌ Failed to set default deny: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.DefaultDeny = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ Default deny policy set to: %v", enable)
}

func SyncEnableAFXDP(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetEnableAFXDP(enable); err != nil {
		log.Fatalf("❌ Failed to set enable AF_XDP: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.EnableAFXDP = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🚀 AF_XDP redirection set to: %v", enable)
}

func SyncEnableRateLimit(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetEnableRateLimit(enable); err != nil {
		log.Fatalf("❌ Failed to set enable ratelimit: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.Enabled = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🚀 Global rate limit set to: %v", enable)
}

func SyncDropFragments(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetDropFragments(enable); err != nil {
		log.Fatalf("❌ Failed to set drop fragments: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.DropFragments = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ IP Fragment dropping set to: %v", enable)
}

func SyncStrictTCP(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetStrictTCP(enable); err != nil {
		log.Fatalf("❌ Failed to set strict TCP: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.StrictTCP = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ Strict TCP validation set to: %v", enable)
}

func SyncSYNLimit(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetSYNLimit(enable); err != nil {
		log.Fatalf("❌ Failed to set SYN limit: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.SYNLimit = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ SYN-only rate limiting set to: %v", enable)
}

func SyncBogonFilter(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetBogonFilter(enable); err != nil {
		log.Fatalf("❌ Failed to set bogon filter: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.BogonFilter = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ Bogon IP filtering set to: %v", enable)
}

func SyncAllowedPort(port uint16, allow bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	if allow {
		mapFound := false
		ports, _ := m.ListAllowedPorts()
		for _, p := range ports {
			if p == port {
				mapFound = true
				break
			}
		}

		cfgFound := false
		for _, p := range globalCfg.Port.AllowedPorts {
			if p == port {
				cfgFound = true
				break
			}
		}

		if mapFound && cfgFound {
			log.Printf("ℹ️  Port %d is already globally allowed in both BPF and config.", port)
			return
		}

		if !mapFound {
			if err := m.AllowPort(port, nil); err != nil {
				log.Fatalf("❌ Failed to allow port %d: %v", port, err)
			}
		}

		if !cfgFound {
			globalCfg.Port.AllowedPorts = append(globalCfg.Port.AllowedPorts, port)
			types.SaveGlobalConfig(configPath, globalCfg)
			log.Printf("📄 Added port %d to config", port)
		}

		if !mapFound || !cfgFound {
			log.Printf("🔓 Port allowed globally: %d (Updated BPF: %v, Updated Config: %v)", port, !mapFound, !cfgFound)
		}
	} else {
		if err := m.RemovePort(port); err != nil {
			log.Fatalf("❌ Failed to disallow port %d: %v", port, err)
		}
		newPorts := []uint16{}
		for _, p := range globalCfg.Port.AllowedPorts {
			if p != port {
				newPorts = append(newPorts, p)
			}
		}
		globalCfg.Port.AllowedPorts = newPorts
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Printf("🔒 Port removed from global allow list: %d", port)
	}
}

func SyncIPPortRule(cidrStr string, port uint16, action uint8, add bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			log.Fatalf("❌ Invalid IP address: %s", cidrStr)
		}
		mask := net.CIDRMask(32, 32)
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		}
		ipNet = &net.IPNet{IP: ip, Mask: mask}
	}

	if add {
		isV6 := ipNet.IP.To4() == nil
		existingRules, _, _ := m.ListIPPortRules(isV6, 0, "")
		targetKey := fmt.Sprintf("%s:%d", cidrStr, port)
		if !strings.Contains(cidrStr, "/") {
			if isV6 {
				targetKey = fmt.Sprintf("%s/128:%d", ipNet.IP.String(), port)
			} else {
				targetKey = fmt.Sprintf("%s/32:%d", ipNet.IP.String(), port)
			}
		}

		mapAction := uint8(0)
		for k, v := range existingRules {
			if k == targetKey {
				if v == "allow" {
					mapAction = 1
				} else {
					mapAction = 2
				}
				break
			}
		}

		cfgAction := uint8(0)
		cfgIdx := -1
		for i, r := range globalCfg.Port.IPPortRules {
			if r.IP == cidrStr && r.Port == port {
				cfgAction = r.Action
				cfgIdx = i
				break
			}
		}

		if mapAction == action && cfgAction == action {
			actionStr := "allow"
			if action == 2 {
				actionStr = "deny"
			}
			fmt.Printf("ℹ️  Rule already exists: %s:%d -> %s\n", cidrStr, port, actionStr)
			return
		}

		if action == 1 { // Allow
			oppositeMapPath := "/sys/fs/bpf/netxfw/lock_list"
			if IsIPv6(cidrStr) {
				oppositeMapPath = "/sys/fs/bpf/netxfw/lock_list6"
			}
			if opM, err := ebpf.LoadPinnedMap(oppositeMapPath, nil); err == nil {
				if conflict, msg := xdp.CheckConflict(opM, cidrStr, false); conflict {
					fmt.Printf("⚠️  [Conflict] %s (Already in blacklist).\n", msg)
					if !AskConfirmation("Do you want to remove it from blacklist and add this allow rule?") {
						fmt.Println("Aborted.")
						opM.Close()
						return
					}
					xdp.UnlockIP(opM, cidrStr)
				}
				opM.Close()
			}
		} else if action == 2 { // Deny
			oppositeMapPath := "/sys/fs/bpf/netxfw/whitelist"
			if IsIPv6(cidrStr) {
				oppositeMapPath = "/sys/fs/bpf/netxfw/whitelist6"
			}
			if opM, err := ebpf.LoadPinnedMap(oppositeMapPath, nil); err == nil {
				if conflict, msg := xdp.CheckConflict(opM, cidrStr, true); conflict {
					fmt.Printf("⚠️  [Conflict] %s (Already in whitelist).\n", msg)
					if !AskConfirmation("Do you want to remove it from whitelist and add this deny rule?") {
						fmt.Println("Aborted.")
						opM.Close()
						return
					}
					xdp.UnlockIP(opM, cidrStr)
				}
				opM.Close()
			}
		}

		if mapAction != action {
			if err := m.AddIPPortRule(ipNet, port, action, nil); err != nil {
				log.Fatalf("❌ Failed to add IP+Port rule: %v", err)
			}
		}

		if cfgAction != action {
			persist := true
			if action == 2 && !globalCfg.Base.PersistRules {
				persist = false
			}
			if persist {
				// Backup old rules
				oldRules := make([]types.IPPortRule, len(globalCfg.Port.IPPortRules))
				copy(oldRules, globalCfg.Port.IPPortRules)

				if cfgIdx >= 0 {
					globalCfg.Port.IPPortRules[cfgIdx].Action = action
				} else {
					globalCfg.Port.IPPortRules = append(globalCfg.Port.IPPortRules, types.IPPortRule{
						IP:     cidrStr,
						Port:   port,
						Action: action,
					})
				}
				OptimizeIPPortRulesConfig(globalCfg)
				types.SaveGlobalConfig(configPath, globalCfg)
				log.Printf("📄 Updated IP+Port rule in config: %s:%d", cidrStr, port)

				// Cleanup BPF runtime
				finalSet := make(map[string]bool)
				for _, r := range globalCfg.Port.IPPortRules {
					finalSet[fmt.Sprintf("%s:%d:%d", r.IP, r.Port, r.Action)] = true
				}

				// Helper to remove rule
				removeRule := func(ipStr string, p uint16) {
					_, ipNet, err := net.ParseCIDR(ipStr)
					if err != nil {
						ip := net.ParseIP(ipStr)
						if ip != nil {
							if ip.To4() != nil {
								ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
							} else {
								ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
							}
						}
					}
					if ipNet != nil {
						if err := m.RemoveIPPortRule(ipNet, p); err == nil {
							log.Printf("🧹 Optimized runtime: Removed subsumed IP+Port rule %s:%d", ipStr, p)
						}
					}
				}

				// 1. Remove obsolete rules from Old Set
				for _, r := range oldRules {
					// Normalize IP for comparison
					checkIP := r.IP
					if !strings.Contains(checkIP, "/") {
						if IsIPv6(checkIP) {
							checkIP += "/128"
						} else {
							checkIP += "/32"
						}
					}
					key := fmt.Sprintf("%s:%d:%d", checkIP, r.Port, r.Action)
					if !finalSet[key] {
						removeRule(r.IP, r.Port)
					}
				}

				// 2. Remove added rule if it was merged
				addedKey := fmt.Sprintf("%s:%d:%d", cidrStr, port, action)
				// Normalize added key too if needed, but usually cidrStr comes from input.
				// However, finalSet has normalized keys.
				checkAddedIP := cidrStr
				if !strings.Contains(checkAddedIP, "/") {
					if IsIPv6(checkAddedIP) {
						checkAddedIP += "/128"
					} else {
						checkAddedIP += "/32"
					}
				}
				addedKeyNormalized := fmt.Sprintf("%s:%d:%d", checkAddedIP, port, action)

				if !finalSet[addedKeyNormalized] {
					removeRule(cidrStr, port)
				}

				// 3. Add new merged rules
				oldSet := make(map[string]bool)
				for _, r := range oldRules {
					checkIP := r.IP
					if !strings.Contains(checkIP, "/") {
						if IsIPv6(checkIP) {
							checkIP += "/128"
						} else {
							checkIP += "/32"
						}
					}
					oldSet[fmt.Sprintf("%s:%d:%d", checkIP, r.Port, r.Action)] = true
				}

				for _, r := range globalCfg.Port.IPPortRules {
					key := fmt.Sprintf("%s:%d:%d", r.IP, r.Port, r.Action)
					if !oldSet[key] && key != addedKey {
						_, ipNet, err := net.ParseCIDR(r.IP)
						if err != nil {
							ip := net.ParseIP(r.IP)
							if ip != nil {
								if ip.To4() != nil {
									ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
								} else {
									ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
								}
							}
						}
						if ipNet != nil {
							if err := m.AddIPPortRule(ipNet, r.Port, r.Action, nil); err != nil {
								log.Printf("⚠️ Failed to sync merged IP+Port rule to BPF: %s:%d", r.IP, r.Port)
							}
						}
					}
				}
			}
		}

		if mapAction != action || cfgAction != action {
			actionStr := "allow"
			if action == 2 {
				actionStr = "deny"
			}
			log.Printf("🛡️ Rule added: %s:%d -> %s (Updated BPF: %v, Updated Config: %v)",
				cidrStr, port, actionStr, mapAction != action, cfgAction != action)
		}
	} else {
		if err := m.RemoveIPPortRule(ipNet, port); err != nil {
			log.Fatalf("❌ Failed to remove IP+Port rule: %v", err)
		}
		foundInConfig := false
		isDenyRule := false
		for _, r := range globalCfg.Port.IPPortRules {
			if r.IP == cidrStr && r.Port == port {
				foundInConfig = true
				if r.Action == 2 {
					isDenyRule = true
				}
				break
			}
		}
		if foundInConfig {
			persist := true
			if isDenyRule && !globalCfg.Base.PersistRules {
				persist = false
			}
			if persist {
				newRules := []types.IPPortRule{}
				for _, r := range globalCfg.Port.IPPortRules {
					if r.IP != cidrStr || r.Port != port {
						newRules = append(newRules, r)
					}
				}
				globalCfg.Port.IPPortRules = newRules
				types.SaveGlobalConfig(configPath, globalCfg)
				log.Printf("🛡️ Rule removed from config: %s:%d", cidrStr, port)
			}
		}
		log.Printf("🛡️ Rule removed from BPF: %s:%d", cidrStr, port)
	}
}

func ClearBlacklist() {
	if !AskConfirmation("⚠️  Are you sure you want to clear the ENTIRE blacklist (IPs and IP+Port deny rules)?") {
		fmt.Println("Aborted.")
		return
	}

	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err == nil {
		removed, _ := xdp.ClearMap(m4)
		log.Printf("🧹 Cleared %d entries from IPv4 lock list", removed)
		m4.Close()
	}

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err == nil {
		removed, _ := xdp.ClearMap(m6)
		log.Printf("🧹 Cleared %d entries from IPv6 lock list", removed)
		m6.Close()
	}

	mgr, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err == nil {
		clearDenyRules := func(mapPtr *ebpf.Map) int {
			removed := 0
			iter := mapPtr.Iterate()
			var k interface{}
			var v xdp.NetXfwRuleValue
			for iter.Next(&k, &v) {
				if v.Counter == 2 { // Action Deny
					if err := mapPtr.Delete(k); err == nil {
						removed++
					}
				}
			}
			return removed
		}
		removedP4 := clearDenyRules(mgr.IpPortRules())
		removedP6 := clearDenyRules(mgr.IpPortRules6())
		if removedP4+removedP6 > 0 {
			log.Printf("🧹 Cleared %d IP+Port deny rules from BPF", removedP4+removedP6)
		}
		mgr.Close()
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		if globalCfg.Base.LockListFile != "" {
			os.WriteFile(globalCfg.Base.LockListFile, []byte(""), 0644)
			log.Printf("📄 Cleared blacklist file: %s", globalCfg.Base.LockListFile)
		}
		var newRules []types.IPPortRule
		removedCount := 0
		for _, r := range globalCfg.Port.IPPortRules {
			if r.Action != 2 {
				newRules = append(newRules, r)
			} else {
				removedCount++
			}
		}
		if removedCount > 0 {
			globalCfg.Port.IPPortRules = newRules
			types.SaveGlobalConfig(configPath, globalCfg)
			log.Printf("📄 Removed %d deny rules from config.yaml", removedCount)
		}
	}
	log.Println("✅ Blacklist cleared successfully.")
}

func SyncAutoBlock(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetAutoBlock(enable); err != nil {
		log.Fatalf("❌ Failed to set auto-block: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.AutoBlock = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ Automatic blocking set to: %v", enable)
}

func SyncAutoBlockExpiry(expiry uint32) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetAutoBlockExpiry(time.Duration(expiry) * time.Second); err != nil {
		log.Fatalf("❌ Failed to set auto-block expiry: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.AutoBlockExpiry = fmt.Sprintf("%ds", expiry)
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ Automatic blocking expiry set to: %d seconds", expiry)
}

func ImportIPPortRulesFromFile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open rules file: %v", err)
	}
	defer file.Close()

	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	existingRules4, _, _ := m.ListIPPortRules(false, 0, "")
	existingRules6, _, _ := m.ListIPPortRules(true, 0, "")

	scanner := bufio.NewScanner(file)

	// Group rules by Port and Action
	type ruleKey struct {
		port   uint16
		action uint8
	}
	rulesByGroup := make(map[ruleKey][]string)
	totalRead := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		cidrStr := parts[0]
		pVal, _ := strconv.ParseUint(parts[1], 10, 16)
		port := uint16(pVal)
		aVal, _ := strconv.ParseUint(parts[2], 10, 8)
		action := uint8(aVal)

		rulesByGroup[ruleKey{port, action}] = append(rulesByGroup[ruleKey{port, action}], cidrStr)
		totalRead++
	}

	log.Printf("ℹ️  Read %d rules from %s. Optimizing...", totalRead, filePath)

	count := 0
	updatedCount := 0

	for key, cidrs := range rulesByGroup {
		merged, err := ipmerge.MergeCIDRs(cidrs)
		if err != nil {
			log.Printf("⚠️  Error merging rules for port %d action %d: %v. Using unoptimized.", key.port, key.action, err)
			merged = cidrs
		} else if len(merged) < len(cidrs) {
			log.Printf("✅ Port %d Action %d: Optimized to %d rules (reduced by %d)", key.port, key.action, len(merged), len(cidrs)-len(merged))
		}

		for _, cidrStr := range merged {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				ip := net.ParseIP(cidrStr)
				if ip == nil {
					continue
				}
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				ipNet = &net.IPNet{IP: ip, Mask: mask}
			}

			isV6 := ipNet.IP.To4() == nil
			targetKey := ""
			if !strings.Contains(cidrStr, "/") {
				if isV6 {
					targetKey = fmt.Sprintf("%s/128:%d", ipNet.IP.String(), key.port)
				} else {
					targetKey = fmt.Sprintf("%s/32:%d", ipNet.IP.String(), key.port)
				}
			} else {
				targetKey = fmt.Sprintf("%s:%d", cidrStr, key.port)
			}

			mapAction := uint8(0)
			existingMap := existingRules4
			if isV6 {
				existingMap = existingRules6
			}
			if v, ok := existingMap[targetKey]; ok {
				if v == "allow" {
					mapAction = 1
				} else {
					mapAction = 2
				}
			}

			if mapAction != key.action {
				if err := m.AddIPPortRule(ipNet, key.port, key.action, nil); err == nil {
					updatedCount++
				}
			}

			found := false
			for i, r := range globalCfg.Port.IPPortRules {
				if r.IP == cidrStr && r.Port == key.port {
					if globalCfg.Port.IPPortRules[i].Action != key.action {
						globalCfg.Port.IPPortRules[i].Action = key.action
						updatedCount++
					}
					found = true
					break
				}
			}
			if !found {
				globalCfg.Port.IPPortRules = append(globalCfg.Port.IPPortRules, types.IPPortRule{
					IP:     cidrStr,
					Port:   key.port,
					Action: key.action,
				})
				updatedCount++
			}
			count++
		}
	}

	if updatedCount > 0 {
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	log.Printf("🚀 Successfully processed %d IP+Port rules (New/Updated: %d).", count, updatedCount)
}

func ImportLockListFromFile(filePath string) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 lock list (is the daemon running?): %v", err)
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 lock list (is the daemon running?): %v", err)
	}
	defer m6.Close()

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open lock list file %s: %v", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	threshold := 0
	v4Mask := 24
	v6Mask := 64
	if globalCfg != nil {
		threshold = globalCfg.Base.LockListMergeThreshold
		v4Mask = globalCfg.Base.LockListV4Mask
		v6Mask = globalCfg.Base.LockListV6Mask
	}

	log.Printf("ℹ️  Read %d rules from %s. Optimizing (Threshold: %d, V4Mask: /%d, V6Mask: /%d)...", len(lines), filePath, threshold, v4Mask, v6Mask)
	merged, err := ipmerge.MergeCIDRsWithThreshold(lines, threshold, v4Mask, v6Mask)
	if err != nil {
		log.Printf("⚠️  Error merging rules: %v. Proceeding with unoptimized list.", err)
		merged = lines
	} else {
		log.Printf("✅ Optimized to %d rules (reduced by %d)", len(merged), len(lines)-len(merged))
	}

	count := 0
	conflictCount := 0
	for _, line := range merged {
		var targetMap *ebpf.Map
		var oppositeMap *ebpf.Map
		if !IsIPv6(line) {
			targetMap = m4
			oppositeMap, _ = ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
		} else {
			targetMap = m6
			oppositeMap, _ = ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist6", nil)
		}

		if oppositeMap != nil {
			if conflict, _ := xdp.CheckConflict(oppositeMap, line, true); conflict {
				conflictCount++
				oppositeMap.Close()
				continue
			}
			oppositeMap.Close()
		}

		if err := xdp.LockIP(targetMap, line); err == nil {
			count++
		}
	}
	log.Printf("🛡️ Imported %d IPs/ranges from %s to lock list (Skipped %d conflicts)", count, filePath, conflictCount)
}

func ImportWhitelistFromFile(filePath string) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 whitelist (is the daemon running?): %v", err)
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 whitelist (is the daemon running?): %v", err)
	}
	defer m6.Close()

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open whitelist file %s: %v", filePath, err)
	}
	defer file.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	scanner := bufio.NewScanner(file)
	rulesByPort := make(map[uint16][]string)
	totalRead := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cidr := line
		var port uint16
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]:") {
			endBracket := strings.LastIndex(line, "]")
			portStr := line[endBracket+2:]
			cidr = line[1:endBracket]
			fmt.Sscanf(portStr, "%d", &port)
		} else if strings.Contains(line, "/") {
			lastColon := strings.LastIndex(line, ":")
			if lastColon > strings.LastIndex(line, "/") {
				portStr := line[lastColon+1:]
				cidr = line[:lastColon]
				fmt.Sscanf(portStr, "%d", &port)
			}
		} else if !IsIPv6(line) && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				cidr = parts[0]
				fmt.Sscanf(parts[1], "%d", &port)
			}
		}
		rulesByPort[port] = append(rulesByPort[port], cidr)
		totalRead++
	}

	log.Printf("ℹ️  Read %d rules from %s. Optimizing...", totalRead, filePath)

	count := 0
	conflictCount := 0
	updatedConfig := false

	for port, cidrs := range rulesByPort {
		merged, err := ipmerge.MergeCIDRs(cidrs)
		if err != nil {
			log.Printf("⚠️  Error merging rules for port %d: %v. Using unoptimized list.", port, err)
			merged = cidrs
		} else if len(merged) < len(cidrs) {
			log.Printf("✅ Port %d: Optimized to %d rules (reduced by %d)", port, len(merged), len(cidrs)-len(merged))
		}

		for _, cidr := range merged {
			var targetMap *ebpf.Map
			var oppositeMap *ebpf.Map
			if !IsIPv6(cidr) {
				targetMap = m4
				oppositeMap, _ = ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
			} else {
				targetMap = m6
				oppositeMap, _ = ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
			}

			if oppositeMap != nil {
				if conflict, _ := xdp.CheckConflict(oppositeMap, cidr, false); conflict {
					conflictCount++
					oppositeMap.Close()
					continue
				}
				oppositeMap.Close()
			}

			if err := xdp.AllowIP(targetMap, cidr, port); err == nil {
				count++

				// Construct the config entry string
				entry := cidr
				if port > 0 {
					entry = fmt.Sprintf("%s:%d", cidr, port)
				}

				found := false
				for _, ip := range globalCfg.Base.Whitelist {
					if ip == entry {
						found = true
						break
					}
				}
				if !found {
					globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, entry)
					updatedConfig = true
				}
			}
		}
	}

	if updatedConfig {
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	log.Printf("⚪ Imported %d IPs/ranges from %s to whitelist (Skipped %d conflicts, Updated config: %v)", count, filePath, conflictCount, updatedConfig)
}

func SyncRateLimitRule(cidrStr string, rate, burst uint64, add bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			log.Fatalf("❌ Invalid IP address: %s", cidrStr)
		}
		mask := net.CIDRMask(32, 32)
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		}
		ipNet = &net.IPNet{IP: ip, Mask: mask}
	}

	if add {
		if err := m.AddRateLimitRule(ipNet, rate, burst); err != nil {
			log.Fatalf("❌ Failed to add rate limit rule: %v", err)
		}

		// Persist to config
		found := false
		for i, r := range globalCfg.RateLimit.Rules {
			if r.IP == cidrStr {
				globalCfg.RateLimit.Rules[i].Rate = rate
				globalCfg.RateLimit.Rules[i].Burst = burst
				found = true
				break
			}
		}
		if !found {
			globalCfg.RateLimit.Rules = append(globalCfg.RateLimit.Rules, types.RateLimitRule{
				IP:    cidrStr,
				Rate:  rate,
				Burst: burst,
			})
		}
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Printf("🚀 Rate limit rule added/updated: %s -> %d pps (burst: %d)", cidrStr, rate, burst)
	} else {
		if err := m.RemoveRateLimitRule(ipNet); err != nil {
			log.Fatalf("❌ Failed to remove rate limit rule: %v", err)
		}

		// Remove from config
		newRules := []types.RateLimitRule{}
		for _, r := range globalCfg.RateLimit.Rules {
			if r.IP != cidrStr {
				newRules = append(newRules, r)
			}
		}
		globalCfg.RateLimit.Rules = newRules
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Printf("🛡️ Rate limit rule removed: %s", cidrStr)
	}
}
