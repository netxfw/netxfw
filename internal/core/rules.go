package core

import (
	"fmt"
	"log"
	"os"
	"strings"

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
			existingMap := make(map[string]bool)
			if content, err := os.ReadFile(filePath); err == nil {
				for _, line := range strings.Split(string(content), "\n") {
					trimmed := strings.TrimSpace(line)
					if trimmed != "" {
						if !existingMap[trimmed] {
							lines = append(lines, trimmed)
							existingMap[trimmed] = true
						}
					}
				}
			}

			// Add new CIDR if not exists (normalization might happen in MergeCIDRs, 
			// but this prevents exact string duplicates from even reaching the merge step)
			if !existingMap[cidrStr] {
				lines = append(lines, cidrStr)
			}

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
					// Normalize for comparison
					trimmedCIDR := ensureCIDR(trimmed)
					targetCIDR := ensureCIDR(cidrStr)

					if trimmed != "" && trimmedCIDR != targetCIDR {
						newLines = append(newLines, trimmed)
					} else if trimmedCIDR == targetCIDR {
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
				for _, newEntry := range globalCfg.Base.Whitelist {
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
		targetCIDR := ensureCIDR(cidrStr)

		for _, ip := range globalCfg.Base.Whitelist {
			// Extract IP part and check if port is present
			entryIP := ip
			hasPort := false
			if strings.Contains(ip, "]:") { // [IPv6]:Port
				end := strings.LastIndex(ip, "]")
				entryIP = ip[1:end]
				hasPort = true
			} else if idx := strings.LastIndex(ip, ":"); idx > strings.LastIndex(ip, "/") {
				// IPv4:Port or IPv6/CIDR:Port
				entryIP = ip[:idx]
				hasPort = true
			}

			// Normalize entry IP
			entryCIDR := ensureCIDR(entryIP)

			match := false
			// Only match if no port is present in config entry (since we are removing allow rule which is global)
			if port == 0 {
				if !hasPort && entryCIDR == targetCIDR {
					match = true
				}
			} else {
				// If port specified, match both IP and Port
				if hasPort && entryCIDR == targetCIDR {
					// Check port suffix
					suffix := fmt.Sprintf(":%d", port)
					if strings.HasSuffix(ip, suffix) {
						match = true
					}
				}
			}

			if !match {
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
		log.Fatalf("❌ Failed to set strict tcp: %v", err)
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
		log.Fatalf("❌ Failed to set syn limit: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.SYNLimit = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ SYN Rate Limit set to: %v", enable)
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

	log.Printf("🛡️ Bogon Filter set to: %v", enable)
}

/**
 * ensureCIDR ensures the IP string is in CIDR format.
 * Defaults to /32 for IPv4 and /128 for IPv6 if no mask is present.
 */
func ensureCIDR(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	if IsIPv6(s) {
		return s + "/128"
	}
	return s + "/32"
}
