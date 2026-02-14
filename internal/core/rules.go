package core

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/optimizer"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/fileutil"
	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/xdp"
)

// SyncLockMap syncs a single lock IP to the XDP map and config.
// SyncLockMap 同步单个锁定 IP 到 XDP Map 和配置。
func SyncLockMap(cidrStr string, lock bool) {
	m, err := config.LoadMap(config.MapLockList)
	if err != nil {
		log.Fatalf("❌ Failed to load lock_list map: %v", err)
	}
	defer m.Close()

	if lock {
		// Check for conflict in whitelist / 检查白名单中是否存在冲突
		if opM, err := config.LoadMap(config.MapWhitelist); err == nil {
			if conflict, msg := xdp.CheckConflict(opM, cidrStr, true); conflict {
				fmt.Printf("⚠️  [Conflict] %s (Already in whitelist).\n", msg)
				if !AskConfirmation("Do you want to remove it from whitelist and add to blacklist?") {
					fmt.Println("Aborted.")
					opM.Close()
					return
				}
				// Remove from whitelist / 从白名单移除
				if err := xdp.UnlockIP(opM, cidrStr); err != nil {
					log.Printf("⚠️  Failed to remove from whitelist: %v", err)
				} else {
					log.Printf("🔓 Removed %s from whitelist", cidrStr)
					// Also update config / 同时更新配置
					globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
					if err == nil {
						newWhitelist := []string{}
						for _, ip := range globalCfg.Base.Whitelist {
							if ip != cidrStr && !strings.HasPrefix(ip, cidrStr+":") {
								newWhitelist = append(newWhitelist, ip)
							}
						}
						globalCfg.Base.Whitelist = newWhitelist
						types.SaveGlobalConfig(config.GetConfigPath(), globalCfg)
					}
				}
			}
			opM.Close()
		}

		if err := xdp.LockIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to lock %s: %v", cidrStr, err)
		}
		log.Printf("🛡️ Locked: %s", cidrStr)

		// Persist to LockListFile if enabled / 如果启用了持久化，则保存到 LockListFile
		globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
		if err == nil && globalCfg.Base.PersistRules && globalCfg.Base.LockListFile != "" {
			filePath := globalCfg.Base.LockListFile

			// Read existing lines / 读取现有行
			var lines []string
			existingMap := make(map[string]bool)
			if fileLines, err := fileutil.ReadLines(filePath); err == nil {
				for _, line := range fileLines {
					if !existingMap[line] {
						lines = append(lines, line)
						existingMap[line] = true
					}
				}
			}

			// Add new CIDR if not exists / 如果不存在则添加新的 CIDR
			if !existingMap[cidrStr] {
				lines = append(lines, cidrStr)
			}

			// Merge / 合并网段
			merged, err := ipmerge.MergeCIDRsWithThreshold(lines, globalCfg.Base.LockListMergeThreshold, globalCfg.Base.LockListV4Mask, globalCfg.Base.LockListV6Mask)
			if err != nil {
				log.Printf("⚠️  Failed to merge IPs for persistence: %v", err)
				merged = lines
			}

			// Write back / 写回文件
			if err := os.WriteFile(filePath, []byte(strings.Join(merged, "\n")+"\n"), 0644); err == nil {
				log.Printf("📄 Persisted %s to %s (Optimized to %d rules)", cidrStr, filePath, len(merged))

				// Runtime Optimization: Sync BPF with merged list if rules were reduced
				// 运行时优化：如果规则减少，则同步 BPF 与合并列表
				if len(merged) < len(lines) {
					log.Println("🔄 Optimizing runtime BPF map...")
					// 1. Add all merged rules (ensure broad subnets are added) / 添加所有合并规则（确保添加了宽泛的子网）
					for _, cidr := range merged {
						xdp.LockIP(m, cidr)
					}
					// 2. Remove obsolete rules (redundant small IPs) / 移除过时规则（冗余的小 IP）
					mergedSet := make(map[string]bool)
					for _, c := range merged {
						mergedSet[c] = true
					}
					for _, line := range lines {
						// Normalize line to CIDR format for comparison / 将行标准化为 CIDR 格式进行比较
						checkLine := line
						if !strings.Contains(line, "/") {
							if iputil.IsIPv6(line) {
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

		// Remove from LockListFile if enabled / 如果启用了，从 LockListFile 中移除
		globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
		if err == nil && globalCfg.Base.PersistRules && globalCfg.Base.LockListFile != "" {
			filePath := globalCfg.Base.LockListFile
			if _, err := os.Stat(filePath); err == nil {
				// Read all lines except the one to remove / 读取除要删除的行以外的所有行
				lines, _ := fileutil.ReadLines(filePath)
				var newLines []string
				modified := false
				for _, trimmed := range lines {
					// Normalize for comparison / 标准化以进行比较
					trimmedCIDR := iputil.NormalizeCIDR(trimmed)
					targetCIDR := iputil.NormalizeCIDR(cidrStr)

					if trimmedCIDR != targetCIDR {
						newLines = append(newLines, trimmed)
					} else {
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

// SyncWhitelistMap syncs a whitelist entry to the XDP map and config.
// SyncWhitelistMap 同步白名单条目到 XDP Map 和配置。
func SyncWhitelistMap(cidrStr string, port uint16, allow bool) {
	m, err := config.LoadMap(config.MapWhitelist)
	if err != nil {
		log.Fatalf("❌ Failed to load whitelist map: %v", err)
	}
	defer m.Close()

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)

	if allow {
		if opM, err := config.LoadMap(config.MapLockList); err == nil {
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
				// Backup list before optimization to track changes / 优化前备份列表以跟踪更改
				oldWhitelist := make([]string, len(globalCfg.Base.Whitelist))
				copy(oldWhitelist, globalCfg.Base.Whitelist)

				globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, entry)
				optimizer.OptimizeWhitelistConfig(globalCfg)
				types.SaveGlobalConfig(configPath, globalCfg)

				// Cleanup BPF: Remove rules that were merged into larger subnets
				// 清理 BPF：删除已合并到较大子网中的规则
				newSet := make(map[string]bool)
				for _, ip := range globalCfg.Base.Whitelist {
					newSet[ip] = true
				}

				for _, oldEntry := range oldWhitelist {
					if !newSet[oldEntry] {
						// This entry was merged. Remove it from BPF. / 此条目已合并。从 BPF 中删除。
						cidrToRemove := oldEntry
						if host, _, err := iputil.ParseIPPort(oldEntry); err == nil {
							cidrToRemove = host
						}

						if err := xdp.UnlockIP(m, cidrToRemove); err != nil {
							// Ignore if already gone / 如果已删除则忽略
						} else {
							log.Printf("🧹 Optimized runtime: Removed subsumed whitelist rule %s", cidrToRemove)
						}
					}
				}

				// Ensure merged rules are in BPF / 确保合并后的规则在 BPF 中
				for _, newEntry := range globalCfg.Base.Whitelist {
					cidrToAdd := newEntry
					var portToAdd uint16

					if host, p, err := iputil.ParseIPPort(newEntry); err == nil {
						cidrToAdd = host
						portToAdd = p
					}

					if err := xdp.AllowIP(m, cidrToAdd, portToAdd); err != nil {
						log.Printf("⚠️ Failed to sync merged rule to BPF: %s", cidrToAdd)
					}
				}
			}
		}
	} else {
		if err := xdp.UnlockIP(m, cidrStr); err != nil {
			log.Printf("⚠️  Failed to remove %s: %v", cidrStr, err)
		} else {
			if port > 0 {
				log.Printf("🗑️  Removed from whitelist: %s (port: %d)", cidrStr, port)
			} else {
				log.Printf("🗑️  Removed from whitelist: %s", cidrStr)
			}
		}

		// Always try to remove from config if it exists there / 总是尝试从配置中删除（如果存在）
		newWhitelist := []string{}
		modified := false
		targetCIDR := iputil.NormalizeCIDR(cidrStr)

		for _, ip := range globalCfg.Base.Whitelist {
			// Extract IP part and check if port is present / 提取 IP 部分并检查是否存在端口
			entryIP := ip
			hasPort := false
			if host, _, err := iputil.ParseIPPort(ip); err == nil {
				entryIP = host
				hasPort = true
			}

			// Normalize entry IP / 标准化条目 IP
			entryCIDR := iputil.NormalizeCIDR(entryIP)

			match := false
			// Only match if no port is present in config entry (since we are removing allow rule which is global)
			// 仅当配置条目中没有端口时才匹配（因为我们要删除的是全局允许规则）
			if port == 0 {
				if !hasPort && entryCIDR == targetCIDR {
					match = true
				}
			} else {
				// If port specified, match both IP and Port / 如果指定了端口，则同时匹配 IP 和端口
				if hasPort && entryCIDR == targetCIDR {
					// Check port suffix / 检查端口后缀
					_, p, err := iputil.ParseIPPort(ip)
					if err == nil && p == port {
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

// SyncDefaultDeny sets the default deny policy and syncs with configuration.
// SyncDefaultDeny 设置默认拒绝策略并与配置同步。
func SyncDefaultDeny(enable bool) {
	m, err := xdp.NewManagerFromPins(config.GetPinPath())
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetDefaultDeny(enable); err != nil {
		log.Fatalf("❌ Failed to set default deny: %v", err)
	}

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.DefaultDeny = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ Default deny policy set to: %v", enable)
}

// SyncEnableAFXDP enables or disables AF_XDP redirection and syncs with configuration.
// SyncEnableAFXDP 启用或禁用 AF_XDP 重定向并与配置同步。
func SyncEnableAFXDP(enable bool) {
	m, err := xdp.NewManagerFromPins(config.GetPinPath())
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetEnableAFXDP(enable); err != nil {
		log.Fatalf("❌ Failed to set enable AF_XDP: %v", err)
	}

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.EnableAFXDP = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🚀 AF_XDP redirection set to: %v", enable)
}

// SyncEnableRateLimit enables or disables global rate limiting and syncs with configuration.
// SyncEnableRateLimit 启用或禁用全局速率限制并与配置同步。
func SyncEnableRateLimit(enable bool) {
	m, err := xdp.NewManagerFromPins(config.GetPinPath())
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetEnableRateLimit(enable); err != nil {
		log.Fatalf("❌ Failed to set enable ratelimit: %v", err)
	}

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.Enabled = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🚀 Global rate limit set to: %v", enable)
}

// SyncDropFragments enables or disables dropping of IP fragments and syncs with configuration.
// SyncDropFragments 启用或禁用丢弃 IP 分片并与配置同步。
func SyncDropFragments(enable bool) {
	m, err := xdp.NewManagerFromPins(config.GetPinPath())
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetDropFragments(enable); err != nil {
		log.Fatalf("❌ Failed to set drop fragments: %v", err)
	}

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.DropFragments = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ IP Fragment dropping set to: %v", enable)
}

// SyncStrictTCP enables or disables strict TCP validation and syncs with configuration.
// SyncStrictTCP 启用或禁用严格的 TCP 验证并与配置同步。
func SyncStrictTCP(enable bool) {
	m, err := xdp.NewManagerFromPins(config.GetPinPath())
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetStrictTCP(enable); err != nil {
		log.Fatalf("❌ Failed to set strict tcp: %v", err)
	}

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.StrictTCP = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ Strict TCP validation set to: %v", enable)
}

// SyncSYNLimit enables or disables SYN rate limiting and syncs with configuration.
// SyncSYNLimit 启用或禁用 SYN 速率限制并与配置同步。
func SyncSYNLimit(enable bool) {
	m, err := xdp.NewManagerFromPins(config.GetPinPath())
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetSYNLimit(enable); err != nil {
		log.Fatalf("❌ Failed to set syn limit: %v", err)
	}

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.SYNLimit = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ SYN Rate Limit set to: %v", enable)
}

// SyncBogonFilter enables or disables bogon filtering and syncs with configuration.
// SyncBogonFilter 启用或禁用 bogon 过滤并与配置同步。
func SyncBogonFilter(enable bool) {
	m, err := xdp.NewManagerFromPins(config.GetPinPath())
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetBogonFilter(enable); err != nil {
		log.Fatalf("❌ Failed to set bogon filter: %v", err)
	}

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.BogonFilter = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ Bogon Filter set to: %v", enable)
}

// ShowLockList lists all currently blocked IP ranges.
// ShowLockList 列出当前所有被封禁的 IP 范围。
func ShowLockList(limit int, search string) {
	log.Println("📋 Blacklist Rules (Lock List):")

	// Try to load unified lock_list / 尝试加载统一的 lock_list
	m, err := config.LoadMap(config.MapLockList)
	if err != nil {
		log.Printf("⚠️  Failed to load lock_list map: %v", err)
		return
	}
	defer m.Close()

	// Use false for isIPv6 since we have unified map / 由于我们有统一的 Map，因此 isIPv6 使用 false
	ips, count, err := xdp.ListBlockedIPs(m, false, limit, search)
	if err != nil {
		log.Printf("⚠️  Failed to list blocked IPs: %v", err)
	}

	for _, entry := range ips {
		fmt.Printf(" - %s (ExpiresAt: %d)\n", entry.IP, entry.ExpiresAt)
	}

	// Also check dynamic lock list / 同时检查动态锁定列表
	md, err := config.LoadMap(config.MapDynLockList)
	if err == nil {
		defer md.Close()
		dynIps, dynCount, _ := xdp.ListBlockedIPs(md, false, limit, search)
		if dynCount > 0 {
			fmt.Println("\n📋 Dynamic Blacklist Rules:")
			for _, entry := range dynIps {
				fmt.Printf(" - %s (ExpiresAt: %d)\n", entry.IP, entry.ExpiresAt)
			}
			count += dynCount
		}
	}

	fmt.Printf("\nTotal blocked entries found: %d\n", count)
}
