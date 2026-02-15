package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/optimizer"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/fileutil"
	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/utils/logger"
)

// SyncLockMap syncs a single lock IP to the XDP map and config.
// SyncLockMap 同步单个锁定 IP 到 XDP Map 和配置。
func SyncLockMap(ctx context.Context, xdpMgr XDPManager, cidrStr string, lock bool, force bool) error {
	log := logger.Get(ctx)
	cidrStr = iputil.NormalizeCIDR(cidrStr)

	if lock {
		// 1. Check for conflict in whitelist (Read-only check before lock)
		// 1. 检查白名单中是否存在冲突（加锁前的只读检查）
		conflict, err := xdpMgr.IsIPInWhitelist(cidrStr)
		if err == nil && conflict {
			fmt.Printf("⚠️  [Conflict] %s (Already in whitelist).\n", cidrStr)
			if !force && !AskConfirmation("Do you want to remove it from whitelist and add to blacklist?") {
				fmt.Println("Aborted.")
				return nil
			}
		}

		// 2. Critical Section: Atomic update
		// 2. 临界区：原子更新
		ConfigMu.Lock()
		defer ConfigMu.Unlock()

		// Re-check conflict inside lock to handle race conditions
		// 在锁内重新检查冲突以处理竞态条件
		if conflict, err := xdpMgr.IsIPInWhitelist(cidrStr); err == nil && conflict {
			// Remove from whitelist / 从白名单移除
			if err := xdpMgr.RemoveWhitelistIP(cidrStr); err != nil {
				log.Warnf("⚠️  Failed to remove from whitelist: %v", err)
			} else {
				log.Infof("🔓 Removed %s from whitelist", cidrStr)
				// Update config immediately / 立即更新配置
				globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
				if err == nil {
					newWhitelist := []string{}
					for _, entry := range globalCfg.Base.Whitelist {
						normalizedEntry := entry
						if host, _, err := iputil.ParseIPPort(entry); err == nil {
							normalizedEntry = host
						}
						normalizedEntry = iputil.NormalizeCIDR(normalizedEntry)

						if normalizedEntry != cidrStr {
							newWhitelist = append(newWhitelist, entry)
						}
					}
					globalCfg.Base.Whitelist = newWhitelist
					types.SaveGlobalConfig(config.GetConfigPath(), globalCfg)
				}
			}
		}

		if err := xdpMgr.AddBlacklistIP(cidrStr); err != nil {
			return fmt.Errorf("failed to lock %s: %v", cidrStr, err)
		}
		log.Infof("🛡️ Locked: %s", cidrStr)

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
				log.Warnf("⚠️  Failed to merge IPs for persistence: %v", err)
				merged = lines
			}

			// Write back / 写回文件
			if err := fileutil.AtomicWriteFile(filePath, []byte(strings.Join(merged, "\n")+"\n"), 0644); err == nil {
				log.Infof("📄 Persisted %s to %s (Optimized to %d rules)", cidrStr, filePath, len(merged))

				// Runtime Optimization: Sync BPF with merged list if rules were reduced
				// 运行时优化：如果规则减少，则同步 BPF 与合并后的列表
				if len(merged) < len(lines) {
					log.Infof("🔄 Optimizing runtime BPF map...")
				}
			}
		}
	} else {
		// Unlock Logic
		ConfigMu.Lock()
		defer ConfigMu.Unlock()

		if err := xdpMgr.RemoveBlacklistIP(cidrStr); err != nil {
			return fmt.Errorf("failed to unlock %s: %v", cidrStr, err)
		}
		log.Infof("🔓 Unlocked: %s", cidrStr)

		// Remove from LockListFile if exists / 如果存在，从 LockListFile 中移除
		globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
		if err == nil && globalCfg.Base.LockListFile != "" {
			filePath := globalCfg.Base.LockListFile
			if fileLines, err := fileutil.ReadLines(filePath); err == nil {
				var newLines []string
				targetCIDR := iputil.NormalizeCIDR(cidrStr)
				for _, line := range fileLines {
					if iputil.NormalizeCIDR(line) != targetCIDR {
						newLines = append(newLines, line)
					}
				}
				fileutil.AtomicWriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
			}
		}
	}

	return nil
}

// SyncWhitelistMap syncs a whitelist entry to the XDP map and config.
// SyncWhitelistMap 同步白名单条目到 XDP Map 和配置。
func SyncWhitelistMap(ctx context.Context, xdpMgr XDPManager, cidrStr string, port uint16, allow bool, force bool) error {
	log := logger.Get(ctx)
	cidrStr = iputil.NormalizeCIDR(cidrStr)
	configPath := config.GetConfigPath()

	if allow {
		// 1. Check conflict (Read-only)
		// 1. 检查冲突（只读）
		conflict, err := xdpMgr.IsIPInBlacklist(cidrStr)
		if err == nil && conflict {
			fmt.Printf("⚠️  [Conflict] %s (Already in blacklist).\n", cidrStr)
			if !force && !AskConfirmation("Do you want to remove it from blacklist and add to whitelist?") {
				fmt.Println("Aborted.")
				return nil
			}
		}

		// 2. Critical Section
		// 2. 临界区
		ConfigMu.Lock()
		defer ConfigMu.Unlock()

		// Re-check conflict
		// 重新检查冲突
		if conflict, err := xdpMgr.IsIPInBlacklist(cidrStr); err == nil && conflict {
			if err := xdpMgr.RemoveBlacklistIP(cidrStr); err != nil {
				log.Warnf("⚠️  Failed to remove from blacklist: %v", err)
			} else {
				log.Infof("🔓 Removed %s from blacklist", cidrStr)
			}
		}

		if err := xdpMgr.AddWhitelistIP(cidrStr, port); err != nil {
			return fmt.Errorf("failed to allow %s: %v", cidrStr, err)
		}
		if port > 0 {
			log.Infof("⚪ Whitelisted: %s (port: %d)", cidrStr, port)
		} else {
			log.Infof("⚪ Whitelisted: %s", cidrStr)
		}

		// Update Config
		// 更新配置
		// Reload config to ensure freshness / 重新加载配置以确保新鲜度
		globalCfg, err := types.LoadGlobalConfig(configPath)
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

						if err := xdpMgr.RemoveWhitelistIP(cidrToRemove); err != nil {
							// Ignore if already gone / 如果已删除则忽略
						} else {
							log.Infof("🧹 Optimized runtime: Removed subsumed whitelist rule %s", cidrToRemove)
						}
					}
				}

				// Ensure merged rules are in BPF / 确保合并后的规则在 BPF 中
				for _, newEntry := range globalCfg.Base.Whitelist {
					cidrToAdd := newEntry
					portToAdd := uint16(0)
					if host, p, err := iputil.ParseIPPort(newEntry); err == nil {
						cidrToAdd = host
						portToAdd = p
					}
					xdpMgr.AddWhitelistIP(cidrToAdd, portToAdd)
				}
			}
		}
	} else {
		// Unlock Logic
		ConfigMu.Lock()
		defer ConfigMu.Unlock()

		if err := xdpMgr.RemoveWhitelistIP(cidrStr); err != nil {
			return fmt.Errorf("failed to remove %s from whitelist: %v", cidrStr, err)
		}
		log.Infof("🔓 Removed from whitelist: %s", cidrStr)

		globalCfg, err := types.LoadGlobalConfig(configPath)
		if err == nil {
			newWhitelist := []string{}
			targetCIDR := iputil.NormalizeCIDR(cidrStr)
			for _, ip := range globalCfg.Base.Whitelist {
				host, p, err := iputil.ParseIPPort(ip)
				var entryCIDR string
				var entryPort uint16
				if err != nil {
					// No port, normalize and compare
					entryCIDR = iputil.NormalizeCIDR(ip)
					entryPort = 0
				} else {
					// Has port, compare host and port
					entryCIDR = iputil.NormalizeCIDR(host)
					entryPort = p
				}

				if entryCIDR == targetCIDR && (port == 0 || entryPort == port) {
					continue
				}
				newWhitelist = append(newWhitelist, ip)
			}
			globalCfg.Base.Whitelist = newWhitelist
			types.SaveGlobalConfig(configPath, globalCfg)
		}
	}
	return nil
}

// SyncDefaultDeny sets the default deny policy and syncs with configuration.
// SyncDefaultDeny 设置默认拒绝策略并与配置同步。
func SyncDefaultDeny(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	log := logger.Get(ctx)
	if err := xdpMgr.SetDefaultDeny(enable); err != nil {
		return fmt.Errorf("failed to set default deny: %v", err)
	}

	configPath := config.GetConfigPath()
	ConfigMu.Lock()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.DefaultDeny = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	ConfigMu.Unlock()

	log.Infof("🛡️ Default deny policy set to: %v", enable)
	return nil
}

// SyncEnableAFXDP enables or disables AF_XDP redirection and syncs with configuration.
// SyncEnableAFXDP 启用或禁用 AF_XDP 重定向并与配置同步。
func SyncEnableAFXDP(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	log := logger.Get(ctx)
	if err := xdpMgr.SetEnableAFXDP(enable); err != nil {
		return fmt.Errorf("failed to set enable AF_XDP: %v", err)
	}

	configPath := config.GetConfigPath()
	ConfigMu.Lock()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.EnableAFXDP = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	ConfigMu.Unlock()

	log.Infof("🚀 AF_XDP redirection set to: %v", enable)
	return nil
}

// SyncEnableRateLimit enables or disables global rate limiting and syncs with configuration.
// SyncEnableRateLimit 启用或禁用全局速率限制并与配置同步。
func SyncEnableRateLimit(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	log := logger.Get(ctx)
	if err := xdpMgr.SetEnableRateLimit(enable); err != nil {
		return fmt.Errorf("failed to set enable ratelimit: %v", err)
	}

	configPath := config.GetConfigPath()
	ConfigMu.Lock()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.Enabled = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	ConfigMu.Unlock()

	log.Infof("🚀 Global rate limit set to: %v", enable)
	return nil
}

// SyncDropFragments enables or disables dropping of IP fragments and syncs with configuration.
// SyncDropFragments 启用或禁用丢弃 IP 分片并与配置同步。
func SyncDropFragments(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	log := logger.Get(ctx)
	if err := xdpMgr.SetDropFragments(enable); err != nil {
		return fmt.Errorf("failed to set drop fragments: %v", err)
	}

	configPath := config.GetConfigPath()
	ConfigMu.Lock()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.DropFragments = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	ConfigMu.Unlock()

	log.Infof("🛡️ IP Fragment dropping set to: %v", enable)
	return nil
}

// SyncStrictTCP enables or disables strict TCP validation and syncs with configuration.
// SyncStrictTCP 启用或禁用严格的 TCP 验证并与配置同步。
func SyncStrictTCP(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	log := logger.Get(ctx)
	if err := xdpMgr.SetStrictTCP(enable); err != nil {
		return fmt.Errorf("failed to set strict tcp: %v", err)
	}

	configPath := config.GetConfigPath()
	ConfigMu.Lock()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.StrictTCP = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	ConfigMu.Unlock()

	log.Infof("🛡️ Strict TCP validation set to: %v", enable)
	return nil
}

// SyncSYNLimit enables or disables SYN rate limiting and syncs with configuration.
// SyncSYNLimit 启用或禁用 SYN 速率限制并与配置同步。
func SyncSYNLimit(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	log := logger.Get(ctx)
	if err := xdpMgr.SetSYNLimit(enable); err != nil {
		return fmt.Errorf("failed to set syn limit: %v", err)
	}

	configPath := config.GetConfigPath()
	ConfigMu.Lock()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.SYNLimit = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	ConfigMu.Unlock()

	log.Infof("🛡️ SYN Rate Limit set to: %v", enable)
	return nil
}

// SyncBogonFilter enables or disables bogon filtering and syncs with configuration.
// SyncBogonFilter 启用或禁用 bogon 过滤并与配置同步。
func SyncBogonFilter(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	log := logger.Get(ctx)
	if err := xdpMgr.SetBogonFilter(enable); err != nil {
		return fmt.Errorf("failed to set bogon filter: %v", err)
	}

	configPath := config.GetConfigPath()
	ConfigMu.Lock()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.BogonFilter = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	ConfigMu.Unlock()

	log.Infof("🛡️ Bogon Filter set to: %v", enable)
	return nil
}

// ShowLockList lists all currently blocked IP ranges.
// ShowLockList 列出当前所有被封禁的 IP 范围。
func ShowLockList(ctx context.Context, xdpMgr XDPManager, limit int, search string) error {
	log := logger.Get(ctx)
	log.Info("📋 Blacklist Rules (Lock List):")

	ips, _, err := xdpMgr.ListBlacklistIPs(limit, search)
	if err != nil {
		return fmt.Errorf("failed to list blocked IPs: %v", err)
	}

	for _, entry := range ips {
		fmt.Printf(" - %s (ExpiresAt: %d)\n", entry.IP, entry.ExpiresAt)
	}

	// Also check dynamic lock list / 同时检查动态封禁列表
	dynIps, dynCount, _ := xdpMgr.ListDynamicBlacklistIPs(limit, search)
	if dynCount > 0 {
		fmt.Println("\n📋 Dynamic Blacklist Rules:")
		for _, entry := range dynIps {
			fmt.Printf(" - %s (ExpiresAt: %d)\n", entry.IP, entry.ExpiresAt)
		}
	}
	return nil
}
