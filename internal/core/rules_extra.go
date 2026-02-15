package core

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/optimizer"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/utils/logger"
)

// SyncIPPortRule syncs an IP+Port rule to the XDP map and config.
// SyncIPPortRule 同步 IP+端口规则到 XDP Map 和配置。
func SyncIPPortRule(ctx context.Context, xdpMgr XDPManager, ipStr string, port uint16, action uint8, add bool) error {
	log := logger.Get(ctx)
	cidr := iputil.NormalizeCIDR(ipStr)

	if add {
		if err := xdpMgr.AddIPPortRule(cidr, port, action); err != nil {
			return fmt.Errorf("failed to add rule %s:%d: %v", cidr, port, err)
		}
		log.Infof("🛡️ Added IP+Port rule: %s:%d -> Action %d", cidr, port, action)
	} else {
		if err := xdpMgr.RemoveIPPortRule(cidr, port); err != nil {
			log.Warnf("⚠️  Failed to remove rule %s:%d: %v", cidr, port, err)
		} else {
			log.Infof("🛡️ Removed IP+Port rule: %s:%d", cidr, port)
		}
	}

	// Update Config / 更新配置
	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		newRules := []types.IPPortRule{}
		modified := false
		targetCIDR := iputil.NormalizeCIDR(ipStr)

		for _, r := range globalCfg.Port.IPPortRules {
			// Normalize existing rule IP / 标准化现有规则 IP
			ruleCIDR := iputil.NormalizeCIDR(r.IP)
			if ruleCIDR == targetCIDR && r.Port == port {
				if add {
					// Update existing if action changed / 如果动作改变，则更新现有规则
					if r.Action != action {
						r.Action = action
						modified = true
					}
					newRules = append(newRules, r) // Keep it (updated or same) / 保留它（已更新或未变）
				} else {
					modified = true // Remove it (skip append) / 移除它（跳过追加）
				}
			} else {
				newRules = append(newRules, r)
			}
		}

		if add && !modified {
			// Check if we found it in the loop / 检查是否在循环中找到了它
			found := false
			for i, r := range newRules {
				if iputil.NormalizeCIDR(r.IP) == targetCIDR && r.Port == port {
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
					IP:     ipStr,
					Port:   port,
					Action: action,
				})
				modified = true
			}
		}

		if modified {
			globalCfg.Port.IPPortRules = newRules
			optimizer.OptimizeIPPortRulesConfig(globalCfg)
			types.SaveGlobalConfig(configPath, globalCfg)
		}
	}
	return nil
}

// SyncAllowedPort updates the allowed_ports map and config.
// SyncAllowedPort 更新 allowed_ports Map 和配置。
func SyncAllowedPort(ctx context.Context, xdpMgr XDPManager, port uint16, add bool) error {
	log := logger.Get(ctx)

	if add {
		if err := xdpMgr.AllowPort(port); err != nil {
			return fmt.Errorf("failed to allow port %d: %v", port, err)
		}
		log.Infof("🔓 Allowed global port: %d", port)
	} else {
		if err := xdpMgr.RemoveAllowedPort(port); err != nil {
			log.Warnf("⚠️  Failed to remove allowed port %d: %v", port, err)
		} else {
			log.Infof("🔒 Removed allowed global port: %d", port)
		}
	}

	// Update Config / 更新配置
	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		newPorts := []uint16{}
		modified := false
		found := false
		for _, p := range globalCfg.Port.AllowedPorts {
			if p == port {
				found = true
				if !add {
					modified = true // Remove / 移除
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
	return nil
}

// SyncRateLimitRule updates the rate_limit_rules map and config.
// SyncRateLimitRule 更新 rate_limit_rules Map 和配置。
func SyncRateLimitRule(ctx context.Context, xdpMgr XDPManager, ip string, rate uint64, burst uint64, add bool) error {
	log := logger.Get(ctx)
	cidr := iputil.NormalizeCIDR(ip)

	if add {
		if err := xdpMgr.AddRateLimitRule(cidr, rate, burst); err != nil {
			return fmt.Errorf("failed to add rate limit rule %s: %v", cidr, err)
		}
		log.Infof("🚀 Added rate limit: %s -> %d pps (burst %d)", cidr, rate, burst)
	} else {
		if err := xdpMgr.RemoveRateLimitRule(cidr); err != nil {
			log.Warnf("⚠️  Failed to remove rate limit rule %s: %v", cidr, err)
		} else {
			log.Infof("🚀 Removed rate limit: %s", cidr)
		}
	}

	// Update Config / 更新配置
	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		newRules := []types.RateLimitRule{}
		modified := false
		targetCIDR := iputil.NormalizeCIDR(ip)

		for _, r := range globalCfg.RateLimit.Rules {
			if iputil.NormalizeCIDR(r.IP) == targetCIDR {
				if add {
					// Update / 更新
					if r.Rate != rate || r.Burst != burst {
						r.Rate = rate
						r.Burst = burst
						modified = true
					}
					newRules = append(newRules, r)
				} else {
					modified = true // Remove / 移除
				}
			} else {
				newRules = append(newRules, r)
			}
		}

		if add && !modified {
			found := false
			for _, r := range newRules {
				if iputil.NormalizeCIDR(r.IP) == targetCIDR {
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
	return nil
}

// SyncAutoBlock updates the auto-block setting in config.
// SyncAutoBlock 更新配置中的自动封禁设置。
func SyncAutoBlock(ctx context.Context, mgr XDPManager, enable bool) error {
	log := logger.Get(ctx)

	// Update Runtime / 更新运行时
	if err := mgr.SetAutoBlock(enable); err != nil {
		return fmt.Errorf("failed to update auto-block in BPF: %v", err)
	}

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.AutoBlock = enable
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Infof("🛡️ Auto Block set to: %v", enable)
		return nil
	} else {
		return fmt.Errorf("failed to load config: %v", err)
	}
}

// SyncAutoBlockExpiry updates the auto-block expiry time in config.
// SyncAutoBlockExpiry 更新配置中的自动封禁过期时间。
func SyncAutoBlockExpiry(ctx context.Context, mgr XDPManager, seconds uint32) error {
	log := logger.Get(ctx)

	// Update Runtime / 更新运行时
	if err := mgr.SetAutoBlockExpiry(time.Duration(seconds) * time.Second); err != nil {
		return fmt.Errorf("failed to update auto-block expiry in BPF: %v", err)
	}

	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.AutoBlockExpiry = fmt.Sprintf("%ds", seconds)
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Infof("🛡️ Auto Block Expiry set to: %d seconds", seconds)
		return nil
	} else {
		return fmt.Errorf("failed to load config: %v", err)
	}
}

// ClearBlacklist clears all entries from lock_list.
// ClearBlacklist 清除 lock_list 中的所有条目。
func ClearBlacklist(ctx context.Context, xdpMgr XDPManager) error {
	log := logger.Get(ctx)
	log.Info("🧹 Clearing blacklist...")

	// Clear Unified Map / 清除统一 Map
	if err := xdpMgr.ClearBlacklist(); err != nil {
		log.Warnf("⚠️  Failed to clear blacklist: %v", err)
		return err
	}
	log.Info("✅ IPv4 Blacklist cleared.")

	// Clear persistence file / 清除持久化文件
	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil && globalCfg.Base.LockListFile != "" {
		if err := os.WriteFile(globalCfg.Base.LockListFile, []byte(""), 0644); err == nil {
			log.Infof("📄 Cleared persistence file: %s", globalCfg.Base.LockListFile)
		} else {
			log.Warnf("⚠️  Failed to clear persistence file: %v", err)
		}
	}
	return nil
}

// ImportLockListFromFile imports IPs from a file to the blacklist.
// ImportLockListFromFile 从文件导入 IP 到黑名单。
func ImportLockListFromFile(ctx context.Context, xdpMgr XDPManager, path string) error {
	log := logger.Get(ctx)
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	log.Infof("📦 Importing blacklist from %s...", path)
	scanner := bufio.NewScanner(file)
	count := 0

	// Use batch loading by reading all valid lines first / 首先读取所有有效行，使用批量加载
	var cidrs []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			cidrs = append(cidrs, line)
		}
	}

	// Prepare persistence update / 准备持久化更新
	configPath := config.GetConfigPath()
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	var persistentLines []string
	if globalCfg != nil && globalCfg.Base.LockListFile != "" {
		// Read existing / 读取现有内容
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
		// Check valid CIDR/IP / 检查有效的 CIDR/IP
		if !strings.Contains(cidr, "/") {
			if iputil.IsIPv6(cidr) {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}

		// Update BPF / 更新 BPF
		if err := xdpMgr.AddBlacklistIP(cidr); err != nil {
			log.Warnf("⚠️  Failed to lock %s: %v", cidr, err)
		} else {
			count++
		}

		// Update persistent list / 更新持久化列表
		if globalCfg != nil && globalCfg.Base.PersistRules {
			persistentLines = append(persistentLines, cidr)
		}
	}

	// Save persistence / 保存持久化
	if globalCfg != nil && globalCfg.Base.PersistRules && globalCfg.Base.LockListFile != "" {
		// Merge/Deduplicate / 合并/去重
		merged, err := ipmerge.MergeCIDRsWithThreshold(persistentLines, globalCfg.Base.LockListMergeThreshold, globalCfg.Base.LockListV4Mask, globalCfg.Base.LockListV6Mask)
		if err != nil {
			merged = persistentLines
		}
		if err := os.WriteFile(globalCfg.Base.LockListFile, []byte(strings.Join(merged, "\n")+"\n"), 0644); err != nil {
			log.Warnf("⚠️  Failed to persist rules: %v", err)
		} else {
			log.Infof("📄 Persisted %d rules to %s", len(merged), globalCfg.Base.LockListFile)
		}
	}

	log.Infof("✅ Imported %d rules.", count)
	return nil
}

// ImportWhitelistFromFile imports IPs from a file to the whitelist.
// ImportWhitelistFromFile 从文件导入 IP 到白名单。
func ImportWhitelistFromFile(ctx context.Context, xdpMgr XDPManager, path string) error {
	log := logger.Get(ctx)
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	log.Infof("📦 Importing whitelist from %s...", path)
	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Format: IP or IP:Port / 格式：IP 或 IP:端口
			var ip string
			var port uint16
			host, p, err := iputil.ParseIPPort(line)
			if err == nil {
				ip = host
				port = p
			} else {
				ip = line
			}

			SyncWhitelistMap(ctx, xdpMgr, ip, port, true)
			count++
		}
	}
	log.Infof("✅ Imported %d whitelist rules.", count)
	return nil
}

// ImportIPPortRulesFromFile imports IP+Port rules from a file.
// ImportIPPortRulesFromFile 从文件导入 IP+端口规则。
func ImportIPPortRulesFromFile(ctx context.Context, xdpMgr XDPManager, path string) error {
	log := logger.Get(ctx)
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	log.Infof("📦 Importing IP+Port rules from %s...", path)
	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Format: IP Port Action (allow/deny) / 格式：IP 端口 动作 (allow/deny)
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ip := parts[0]
				port, _ := strconv.Atoi(parts[1])
				actionStr := strings.ToLower(parts[2])
				action := uint8(2) // Deny
				if actionStr == "allow" {
					action = 1
				}

				SyncIPPortRule(ctx, xdpMgr, ip, uint16(port), action, true)
				count++
			}
		}
	}
	log.Infof("✅ Imported %d IP+Port rules.", count)
	return nil
}
