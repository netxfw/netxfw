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
	"github.com/livp123/netxfw/internal/utils/fileutil"
	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/utils/logger"
	"go.uber.org/zap"
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
	types.ConfigMu.Lock()
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
			if saveErr := types.SaveGlobalConfig(configPath, globalCfg); saveErr != nil {
				log.Warnf("⚠️  Failed to save config: %v", saveErr)
			}
		}
	}
	types.ConfigMu.Unlock()
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
	types.ConfigMu.Lock()
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
			if saveErr := types.SaveGlobalConfig(configPath, globalCfg); saveErr != nil {
				log.Warnf("⚠️  Failed to save config: %v", saveErr)
			}
		}
	}
	types.ConfigMu.Unlock()
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
	types.ConfigMu.Lock()
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
			if saveErr := types.SaveGlobalConfig(configPath, globalCfg); saveErr != nil {
				log.Warnf("⚠️  Failed to save config: %v", saveErr)
			}
		}
	}
	types.ConfigMu.Unlock()
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
	types.ConfigMu.Lock()
	defer types.ConfigMu.Unlock()

	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}
	globalCfg.RateLimit.AutoBlock = enable
	if saveErr := types.SaveGlobalConfig(configPath, globalCfg); saveErr != nil {
		log.Warnf("⚠️  Failed to save config: %v", saveErr)
	}
	log.Infof("🛡️ Auto Block set to: %v", enable)
	return nil
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
	types.ConfigMu.Lock()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		types.ConfigMu.Unlock()
		return fmt.Errorf("failed to load config: %v", err)
	}
	globalCfg.RateLimit.AutoBlockExpiry = fmt.Sprintf("%ds", seconds)
	if saveErr := types.SaveGlobalConfig(configPath, globalCfg); saveErr != nil {
		log.Warnf("⚠️  Failed to save config: %v", saveErr)
	}
	log.Infof("🛡️ Auto Block Expiry set to: %d seconds", seconds)
	types.ConfigMu.Unlock()
	return nil
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
	types.ConfigMu.Lock()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil && globalCfg.Base.LockListFile != "" {
		if err := fileutil.AtomicWriteFile(globalCfg.Base.LockListFile, []byte(""), 0644); err == nil {
			log.Infof("📄 Cleared persistence file: %s", globalCfg.Base.LockListFile)
		} else {
			log.Warnf("⚠️  Failed to clear persistence file: %v", err)
		}
	}
	types.ConfigMu.Unlock()
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
	cidrs := readCIDRsFromFile(file)
	count := importCIDRsToBlacklist(ctx, xdpMgr, cidrs)

	log.Infof("✅ Imported %d rules.", count)
	return nil
}

// readCIDRsFromFile reads CIDR lines from a file scanner.
// readCIDRsFromFile 从文件扫描器读取 CIDR 行。
func readCIDRsFromFile(file *os.File) []string {
	scanner := bufio.NewScanner(file)
	var cidrs []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			cidrs = append(cidrs, line)
		}
	}
	return cidrs
}

// importCIDRsToBlacklist imports CIDRs to blacklist and persists them.
// importCIDRsToBlacklist 将 CIDR 导入黑名单并持久化。
func importCIDRsToBlacklist(ctx context.Context, xdpMgr XDPManager, cidrs []string) int {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	types.ConfigMu.Lock()
	defer types.ConfigMu.Unlock()

	globalCfg, loadErr := types.LoadGlobalConfig(configPath)
	if loadErr != nil {
		globalCfg = nil
	}

	persistentLines := loadExistingPersistentLines(globalCfg)
	count := 0

	for _, cidr := range cidrs {
		cidr = normalizeCIDR(cidr)

		if err := xdpMgr.AddBlacklistIP(cidr); err != nil {
			log.Warnf("⚠️  Failed to lock %s: %v", cidr, err)
		} else {
			count++
		}

		if globalCfg != nil && globalCfg.Base.PersistRules {
			persistentLines = append(persistentLines, cidr)
		}
	}

	persistBlacklistRules(log, globalCfg, persistentLines)
	return count
}

// normalizeCIDR normalizes a CIDR string by adding prefix if missing.
// normalizeCIDR 通过添加缺失的前缀来规范化 CIDR 字符串。
func normalizeCIDR(cidr string) string {
	if !strings.Contains(cidr, "/") {
		if iputil.IsIPv6(cidr) {
			return cidr + "/128"
		}
		return cidr + "/32"
	}
	return cidr
}

// loadExistingPersistentLines loads existing persistent lines from lock list file.
// loadExistingPersistentLines 从锁定列表文件加载现有的持久化行。
func loadExistingPersistentLines(globalCfg *types.GlobalConfig) []string {
	var persistentLines []string
	if globalCfg == nil || globalCfg.Base.LockListFile == "" {
		return persistentLines
	}

	content, err := os.ReadFile(globalCfg.Base.LockListFile)
	if err != nil {
		return persistentLines
	}

	lines := strings.Split(string(content), "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			persistentLines = append(persistentLines, strings.TrimSpace(l))
		}
	}
	return persistentLines
}

// persistBlacklistRules persists blacklist rules to file.
// persistBlacklistRules 将黑名单规则持久化到文件。
func persistBlacklistRules(log *zap.SugaredLogger, globalCfg *types.GlobalConfig, persistentLines []string) {
	if globalCfg == nil || !globalCfg.Base.PersistRules || globalCfg.Base.LockListFile == "" {
		return
	}

	merged, err := ipmerge.MergeCIDRsWithThreshold(persistentLines, globalCfg.Base.LockListMergeThreshold, globalCfg.Base.LockListV4Mask, globalCfg.Base.LockListV6Mask)
	if err != nil {
		merged = persistentLines
	}

	if err := fileutil.AtomicWriteFile(globalCfg.Base.LockListFile, []byte(strings.Join(merged, "\n")+"\n"), 0644); err != nil {
		log.Warnf("⚠️  Failed to persist rules: %v", err)
	} else {
		log.Infof("📄 Persisted %d rules to %s", len(merged), globalCfg.Base.LockListFile)
	}
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

			if err := SyncWhitelistMap(ctx, xdpMgr, ip, port, true, true); err != nil {
				log.Warnf("⚠️  Failed to sync whitelist rule %s: %v", line, err)
			}
			count++
		}
	}
	log.Infof("✅ Imported %d whitelist rules.", count)
	return scanner.Err()
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
				port, portErr := strconv.Atoi(parts[1])
				if portErr != nil {
					log.Warnf("⚠️  Invalid port in line: %s", line)
					continue
				}
				actionStr := strings.ToLower(parts[2])
				action := uint8(2) // Deny
				if actionStr == "allow" {
					action = 1
				}

				if syncErr := SyncIPPortRule(ctx, xdpMgr, ip, uint16(port), action, true); syncErr != nil { // #nosec G115 // port is always 0-65535
					log.Warnf("⚠️  Failed to sync rule %s: %v", line, syncErr)
				} else {
					count++
				}
			}
		}
	}
	log.Infof("✅ Imported %d IP+Port rules.", count)
	return nil
}
