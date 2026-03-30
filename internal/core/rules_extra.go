package core

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/optimizer"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/ipmerge"
	"github.com/netxfw/netxfw/internal/utils/iputil"
	"github.com/netxfw/netxfw/internal/utils/logger"
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
		log.Infof("[SHIELD] Added IP+Port rule: %s:%d -> Action %d", cidr, port, action)
	} else {
		if err := xdpMgr.RemoveIPPortRule(cidr, port); err != nil {
			log.Warnf("[WARN]  Failed to remove rule %s:%d: %v", cidr, port, err)
		} else {
			log.Infof("[SHIELD] Removed IP+Port rule: %s:%d", cidr, port)
		}
	}

	modified := false
	if err := config.MutateLoadedConfig(func(globalCfg *types.GlobalConfig) error {
		newRules := make([]types.IPPortRule, 0, len(globalCfg.Port.IPPortRules))
		targetCIDR := iputil.NormalizeCIDR(ipStr)

		for _, r := range globalCfg.Port.IPPortRules {
			ruleCIDR := iputil.NormalizeCIDR(r.IP)
			if ruleCIDR == targetCIDR && r.Port == port {
				if add {
					if r.Action != action {
						r.Action = action
						modified = true
					}
					newRules = append(newRules, r)
				} else {
					modified = true
				}
			} else {
				newRules = append(newRules, r)
			}
		}

		if add && !modified {
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

		if !modified {
			return nil
		}

		globalCfg.Port.IPPortRules = newRules
		optimizer.OptimizeIPPortRulesConfig(globalCfg)
		return nil
	}); err != nil {
		log.Warnf("[WARN]  Failed to save config: %v", err)
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
		log.Infof("[Allow] Allowed global port: %d", port)
	} else {
		if err := xdpMgr.RemoveAllowedPort(port); err != nil {
			log.Warnf("[WARN]  Failed to remove allowed port %d: %v", port, err)
		} else {
			log.Infof("[LOCK] Removed allowed global port: %d", port)
		}
	}

	modified := false
	if err := config.MutateLoadedConfig(func(globalCfg *types.GlobalConfig) error {
		newPorts := make([]uint16, 0, len(globalCfg.Port.AllowedPorts))
		found := false
		for _, p := range globalCfg.Port.AllowedPorts {
			if p == port {
				found = true
				if !add {
					modified = true
					continue
				}
			}
			newPorts = append(newPorts, p)
		}

		if add && !found {
			newPorts = append(newPorts, port)
			modified = true
		}

		if !modified {
			return nil
		}

		globalCfg.Port.AllowedPorts = newPorts
		return nil
	}); err != nil {
		log.Warnf("[WARN]  Failed to save config: %v", err)
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
		log.Infof("[START] Added rate limit: %s -> %d pps (burst %d)", cidr, rate, burst)
	} else {
		if err := xdpMgr.RemoveRateLimitRule(cidr); err != nil {
			log.Warnf("[WARN]  Failed to remove rate limit rule %s: %v", cidr, err)
		} else {
			log.Infof("[START] Removed rate limit: %s", cidr)
		}
	}

	modified := false
	if err := config.MutateLoadedConfig(func(globalCfg *types.GlobalConfig) error {
		newRules := make([]types.RateLimitRule, 0, len(globalCfg.RateLimit.Rules))
		targetCIDR := iputil.NormalizeCIDR(ip)

		for _, r := range globalCfg.RateLimit.Rules {
			if iputil.NormalizeCIDR(r.IP) == targetCIDR {
				if add {
					if r.Rate != rate || r.Burst != burst {
						r.Rate = rate
						r.Burst = burst
						modified = true
					}
					newRules = append(newRules, r)
				} else {
					modified = true
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

		if !modified {
			return nil
		}

		globalCfg.RateLimit.Rules = newRules
		return nil
	}); err != nil {
		log.Warnf("[WARN]  Failed to save config: %v", err)
	}
	return nil
}

// SyncAutoBlock updates the auto-block setting in config.
// SyncAutoBlock 更新配置中的自动封禁设置。
func SyncAutoBlock(ctx context.Context, mgr XDPManager, enable bool) error {
	log := logger.Get(ctx)

	if err := mgr.SetAutoBlock(enable); err != nil {
		return fmt.Errorf("failed to update auto-block in BPF: %v", err)
	}

	if err := config.MutateLoadedConfig(func(globalCfg *types.GlobalConfig) error {
		globalCfg.RateLimit.AutoBlock = enable
		return nil
	}); err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}
	log.Infof("[SHIELD] Auto Block set to: %v", enable)
	return nil
}

// SyncAutoBlockExpiry updates the auto-block expiry time in config.
// SyncAutoBlockExpiry 更新配置中的自动封禁过期时间。
func SyncAutoBlockExpiry(ctx context.Context, mgr XDPManager, seconds uint32) error {
	log := logger.Get(ctx)

	if err := mgr.SetAutoBlockExpiry(time.Duration(seconds) * time.Second); err != nil {
		return fmt.Errorf("failed to update auto-block expiry in BPF: %v", err)
	}

	if err := config.MutateLoadedConfig(func(globalCfg *types.GlobalConfig) error {
		globalCfg.RateLimit.AutoBlockExpiry = fmt.Sprintf("%ds", seconds)
		return nil
	}); err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}
	log.Infof("[SHIELD] Auto Block Expiry set to: %d seconds", seconds)
	return nil
}

// ClearBlacklist clears all entries from lock_list.
// ClearBlacklist 清除 lock_list 中的所有条目。
func ClearBlacklist(ctx context.Context, xdpMgr XDPManager) error {
	log := logger.Get(ctx)
	log.Info("[CLEAN] Clearing blacklist...")

	if err := xdpMgr.ClearBlacklist(); err != nil {
		log.Warnf("[WARN]  Failed to clear blacklist: %v", err)
		return err
	}
	log.Info("[OK] IPv4 Blacklist cleared.")

	globalCfg, err := config.ReloadCurrentConfig()
	if err == nil && globalCfg != nil && globalCfg.Base.LockListFile != "" {
		if err := fileutil.AtomicWriteFile(globalCfg.Base.LockListFile, []byte(""), 0644); err == nil {
			log.Infof("[FILE] Cleared persistence file: %s", globalCfg.Base.LockListFile)
		} else {
			log.Warnf("[WARN]  Failed to clear persistence file: %v", err)
		}
	}
	return nil
}

// ImportLockListFromFile imports IPs from a file to the blacklist.
// ImportLockListFromFile 从文件导入 IP 到黑名单。
func ImportLockListFromFile(ctx context.Context, xdpMgr XDPManager, path string) error {
	log := logger.Get(ctx)
	safePath := filepath.Clean(path) // Sanitize path to prevent directory traversal
	file, err := os.Open(safePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	log.Infof("[DATA] Importing blacklist from %s...", path)
	cidrs := readCIDRsFromFile(file)
	count := importCIDRsToBlacklist(ctx, xdpMgr, cidrs)

	log.Infof("[OK] Imported %d rules.", count)
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
			// 验证 IP/CIDR 格式
			// Validate IP/CIDR format
			if iputil.IsValidCIDR(line) {
				cidrs = append(cidrs, line)
			}
		}
	}
	return cidrs
}

// importCIDRsToBlacklist imports CIDRs to blacklist and persists them.
// importCIDRsToBlacklist 将 CIDR 导入黑名单并持久化。
func importCIDRsToBlacklist(ctx context.Context, xdpMgr XDPManager, cidrs []string) int {
	log := logger.Get(ctx)
	globalCfg, loadErr := config.ReloadCurrentConfig()
	if loadErr != nil {
		globalCfg = nil
	}

	persistentLines := loadExistingPersistentLines(globalCfg)
	count := 0

	for _, cidr := range cidrs {
		cidr = normalizeCIDR(cidr)

		if err := xdpMgr.AddBlacklistIP(cidr); err != nil {
			log.Warnf("[WARN]  Failed to lock %s: %v", cidr, err)
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
		log.Warnf("[WARN]  Failed to persist rules: %v", err)
	} else {
		log.Infof("[FILE] Persisted %d rules to %s", len(merged), globalCfg.Base.LockListFile)
	}
}

type whitelistImportEntry struct {
	cidr   string
	port   uint16
	source string
}

type ipPortImportEntry struct {
	cidr   string
	port   uint16
	action uint8
	source string
}

func persistImportedWhitelist(ctx context.Context, xdpMgr XDPManager, entries []whitelistImportEntry) error {
	var oldWhitelist []string
	var newWhitelist []string
	modified := false
	if err := config.MutateLoadedConfig(func(globalCfg *types.GlobalConfig) error {
		oldWhitelist = append([]string(nil), globalCfg.Base.Whitelist...)
		existing := make(map[string]bool, len(globalCfg.Base.Whitelist))
		for _, entry := range globalCfg.Base.Whitelist {
			existing[entry] = true
		}

		for _, item := range entries {
			entry := item.cidr
			if item.port > 0 {
				entry = fmt.Sprintf("%s:%d", item.cidr, item.port)
			}
			if existing[entry] {
				continue
			}
			globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, entry)
			existing[entry] = true
			modified = true
		}

		if !modified {
			return nil
		}

		optimizer.OptimizeWhitelistConfig(globalCfg)
		newWhitelist = append([]string(nil), globalCfg.Base.Whitelist...)
		return nil
	}); err != nil {
		return err
	}
	if !modified {
		return nil
	}

	cleanupMergedWhitelistRules(ctx, xdpMgr, oldWhitelist, newWhitelist, "")
	ensureWhitelistRulesInBPF(ctx, xdpMgr, newWhitelist)
	return nil
}

func persistImportedIPPortRules(ctx context.Context, entries []ipPortImportEntry) error {
	if err := config.MutateLoadedConfig(func(globalCfg *types.GlobalConfig) error {
		modified := false
		for _, item := range entries {
			targetCIDR := iputil.NormalizeCIDR(item.cidr)
			found := false
			for i, rule := range globalCfg.Port.IPPortRules {
				if iputil.NormalizeCIDR(rule.IP) != targetCIDR || rule.Port != item.port {
					continue
				}
				found = true
				if rule.Action != item.action {
					globalCfg.Port.IPPortRules[i].Action = item.action
					modified = true
				}
				break
			}

			if !found {
				globalCfg.Port.IPPortRules = append(globalCfg.Port.IPPortRules, types.IPPortRule{
					IP:     item.cidr,
					Port:   item.port,
					Action: item.action,
				})
				modified = true
			}
		}

		if !modified {
			return nil
		}

		optimizer.OptimizeIPPortRulesConfig(globalCfg)
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// ImportWhitelistFromFile imports IPs from a file to the whitelist.
// ImportWhitelistFromFile 从文件导入 IP 到白名单。
func ImportWhitelistFromFile(ctx context.Context, xdpMgr XDPManager, path string) error {
	log := logger.Get(ctx)
	safePath := filepath.Clean(path) // Sanitize path to prevent directory traversal
	file, err := os.Open(safePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	log.Infof("[DATA] Importing whitelist from %s...", path)
	scanner := bufio.NewScanner(file)
	entries := make([]whitelistImportEntry, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			var ip string
			var port uint16
			host, p, err := iputil.ParseIPPort(line)
			if err == nil {
				ip = iputil.NormalizeCIDR(host)
				port = p
			} else {
				if !iputil.IsValidCIDR(line) {
					continue
				}
				ip = iputil.NormalizeCIDR(line)
			}
			entries = append(entries, whitelistImportEntry{cidr: ip, port: port, source: line})
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	success := make([]whitelistImportEntry, 0, len(entries))
	for _, entry := range entries {
		if err := xdpMgr.AddWhitelistIP(entry.cidr, entry.port); err != nil {
			log.Warnf("[WARN]  Failed to sync whitelist rule %s: %v", entry.source, err)
			continue
		}
		success = append(success, entry)
	}

	if len(success) > 0 {
		if err := persistImportedWhitelist(ctx, xdpMgr, success); err != nil {
			log.Warnf("[WARN]  Failed to persist whitelist import: %v", err)
		}
	}

	log.Infof("[OK] Imported %d whitelist rules.", len(success))
	return nil
}

// ImportIPPortRulesFromFile imports IP+Port rules from a file.
// ImportIPPortRulesFromFile 从文件导入 IP+端口规则。
func ImportIPPortRulesFromFile(ctx context.Context, xdpMgr XDPManager, path string) error {
	log := logger.Get(ctx)
	safePath := filepath.Clean(path) // Sanitize path to prevent directory traversal
	file, err := os.Open(safePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	log.Infof("[DATA] Importing IP+Port rules from %s...", path)
	scanner := bufio.NewScanner(file)
	entries := make([]ipPortImportEntry, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ip := iputil.NormalizeCIDR(parts[0])
				if !iputil.IsValidCIDR(ip) {
					log.Warnf("[WARN]  Invalid IP format in line: %s", line)
					continue
				}
				port, portErr := strconv.Atoi(parts[1])
				if portErr != nil {
					log.Warnf("[WARN]  Invalid port in line: %s", line)
					continue
				}
				// 验证端口范围：1-65535
				// Validate port range: 1-65535
				if port < 1 || port > 65535 {
					log.Warnf("[WARN]  Port out of range in line: %s (must be 1-65535)", line)
					continue
				}
				actionStr := strings.ToLower(parts[2])
				action := uint8(0)
				if actionStr == "allow" {
					action = 1
				}
				entries = append(entries, ipPortImportEntry{cidr: ip, port: uint16(port), action: action, source: line})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	success := make([]ipPortImportEntry, 0, len(entries))
	for _, entry := range entries {
		if err := xdpMgr.AddIPPortRule(entry.cidr, entry.port, entry.action); err != nil {
			log.Warnf("[WARN]  Failed to sync rule %s: %v", entry.source, err)
			continue
		}
		success = append(success, entry)
	}

	if len(success) > 0 {
		if err := persistImportedIPPortRules(ctx, success); err != nil {
			log.Warnf("[WARN]  Failed to persist IP+Port import: %v", err)
		}
	}

	log.Infof("[OK] Imported %d IP+Port rules.", len(success))
	return nil
}
