package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/optimizer"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/ipmerge"
	"github.com/netxfw/netxfw/internal/utils/iputil"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// handleLockWhitelistConflict handles conflict when locking an IP that's in whitelist.
// handleLockWhitelistConflict 处理锁定 IP 时与白名单的冲突。
func handleLockWhitelistConflict(ctx context.Context, xdpMgr XDPManager, cidrStr string, force bool) bool {
	log := logger.Get(ctx)
	conflict, err := xdpMgr.IsIPInWhitelist(cidrStr)
	if err != nil || !conflict {
		return false
	}

	log.Warnf("⚠️  [Conflict] %s (Already in whitelist).", cidrStr)
	if !force && !AskConfirmation("Do you want to remove it from whitelist and add to blacklist?") {
		log.Info("Aborted.")
		return true
	}
	return false
}

// removeFromWhitelistConfig removes an IP from whitelist in config.
// removeFromWhitelistConfig 从配置的白名单中移除 IP。
func removeFromWhitelistConfig(cidrStr string) error {
	globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
	if err != nil {
		return err
	}

	newWhitelist := []string{}
	for _, entry := range globalCfg.Base.Whitelist {
		normalizedEntry := entry
		if host, _, parseErr := iputil.ParseIPPort(entry); parseErr == nil {
			normalizedEntry = host
		}
		normalizedEntry = iputil.NormalizeCIDR(normalizedEntry)

		if normalizedEntry != cidrStr {
			newWhitelist = append(newWhitelist, entry)
		}
	}
	globalCfg.Base.Whitelist = newWhitelist
	return types.SaveGlobalConfig(config.GetConfigPath(), globalCfg)
}

// removeWhitelistAndLog removes IP from whitelist and logs the action.
// removeWhitelistAndLog 从白名单移除 IP 并记录日志。
func removeWhitelistAndLog(ctx context.Context, xdpMgr XDPManager, cidrStr string) error {
	log := logger.Get(ctx)
	if removeErr := xdpMgr.RemoveWhitelistIP(cidrStr); removeErr != nil {
		log.Warnf("⚠️  Failed to remove from whitelist: %v", removeErr)
		return removeErr
	}
	log.Infof("🔓 Removed %s from whitelist", cidrStr)
	return removeFromWhitelistConfig(cidrStr)
}

// persistLockToFile persists a locked IP to the lock list file.
// persistLockToFile 将锁定的 IP 持久化到锁定列表文件。
func persistLockToFile(ctx context.Context, cidrStr string) error {
	log := logger.Get(ctx)
	globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
	if err != nil || !globalCfg.Base.PersistRules || globalCfg.Base.LockListFile == "" {
		return nil
	}

	filePath := globalCfg.Base.LockListFile
	var lines []string
	existingMap := make(map[string]bool)
	fileLines, readErr := fileutil.ReadLines(filePath)
	if readErr == nil {
		for _, line := range fileLines {
			if !existingMap[line] {
				lines = append(lines, line)
				existingMap[line] = true
			}
		}
	}

	if !existingMap[cidrStr] {
		lines = append(lines, cidrStr)
	}

	merged, err := ipmerge.MergeCIDRsWithThreshold(lines, globalCfg.Base.LockListMergeThreshold, globalCfg.Base.LockListV4Mask, globalCfg.Base.LockListV6Mask)
	if err != nil {
		log.Warnf("⚠️  Failed to merge IPs for persistence: %v", err)
		merged = lines
	}

	if err := fileutil.AtomicWriteFile(filePath, []byte(strings.Join(merged, "\n")+"\n"), 0644); err == nil {
		log.Infof("📄 Persisted %s to %s (Optimized to %d rules)", cidrStr, filePath, len(merged))
	}
	return nil
}

// removeFromLockFile removes an IP from the lock list file.
// removeFromLockFile 从锁定列表文件中移除 IP。
func removeFromLockFile(cidrStr string) error {
	globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
	if err != nil || globalCfg.Base.LockListFile == "" {
		return nil
	}

	filePath := globalCfg.Base.LockListFile
	fileLines, err := fileutil.ReadLines(filePath)
	if err != nil {
		return nil
	}

	var newLines []string
	targetCIDR := iputil.NormalizeCIDR(cidrStr)
	for _, line := range fileLines {
		if iputil.NormalizeCIDR(line) != targetCIDR {
			newLines = append(newLines, line)
		}
	}
	return fileutil.AtomicWriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

// lockIP locks an IP address to the blacklist.
// lockIP 将 IP 地址锁定到黑名单。
func lockIP(ctx context.Context, xdpMgr XDPManager, cidrStr string, force bool) error {
	log := logger.Get(ctx)
	if aborted := handleLockWhitelistConflict(ctx, xdpMgr, cidrStr, force); aborted {
		return nil
	}

	types.ConfigMu.Lock()
	defer types.ConfigMu.Unlock()

	if conflict, _ := xdpMgr.IsIPInWhitelist(cidrStr); conflict {
		if err := removeWhitelistAndLog(ctx, xdpMgr, cidrStr); err != nil {
			log.Warnf("⚠️  Failed to remove from whitelist: %v", err)
		}
	}

	if addErr := xdpMgr.AddBlacklistIP(cidrStr); addErr != nil {
		return fmt.Errorf("failed to lock %s: %v", cidrStr, addErr)
	}
	log.Infof("🛡️ Locked: %s", cidrStr)
	return persistLockToFile(ctx, cidrStr)
}

// unlockIP unlocks an IP address from the blacklist.
// unlockIP 从黑名单解锁 IP 地址。
func unlockIP(ctx context.Context, xdpMgr XDPManager, cidrStr string) error {
	log := logger.Get(ctx)
	types.ConfigMu.Lock()
	defer types.ConfigMu.Unlock()

	if err := xdpMgr.RemoveBlacklistIP(cidrStr); err != nil {
		return fmt.Errorf("failed to unlock %s: %v", cidrStr, err)
	}
	log.Infof("🔓 Unlocked: %s", cidrStr)
	return removeFromLockFile(cidrStr)
}

// SyncLockMap syncs a single lock IP to the XDP map and config.
// SyncLockMap 同步单个锁定 IP 到 XDP Map 和配置。
func SyncLockMap(ctx context.Context, xdpMgr XDPManager, cidrStr string, lock bool, force bool) error {
	cidrStr = iputil.NormalizeCIDR(cidrStr)

	if lock {
		return lockIP(ctx, xdpMgr, cidrStr, force)
	}
	return unlockIP(ctx, xdpMgr, cidrStr)
}

// handleWhitelistBlacklistConflict handles conflict when whitelisting an IP that's in blacklist.
// handleWhitelistBlacklistConflict 处理添加白名单时与黑名单的冲突。
func handleWhitelistBlacklistConflict(ctx context.Context, xdpMgr XDPManager, cidrStr string, force bool) bool {
	log := logger.Get(ctx)
	conflict, err := xdpMgr.IsIPInBlacklist(cidrStr)
	if err != nil || !conflict {
		return false
	}

	log.Warnf("⚠️  [Conflict] %s (Already in blacklist).", cidrStr)
	if !force && !AskConfirmation("Do you want to remove it from blacklist and add to whitelist?") {
		log.Info("Aborted.")
		return true
	}
	return false
}

// removeBlacklistAndLog removes IP from blacklist and logs the action.
// removeBlacklistAndLog 从黑名单移除 IP 并记录日志。
func removeBlacklistAndLog(ctx context.Context, xdpMgr XDPManager, cidrStr string) {
	log := logger.Get(ctx)
	if removeErr := xdpMgr.RemoveBlacklistIP(cidrStr); removeErr != nil {
		log.Warnf("⚠️  Failed to remove from blacklist: %v", removeErr)
	} else {
		log.Infof("🔓 Removed %s from blacklist", cidrStr)
	}
}

// updateWhitelistInConfig updates whitelist in config file.
// updateWhitelistInConfig 更新配置文件中的白名单。
func updateWhitelistInConfig(ctx context.Context, xdpMgr XDPManager, cidrStr string, port uint16) error {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		return err
	}

	entry := cidrStr
	if port > 0 {
		entry = fmt.Sprintf("%s:%d", cidrStr, port)
	}

	for _, ip := range globalCfg.Base.Whitelist {
		if ip == entry {
			return nil
		}
	}

	oldWhitelist := make([]string, len(globalCfg.Base.Whitelist))
	copy(oldWhitelist, globalCfg.Base.Whitelist)

	globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, entry)
	optimizer.OptimizeWhitelistConfig(globalCfg)
	if saveErr := types.SaveGlobalConfig(configPath, globalCfg); saveErr != nil {
		log.Warnf("⚠️  Failed to save config: %v", saveErr)
	}

	cleanupMergedWhitelistRules(ctx, xdpMgr, oldWhitelist, globalCfg.Base.Whitelist)
	ensureWhitelistRulesInBPF(ctx, xdpMgr, globalCfg.Base.Whitelist)
	return nil
}

// cleanupMergedWhitelistRules removes rules that were merged into larger subnets.
// cleanupMergedWhitelistRules 删除已合并到较大子网中的规则。
func cleanupMergedWhitelistRules(ctx context.Context, xdpMgr XDPManager, oldWhitelist, newWhitelist []string) {
	log := logger.Get(ctx)
	newSet := make(map[string]bool)
	for _, ip := range newWhitelist {
		newSet[ip] = true
	}

	for _, oldEntry := range oldWhitelist {
		if !newSet[oldEntry] {
			cidrToRemove := oldEntry
			if host, _, err := iputil.ParseIPPort(oldEntry); err == nil {
				cidrToRemove = host
			}
			_ = xdpMgr.RemoveWhitelistIP(cidrToRemove)
			log.Infof("🧹 Optimized runtime: Removed subsumed whitelist rule %s", cidrToRemove)
		}
	}
}

// ensureWhitelistRulesInBPF ensures all whitelist rules are in BPF map.
// ensureWhitelistRulesInBPF 确保所有白名单规则都在 BPF Map 中。
func ensureWhitelistRulesInBPF(ctx context.Context, xdpMgr XDPManager, whitelist []string) {
	log := logger.Get(ctx)
	for _, entry := range whitelist {
		cidrToAdd := entry
		portToAdd := uint16(0)
		if host, p, err := iputil.ParseIPPort(entry); err == nil {
			cidrToAdd = host
			portToAdd = p
		}
		if addErr := xdpMgr.AddWhitelistIP(cidrToAdd, portToAdd); addErr != nil {
			log.Warnf("⚠️  Failed to add whitelist IP %s: %v", cidrToAdd, addErr)
		}
	}
}

// allowIP adds an IP to the whitelist.
// allowIP 将 IP 添加到白名单。
func allowIP(ctx context.Context, xdpMgr XDPManager, cidrStr string, port uint16, force bool) error {
	log := logger.Get(ctx)
	if aborted := handleWhitelistBlacklistConflict(ctx, xdpMgr, cidrStr, force); aborted {
		return nil
	}

	types.ConfigMu.Lock()
	defer types.ConfigMu.Unlock()

	if conflict, _ := xdpMgr.IsIPInBlacklist(cidrStr); conflict {
		removeBlacklistAndLog(ctx, xdpMgr, cidrStr)
	}

	if addErr := xdpMgr.AddWhitelistIP(cidrStr, port); addErr != nil {
		return fmt.Errorf("failed to allow %s: %v", cidrStr, addErr)
	}

	if port > 0 {
		log.Infof("⚪ Whitelisted: %s (port: %d)", cidrStr, port)
	} else {
		log.Infof("⚪ Whitelisted: %s", cidrStr)
	}

	return updateWhitelistInConfig(ctx, xdpMgr, cidrStr, port)
}

// disallowIP removes an IP from the whitelist.
// disallowIP 从白名单移除 IP。
func disallowIP(ctx context.Context, xdpMgr XDPManager, cidrStr string, port uint16) error {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	types.ConfigMu.Lock()
	defer types.ConfigMu.Unlock()

	if err := xdpMgr.RemoveWhitelistIP(cidrStr); err != nil {
		return fmt.Errorf("failed to remove %s from whitelist: %v", cidrStr, err)
	}
	log.Infof("🔓 Removed from whitelist: %s", cidrStr)

	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		return nil
	}

	newWhitelist := []string{}
	targetCIDR := iputil.NormalizeCIDR(cidrStr)
	for _, ip := range globalCfg.Base.Whitelist {
		host, p, err := iputil.ParseIPPort(ip)
		var entryCIDR string
		var entryPort uint16
		if err != nil {
			entryCIDR = iputil.NormalizeCIDR(ip)
			entryPort = 0
		} else {
			entryCIDR = iputil.NormalizeCIDR(host)
			entryPort = p
		}

		if entryCIDR == targetCIDR && (port == 0 || entryPort == port) {
			continue
		}
		newWhitelist = append(newWhitelist, ip)
	}
	globalCfg.Base.Whitelist = newWhitelist
	if saveErr := types.SaveGlobalConfig(configPath, globalCfg); saveErr != nil {
		log.Warnf("⚠️  Failed to save config: %v", saveErr)
	}
	return nil
}

// SyncWhitelistMap syncs a whitelist entry to the XDP map and config.
// SyncWhitelistMap 同步白名单条目到 XDP Map 和配置。
func SyncWhitelistMap(ctx context.Context, xdpMgr XDPManager, cidrStr string, port uint16, allow bool, force bool) error {
	cidrStr = iputil.NormalizeCIDR(cidrStr)

	if allow {
		return allowIP(ctx, xdpMgr, cidrStr, port, force)
	}
	return disallowIP(ctx, xdpMgr, cidrStr, port)
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
	dynIps, dynCount, err := xdpMgr.ListDynamicBlacklistIPs(limit, search)
	if err != nil {
		log.Warnf("⚠️  Failed to list dynamic blacklist: %v", err)
	} else if dynCount > 0 {
		fmt.Println("\n📋 Dynamic Blacklist Rules:")
		for _, entry := range dynIps {
			fmt.Printf(" - %s (ExpiresAt: %d)\n", entry.IP, entry.ExpiresAt)
		}
	}
	return nil
}
