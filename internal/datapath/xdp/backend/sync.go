package xdp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/netxfw/netxfw/internal/binary"
	"github.com/netxfw/netxfw/internal/utils/ipmerge"
	"github.com/netxfw/netxfw/internal/utils/iputil"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// VerifyAndRepair ensures consistency between config and BPF maps by forcing a sync.
// Uses overwrite=false to avoid clearing existing rules (which would cause network outage).
// VerifyAndRepair 通过强制同步来确保配置和 BPF Map 之间的一致性。
// 使用 overwrite=false 避免清除现有规则（这会导致网络中断）。
func (m *Manager) VerifyAndRepair(cfg *sdk.GlobalConfig) error {
	m.logger.Infof("[SCAN] Verifying consistency between config and BPF maps (Auto-Repair)...")
	return m.SyncFromFiles(cfg, false)
}

// syncWhitelistFromConfig syncs whitelist rules from config to BPF maps.
// syncWhitelistFromConfig 从配置同步白名单规则到 BPF Map。
func (m *Manager) syncWhitelistFromConfig(whitelist []string) {
	if m.whitelist == nil {
		return
	}

	desiredByPort := make(map[uint16][]string)
	for _, rule := range whitelist {
		cidr := rule
		port := uint16(0)
		if host, p, err := iputil.ParseIPPort(rule); err == nil {
			cidr = host
			port = p
		}
		cidr = iputil.NormalizeCIDR(cidr)
		desiredByPort[port] = append(desiredByPort[port], cidr)
	}

	desiredEntries := make(map[string]struct{})
	for port, cidrs := range desiredByPort {
		merged, err := ipmerge.MergeCIDRs(cidrs)
		if err != nil {
			merged = cidrs
		}
		for _, cidr := range merged {
			desiredEntries[whitelistEntryKey(cidr, port)] = struct{}{}
		}
	}

	type currentEntry struct {
		key  NetXfwLpmKey
		cidr string
		port uint16
	}

	currentEntries := make([]currentEntry, 0)
	currentEntrySet := make(map[string]struct{})
	iter := m.whitelist.Iterate()
	var key NetXfwLpmKey
	var val NetXfwRuleValue
	for iter.Next(&key, &val) {
		port := uint16(0)
		if val.Counter > 1 && val.Counter <= uint64(^uint16(0)) {
			port = uint16(val.Counter)
		}

		entry := currentEntry{
			key:  key,
			cidr: FormatLpmKey(&key),
			port: port,
		}
		currentEntries = append(currentEntries, entry)
		currentEntrySet[whitelistEntryKey(entry.cidr, entry.port)] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		m.logger.Warnf("[WARN]  Failed to iterate whitelist map: %v", err)
		return
	}

	for _, entry := range currentEntries {
		entryKey := whitelistEntryKey(entry.cidr, entry.port)
		if _, shouldKeep := desiredEntries[entryKey]; shouldKeep {
			continue
		}
		if err := m.whitelist.Delete(&entry.key); err != nil && !strings.Contains(err.Error(), "key does not exist") {
			m.logger.Warnf("[WARN]  Failed to remove stale whitelist %s: %v", entry.cidr, err)
		}
	}

	for entryKey := range desiredEntries {
		if _, exists := currentEntrySet[entryKey]; exists {
			continue
		}
		cidr, port := parseWhitelistEntryKey(entryKey)
		if err := AllowIP(m.whitelist, cidr, port); err != nil {
			m.logger.Warnf("[WARN]  Failed to whitelist %s: %v", cidr, err)
		}
	}
}

func whitelistEntryKey(cidr string, port uint16) string {
	return fmt.Sprintf("%d|%s", port, iputil.NormalizeCIDR(cidr))
}

func parseWhitelistEntryKey(entry string) (string, uint16) {
	parts := strings.SplitN(entry, "|", 2)
	if len(parts) != 2 {
		return iputil.NormalizeCIDR(entry), 0
	}

	var port uint16
	fmt.Sscanf(parts[0], "%d", &port)
	return parts[1], port
}

// parseLockListFile reads and parses the lock list file.
// parseLockListFile 读取并解析锁定列表文件。
func (m *Manager) parseLockListFile(filePath string) ([]binary.Record, error) {
	safePath := filepath.Clean(filePath) // Sanitize path to prevent directory traversal
	file, err := os.Open(safePath)       // #nosec G304 // path is sanitized with filepath.Clean
	if err != nil {
		return nil, fmt.Errorf("failed to open lock list file: %w", err)
	}
	defer file.Close()

	var records []binary.Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		record, ok := m.parseLockListLine(line)
		if ok {
			records = append(records, record)
		}
	}
	return records, scanner.Err()
}

// parseLockListLine parses a single line from the lock list file.
// parseLockListLine 解析锁定列表文件中的单行。
func (m *Manager) parseLockListLine(line string) (binary.Record, bool) {
	ip, ipNet, err := net.ParseCIDR(line)
	var ones int
	if err != nil {
		ip = net.ParseIP(line)
		if ip == nil {
			m.logger.Warnf("[WARN]  Skipping invalid IP/CIDR: %s", line)
			return binary.Record{}, false
		}
		if ip.To4() != nil {
			ones = 32
		} else {
			ones = 128
		}
	} else {
		ones, _ = ipNet.Mask.Size()
	}

	return binary.Record{
		IP:        ip,
		PrefixLen: uint8(ones), // nolint:gosec // G115: prefixlen is always 0-32
		IsIPv6:    ip.To4() == nil,
	}, true
}

// syncBlacklistRecords syncs blacklist records to BPF maps.
// syncBlacklistRecords 将黑名单记录同步到 BPF Map。
func (m *Manager) syncBlacklistRecords(records []binary.Record) {
	for _, r := range records {
		if m.staticBlacklist == nil {
			continue
		}
		if err := LockIP(m.staticBlacklist, fmt.Sprintf("%s/%d", r.IP.String(), r.PrefixLen)); err != nil {
			m.logger.Warnf("[WARN]  Failed to lock %s/%d: %v", r.IP.String(), r.PrefixLen, err)
		}
	}
}

// parseIPToNet converts an IP string to an IPNet.
// parseIPToNet 将 IP 字符串转换为 IPNet。
func parseIPToNet(ipStr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(ipStr)
	if err != nil {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}
	}
	return ipNet
}

// syncIPPortRules syncs IP+Port rules from config to BPF maps.
// syncIPPortRules 从配置同步 IP+端口规则到 BPF Map。
func (m *Manager) syncIPPortRules(rules []sdk.IPPortRule) {
	for _, rule := range rules {
		ipNet := parseIPToNet(rule.IP)
		if ipNet != nil {
			if err := m.AddIPPortRule(ipNet, rule.Port, rule.Action, nil); err != nil {
				m.logger.Warnf("[WARN]  Failed to add IP+Port rule %s:%d (action %d): %v", rule.IP, rule.Port, rule.Action, err)
			}
		}
	}
}

// syncAllowedPorts syncs allowed ports from config to BPF maps.
// syncAllowedPorts 从配置同步允许端口到 BPF Map。
func (m *Manager) syncAllowedPorts(ports []uint16) {
	m.logger.Infof("[CONFIG] Syncing allowed ports: %v (count: %d), rule_map=%v", ports, len(ports), m.ruleMap)
	for _, port := range ports {
		if err := m.AllowPort(port, nil); err != nil {
			m.logger.Warnf("[WARN]  Failed to allow port %d: %v", port, err)
		} else {
			m.logger.Infof("[CONFIG] Allowed port: %d", port)
		}
	}
}

// syncRateLimitRules syncs rate limit rules from config to BPF maps.
// syncRateLimitRules 从配置同步速率限制规则到 BPF Map。
func (m *Manager) syncRateLimitRules(rules []sdk.RateLimitRule) {
	for _, rule := range rules {
		ipNet := parseIPToNet(rule.IP)
		if ipNet != nil {
			if err := m.AddRateLimitRule(ipNet, rule.Rate, rule.Burst); err != nil {
				m.logger.Warnf("[WARN]  Failed to add rate limit rule %s: %v", rule.IP, err)
			}
		}
	}
}

// syncGlobalConfig syncs global configuration to BPF maps.
// syncGlobalConfig 将全局配置同步到 BPF Map。
func (m *Manager) syncGlobalConfig(cfg *sdk.GlobalConfig) {
	m.logger.Infof("[CONFIG] Syncing global config: default_deny=%v, allow_return=%v, allow_icmp=%v, enable_afxdp=%v, enable_ratelimit=%v, conntrack=%v",
		cfg.Base.DefaultDeny, cfg.Base.AllowReturnTraffic, cfg.Base.AllowICMP, cfg.Base.EnableAFXDP, cfg.RateLimit.Enabled, cfg.Conntrack.Enabled)
	m.setGlobalConfigValue(m.SetDefaultDeny, cfg.Base.DefaultDeny, "default deny")
	m.setGlobalConfigValue(m.SetAllowReturnTraffic, cfg.Base.AllowReturnTraffic, "allow return traffic")
	m.setGlobalConfigValue(m.SetAllowICMP, cfg.Base.AllowICMP, "allow ICMP")
	m.setGlobalConfigValue(m.SetEnableAFXDP, cfg.Base.EnableAFXDP, "enable AF_XDP")
	m.setGlobalConfigValue(m.SetEnableRateLimit, cfg.RateLimit.Enabled, "enable rate limit")
	m.setGlobalConfigValue(m.SetConntrack, cfg.Conntrack.Enabled, "conntrack")

	if err := m.SetICMPRateLimit(cfg.Base.ICMPRate, cfg.Base.ICMPBurst); err != nil {
		m.logger.Warnf("[WARN]  Failed to set ICMP rate limit: %v", err)
	} else {
		m.logger.Infof("[CONFIG] ICMP rate limit: rate=%d, burst=%d", cfg.Base.ICMPRate, cfg.Base.ICMPBurst)
	}

	if cfg.Conntrack.TCPTimeout != "" {
		if d, err := time.ParseDuration(cfg.Conntrack.TCPTimeout); err == nil {
			m.SetConntrackTimeout(d)
			m.logger.Infof("[CONFIG] Conntrack TCP timeout: %v", d)
		}
	}

	m.SetAutoBlock(cfg.RateLimit.AutoBlock)
	m.logger.Infof("[CONFIG] Auto block: enabled=%v", cfg.RateLimit.AutoBlock)
	if cfg.RateLimit.AutoBlockExpiry != "" {
		if d, err := time.ParseDuration(cfg.RateLimit.AutoBlockExpiry); err == nil {
			m.SetAutoBlockExpiry(d)
			m.logger.Infof("[CONFIG] Auto block expiry: %v", d)
		}
	}
}

// setGlobalConfigValue is a helper to set global config values with error logging.
// setGlobalConfigValue 是设置全局配置值并记录错误的辅助函数。
func (m *Manager) setGlobalConfigValue(setter func(bool) error, value bool, name string) {
	if err := setter(value); err != nil {
		m.logger.Warnf("[WARN]  Failed to set %s: %v", name, err)
	}
}

// SyncFromFiles reads rules from text or binary files and updates BPF maps.
// If overwrite is true, it clears existing rules in the maps first.
// SyncFromFiles 从文本或二进制文件读取规则并更新 BPF Map。
// 如果 overwrite 为 true，则先清除 Map 中的现有规则。
func (m *Manager) SyncFromFiles(cfg *sdk.GlobalConfig, overwrite bool) error {
	if overwrite {
		m.logger.Infof("[CLEAN] Overwrite mode: Clearing BPF maps before sync...")
		m.ClearMaps()
	}

	// Sync global config first (even without lock_list_file)
	// 先同步全局配置（即使没有 lock_list_file）
	m.logger.Infof("[SYNC] Syncing global config to BPF maps...")
	m.syncGlobalConfig(cfg)

	// If no lock_list_file configured, skip file loading but sync other config
	// 如果没有配置 lock_list_file，跳过文件加载但同步其他配置
	if cfg.Base.LockListFile == "" {
		m.logger.Infof("[INFO]  No lock_list_file configured, skipping file sync")
		// Still sync allowed ports, rate limit rules, and modules
		// 仍然同步允许端口、速率限制规则和模块
		m.syncAllowedPorts(cfg.Port.AllowedPorts)
		m.syncRateLimitRules(cfg.RateLimit.Rules)
		m.syncIPPortRules(cfg.Port.IPPortRules)
		if err := m.SyncModules(cfg.Modules); err != nil {
			m.logger.Warnf("Failed to sync modules chain: %v", err)
		}
		return nil
	}

	// Try to load from binary file first if configured (for better performance)
	// 如果配置了二进制文件，优先尝试加载（以获得更好的性能）
	loadedFromBinary := false
	if cfg.Base.LockListBinary != "" {
		if err := m.loadFromBinaryFile(cfg); err != nil {
			m.logger.Warnf("[WARN]  Failed to load from binary file: %v, falling back to text file", err)
		} else {
			m.logger.Infof("[OK] Successfully loaded rules from binary file")
			loadedFromBinary = true
		}
	}

	// 1. Sync Whitelist / 1. 同步白名单
	m.logger.Infof("[CONFIG] Syncing whitelist: %v (count: %d)", cfg.Base.Whitelist, len(cfg.Base.Whitelist))
	m.syncWhitelistFromConfig(cfg.Base.Whitelist)

	var records []binary.Record
	if loadedFromBinary {
		// If we loaded from binary, we still need records for UpdateBinaryCache
		// Read from text file just to get records for cache update
		var err error
		records, err = m.parseLockListFile(cfg.Base.LockListFile)
		if err != nil {
			m.logger.Warnf("[WARN]  Could not read text file for cache update: %v", err)
			// We can still continue if we have loaded from binary
		}
	} else {
		// Original behavior: load from text file
		var err error
		records, err = m.parseLockListFile(cfg.Base.LockListFile)
		if err != nil {
			return err
		}
		// Log that we're syncing from text file
		m.logger.Infof("[RELOAD] Syncing rules from %s and config to BPF maps...", cfg.Base.LockListFile)
	}

	// 3. Sync Blacklist / 3. 同步黑名单
	m.logger.Infof("[CONFIG] Syncing blacklist: %d records from file", len(records))
	m.syncBlacklistRecords(records)

	// 6. Sync rate limit rules / 6. 同步速率限制规则
	m.syncRateLimitRules(cfg.RateLimit.Rules)

	// 7. Sync allowed ports / 7. 同步允许端口
	m.syncAllowedPorts(cfg.Port.AllowedPorts)

	// 8. Sync IP+Port rules / 8. 同步 IP+端口规则
	m.syncIPPortRules(cfg.Port.IPPortRules)

	// 9. Update binary cache / 9. 更新二进制缓存
	go m.UpdateBinaryCache(cfg, records)

	// 10. Sync Modules Chain / 10. 同步模块链
	if err := m.SyncModules(cfg.Modules); err != nil {
		m.logger.Warnf("Failed to sync modules chain: %v", err)
		return err
	}

	return nil
}

// ClearMaps clears all rules from blacklist and whitelist maps.
// ClearMaps 清除黑名单和白名单 Map 中的所有规则。
func (m *Manager) ClearMaps() {
	maps := []*ebpf.Map{m.staticBlacklist, m.dynamicBlacklist, m.criticalBlacklist, m.whitelist, m.ruleMap}
	for _, emap := range maps {
		if emap == nil {
			logger.Get(nil).Warnf("Map is nil, skipping")
			continue
		}

		// 安全地迭代并删除所有键值对
		var keys [][]byte

		iter := emap.Iterate()
		for {
			var k []byte
			var v interface{} // 临时值，虽然我们不使用它

			// 使用迭代器安全地获取键值对
			hasNext := iter.Next(&k, &v)
			if !hasNext {
				break
			}

			// 将键复制并保存
			if k != nil {
				keyCopy := make([]byte, len(k))
				copy(keyCopy, k)
				keys = append(keys, keyCopy)
			}
		}

		// 释放迭代器
		_ = iter.Err() // 检查迭代错误但不处理

		// 删除所有收集到的键
		for _, key := range keys {
			if key != nil {
				err := emap.Delete(key)
				if err != nil {
					logger.Get(nil).Warnf("Failed to delete key from map: %v", err)
				}
			}
		}
	}
	logger.Get(nil).Infof("[OK] All BPF maps cleared.")
}

// ClearMap clears all rules from a specific BPF map.
// ClearMap 清除特定 BPF Map 中的所有规则。
func ClearMap(mapPtr *ebpf.Map) (int, error) {
	if mapPtr == nil {
		return 0, fmt.Errorf("mapPtr is nil")
	}

	removed := 0
	iter := mapPtr.Iterate()
	// Use []byte for generic iteration / 使用 []byte 进行通用遍历
	var k []byte
	var v []byte
	for iter.Next(&k, &v) {
		if err := mapPtr.Delete(k); err == nil {
			removed++
		}
	}
	return removed, iter.Err()
}
