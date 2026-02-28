package xdp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/klauspost/compress/zstd"
	"github.com/netxfw/netxfw/internal/binary"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// VerifyAndRepair ensures consistency between config and BPF maps by forcing a sync.
// VerifyAndRepair 通过强制同步来确保配置和 BPF Map 之间的一致性。
func (m *Manager) VerifyAndRepair(cfg *types.GlobalConfig) error {
	m.logger.Infof("[SCAN] Verifying consistency between config and BPF maps (Auto-Repair)...")
	return m.SyncFromFiles(cfg, true)
}

// syncWhitelistFromConfig syncs whitelist rules from config to BPF maps.
// syncWhitelistFromConfig 从配置同步白名单规则到 BPF Map。
func (m *Manager) syncWhitelistFromConfig(whitelist []string) {
	for _, rule := range whitelist {
		cidr := rule
		port := uint16(0)
		if strings.Contains(rule, ":") && !strings.Contains(rule, "[") && !strings.Contains(rule, "/") {
			parts := strings.Split(rule, ":")
			if len(parts) == 2 {
				cidr = parts[0]
				if _, err := fmt.Sscanf(parts[1], "%d", &port); err != nil {
					m.logger.Warnf("[WARN]  Failed to parse port from whitelist rule %s: %v", rule, err)
				}
			}
		}
		if m.whitelist != nil {
			if err := AllowIP(m.whitelist, cidr, port); err != nil {
				m.logger.Warnf("[WARN]  Failed to whitelist %s: %v", rule, err)
			}
		}
	}
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
func (m *Manager) syncIPPortRules(rules []types.IPPortRule) {
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
	for _, port := range ports {
		if err := m.AllowPort(port, nil); err != nil {
			m.logger.Warnf("[WARN]  Failed to allow port %d: %v", port, err)
		}
	}
}

// syncRateLimitRules syncs rate limit rules from config to BPF maps.
// syncRateLimitRules 从配置同步速率限制规则到 BPF Map。
func (m *Manager) syncRateLimitRules(rules []types.RateLimitRule) {
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
func (m *Manager) syncGlobalConfig(cfg *types.GlobalConfig) {
	m.setGlobalConfigValue(m.SetDefaultDeny, cfg.Base.DefaultDeny, "default deny")
	m.setGlobalConfigValue(m.SetAllowReturnTraffic, cfg.Base.AllowReturnTraffic, "allow return traffic")
	m.setGlobalConfigValue(m.SetAllowICMP, cfg.Base.AllowICMP, "allow ICMP")
	m.setGlobalConfigValue(m.SetEnableAFXDP, cfg.Base.EnableAFXDP, "enable AF_XDP")
	m.setGlobalConfigValue(m.SetEnableRateLimit, cfg.RateLimit.Enabled, "enable rate limit")
	m.setGlobalConfigValue(m.SetConntrack, cfg.Conntrack.Enabled, "conntrack")

	if err := m.SetICMPRateLimit(cfg.Base.ICMPRate, cfg.Base.ICMPBurst); err != nil {
		m.logger.Warnf("[WARN]  Failed to set ICMP rate limit: %v", err)
	}

	if cfg.Conntrack.TCPTimeout != "" {
		if d, err := time.ParseDuration(cfg.Conntrack.TCPTimeout); err == nil {
			m.SetConntrackTimeout(d)
		}
	}

	m.SetAutoBlock(cfg.RateLimit.AutoBlock)
	if cfg.RateLimit.AutoBlockExpiry != "" {
		if d, err := time.ParseDuration(cfg.RateLimit.AutoBlockExpiry); err == nil {
			m.SetAutoBlockExpiry(d)
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
func (m *Manager) SyncFromFiles(cfg *types.GlobalConfig, overwrite bool) error {
	if cfg.Base.LockListFile == "" || cfg.Base.LockListBinary == "" {
		return fmt.Errorf("lock_list_file and lock_list_binary must be configured for sync")
	}

	if overwrite {
		m.logger.Infof("[CLEAN] Overwrite mode: Clearing BPF maps before sync...")
		m.ClearMaps()
	}

	// NEW: Try to load from binary file first for better performance
	loadedFromBinary := false
	if err := m.loadFromBinaryFile(cfg); err != nil {
		m.logger.Warnf("[WARN]  Failed to load from binary file: %v, falling back to text file", err)
	} else {
		m.logger.Infof("[OK] Successfully loaded rules from binary file")
		loadedFromBinary = true
	}

	// 1. Sync Whitelist / 1. 同步白名单
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
	m.syncBlacklistRecords(records)

	// 4. Sync IP+Port rules / 4. 同步 IP+端口规则
	m.syncIPPortRules(cfg.Port.IPPortRules)

	// 5. Sync allowed ports / 5. 同步允许端口
	m.syncAllowedPorts(cfg.Port.AllowedPorts)

	// 6. Sync rate limit rules / 6. 同步速率限制规则
	m.syncRateLimitRules(cfg.RateLimit.Rules)

	// 7. Sync Global Config / 7. 同步全局配置
	m.syncGlobalConfig(cfg)

	// 8. Update binary cache / 8. 更新二进制缓存
	go m.UpdateBinaryCache(cfg, records)

	return nil
}

// loadFromBinaryFile loads rules directly from the binary file
func (m *Manager) loadFromBinaryFile(cfg *types.GlobalConfig) error {
	// Open and decompress the binary file
	file, err := os.Open(cfg.Base.LockListBinary)
	if err != nil {
		return fmt.Errorf("failed to open binary file: %v", err)
	}
	defer file.Close()

	decoder, err := zstd.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create zstd decoder: %v", err)
	}
	defer decoder.Close()

	// Decode the binary records
	records, err := binary.Decode(decoder)
	if err != nil {
		return fmt.Errorf("failed to decode binary records: %v", err)
	}

	// Update BPF maps with the decoded records
	m.syncBlacklistRecords(records)

	m.logger.Infof("[OK] Loaded %d rules from binary file", len(records))
	return nil
}

// UpdateBinaryCache encodes records to binary format and compresses them.
// UpdateBinaryCache 将记录编码为二进制格式并进行压缩。
func (m *Manager) UpdateBinaryCache(cfg *types.GlobalConfig, records []binary.Record) {
	if cfg.Base.LockListBinary == "" {
		return
	}

	// Validate and sanitize paths to prevent command injection
	// 验证并清理路径以防止命令注入
	lockListBinary := filepath.Clean(cfg.Base.LockListBinary)
	if strings.ContainsAny(lockListBinary, ";&|`$()") {
		m.logger.Errorf("[ERROR] Invalid characters in lock_list_binary path")
		return
	}

	tmpBin := lockListBinary + ".tmp"
	safeTmpBin := filepath.Clean(tmpBin)        // Sanitize path to prevent directory traversal
	tmpFile, createErr := os.Create(safeTmpBin) // #nosec G304 // path is sanitized with filepath.Clean
	if createErr != nil {
		m.logger.Errorf("[ERROR] Failed to create temporary binary file: %v", createErr)
		return
	}

	if encodeErr := binary.Encode(tmpFile, records); encodeErr != nil {
		tmpFile.Close()
		os.Remove(tmpBin)
		m.logger.Errorf("[ERROR] Failed to encode binary records: %v", encodeErr)
		return
	}
	tmpFile.Close()

	// Use absolute paths to prevent directory traversal
	// 使用绝对路径防止目录遍历
	absLockListBinary, err := filepath.Abs(lockListBinary)
	if err != nil {
		os.Remove(tmpBin)
		m.logger.Errorf("[ERROR] Failed to get absolute path: %v", err)
		return
	}
	absTmpBin, err := filepath.Abs(tmpBin)
	if err != nil {
		os.Remove(tmpBin)
		m.logger.Errorf("[ERROR] Failed to get absolute path: %v", err)
		return
	}

	cmd := exec.Command("zstd", "-f", "-o", absLockListBinary, absTmpBin) // #nosec G204 // absLockListBinary and absTmpBin are validated paths
	if output, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmpBin)
		m.logger.Errorf("[ERROR] Failed to compress with zstd: %v\nOutput: %s", err, string(output))
		return
	}
	os.Remove(tmpBin)
	m.logger.Infof("[OK] Successfully updated binary cache %s", lockListBinary)
}

// SyncToFiles dumps current BPF map rules back to text files.
// SyncToFiles 将当前 BPF Map 规则转储回文本文件。
func (m *Manager) SyncToFiles(cfg *types.GlobalConfig) error {
	if cfg.Base.LockListFile == "" {
		return fmt.Errorf("lock_list_file must be configured")
	}

	m.logger.Infof("[SAVE] Syncing BPF maps to %s and config object...", cfg.Base.LockListFile)

	m.syncWhitelistToConfig(cfg)
	ips, err := m.syncBlacklistToConfig(cfg)
	if err != nil {
		return err
	}
	m.syncIPPortRulesToConfig(cfg)
	m.syncAllowedPortsToConfig(cfg)
	m.syncRateLimitRulesToConfig(cfg)
	m.syncGlobalConfigToConfig(cfg)

	return m.writeLockListFile(cfg, ips)
}

// syncWhitelistToConfig syncs whitelist from BPF map to config.
// syncWhitelistToConfig 从 BPF Map 同步白名单到配置。
func (m *Manager) syncWhitelistToConfig(cfg *types.GlobalConfig) {
	wl, _, err := ListBlockedIPs(m.whitelist, false, 0, "")
	if err != nil {
		return
	}

	newWhitelist := []string{}
	for _, entry := range wl {
		if entry.Counter > 1 {
			newWhitelist = append(newWhitelist, fmt.Sprintf("%s:%d", entry.IP, entry.Counter))
		} else {
			newWhitelist = append(newWhitelist, entry.IP)
		}
	}
	cfg.Base.Whitelist = newWhitelist
}

// syncBlacklistToConfig syncs blacklist from BPF map to config.
// syncBlacklistToConfig 从 BPF Map 同步黑名单到配置。
func (m *Manager) syncBlacklistToConfig(cfg *types.GlobalConfig) ([]sdk.BlockedIP, error) {
	ips, _, err := ListBlockedIPs(m.staticBlacklist, false, 0, "")
	return ips, err
}

// syncIPPortRulesToConfig syncs IP+Port rules from BPF map to config.
// syncIPPortRulesToConfig 从 BPF Map 同步 IP+端口规则到配置。
func (m *Manager) syncIPPortRulesToConfig(cfg *types.GlobalConfig) {
	ipPortRules, _, err := m.ListIPPortRules(false, 0, "")
	if err != nil {
		return
	}

	newIPPortRules := make([]types.IPPortRule, 0, len(ipPortRules))
	for key, actionStr := range ipPortRules {
		lastColon := strings.LastIndex(key, ":")
		if lastColon == -1 {
			continue
		}

		ipCIDR := key[:lastColon]
		portStr := key[lastColon+1:]
		port := uint16(0)
		fmt.Sscanf(portStr, "%d", &port)

		action := uint8(2)
		if actionStr == "allow" {
			action = 1
		}

		newIPPortRules = append(newIPPortRules, types.IPPortRule{
			IP:     ipCIDR,
			Port:   port,
			Action: action,
		})
	}
	cfg.Port.IPPortRules = newIPPortRules
}

// syncAllowedPortsToConfig syncs allowed ports from BPF map to config.
// syncAllowedPortsToConfig 从 BPF Map 同步允许端口到配置。
func (m *Manager) syncAllowedPortsToConfig(cfg *types.GlobalConfig) {
	ports, err := m.ListAllowedPorts()
	if err != nil {
		return
	}
	cfg.Port.AllowedPorts = ports
}

// syncRateLimitRulesToConfig syncs rate limit rules from BPF map to config.
// syncRateLimitRulesToConfig 从 BPF Map 同步速率限制规则到配置。
func (m *Manager) syncRateLimitRulesToConfig(cfg *types.GlobalConfig) {
	rules, _, err := m.ListRateLimitRules(0, "")
	if err != nil {
		return
	}

	newRateRules := make([]types.RateLimitRule, 0, len(rules))
	for target, conf := range rules {
		newRateRules = append(newRateRules, types.RateLimitRule{
			IP:    target,
			Rate:  conf.Rate,
			Burst: conf.Burst,
		})
	}
	cfg.RateLimit.Rules = newRateRules
}

// syncGlobalConfigToConfig syncs global config from BPF map to config object.
// syncGlobalConfigToConfig 从 BPF Map 同步全局配置到配置对象。
func (m *Manager) syncGlobalConfigToConfig(cfg *types.GlobalConfig) {
	if m.globalConfig == nil {
		return
	}

	var val uint64
	var key uint32

	key = configDefaultDeny
	if err := m.globalConfig.Lookup(&key, &val); err == nil {
		cfg.Base.DefaultDeny = (val == 1)
	}
	key = configAllowReturnTraffic
	if err := m.globalConfig.Lookup(&key, &val); err == nil {
		cfg.Base.AllowReturnTraffic = (val == 1)
	}
	key = configAllowICMP
	if err := m.globalConfig.Lookup(&key, &val); err == nil {
		cfg.Base.AllowICMP = (val == 1)
	}
	key = configEnableAFXDP
	if err := m.globalConfig.Lookup(&key, &val); err == nil {
		cfg.Base.EnableAFXDP = (val == 1)
	}
	key = configICMPRate
	if err := m.globalConfig.Lookup(&key, &val); err == nil {
		cfg.Base.ICMPRate = val
	}
	key = configICMPBurst
	if err := m.globalConfig.Lookup(&key, &val); err == nil {
		cfg.Base.ICMPBurst = val
	}
	key = configEnableRateLimit
	if err := m.globalConfig.Lookup(&key, &val); err == nil {
		cfg.RateLimit.Enabled = (val == 1)
	}
	key = configEnableConntrack
	if err := m.globalConfig.Lookup(&key, &val); err == nil {
		cfg.Conntrack.Enabled = (val == 1)
	}
	key = configConntrackTimeout
	if err := m.globalConfig.Lookup(&key, &val); err == nil {
		cfg.Conntrack.TCPTimeout = time.Duration(val).String() // nolint:gosec // G115: timeout is always valid
	}
}

// writeLockListFile writes the lock list to file.
// writeLockListFile 将锁定列表写入文件。
func (m *Manager) writeLockListFile(cfg *types.GlobalConfig, ips []sdk.BlockedIP) error {
	var buf bytes.Buffer
	for _, entry := range ips {
		buf.WriteString(entry.IP + "\n")
	}
	return fileutil.AtomicWriteFile(cfg.Base.LockListFile, buf.Bytes(), 0644)
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
		if mapPtr != nil {
			if err := mapPtr.Delete(k); err == nil {
				removed++
			}
		}
	}
	return removed, iter.Err()
}
