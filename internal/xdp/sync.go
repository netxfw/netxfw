package xdp

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/binary"
	"github.com/livp123/netxfw/internal/plugins/types"
)

// SyncFromFiles reads rules from text files and updates BPF maps.
// If overwrite is true, it clears existing rules in the maps first.
// SyncFromFiles 从文本文件读取规则并更新 BPF Map。
// 如果 overwrite 为 true，则先清除 Map 中的现有规则。
func (m *Manager) SyncFromFiles(cfg *types.GlobalConfig, overwrite bool) error {
	if cfg.Base.LockListFile == "" || cfg.Base.LockListBinary == "" {
		return fmt.Errorf("lock_list_file and lock_list_binary must be configured for sync")
	}

	if overwrite {
		m.logger.Infof("🧹 Overwrite mode: Clearing BPF maps before sync...")
		m.ClearMaps()
	}

	m.logger.Infof("🔄 Syncing rules from %s and config to BPF maps...", cfg.Base.LockListFile)

	// 1. Sync Whitelist from config to maps / 从配置同步白名单到 Map
	for _, rule := range cfg.Base.Whitelist {
		cidr := rule
		port := uint16(0)
		if strings.Contains(rule, ":") && !strings.Contains(rule, "[") && !strings.Contains(rule, "/") {
			parts := strings.Split(rule, ":")
			if len(parts) == 2 {
				cidr = parts[0]
				fmt.Sscanf(parts[1], "%d", &port)
			}
		}

		var targetMap *ebpf.Map
		targetMap = m.whitelist

		if targetMap != nil {
			if err := AllowIP(targetMap, cidr, port); err != nil {
				m.logger.Warnf("⚠️  Failed to whitelist %s: %v", rule, err)
			}
		}
	}

	// 2. Read and parse rules.deny.txt / 读取并解析 rules.deny.txt
	file, err := os.Open(cfg.Base.LockListFile)
	if err != nil {
		return fmt.Errorf("failed to open lock list file: %w", err)
	}
	defer file.Close()

	var records []binary.Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ip, ipNet, err := net.ParseCIDR(line)
		var ones int
		if err != nil {
			ip = net.ParseIP(line)
			if ip == nil {
				m.logger.Warnf("⚠️  Skipping invalid IP/CIDR: %s", line)
				continue
			}
			if ip.To4() != nil {
				ones = 32
			} else {
				ones = 128
			}
		} else {
			ones, _ = ipNet.Mask.Size()
		}

		records = append(records, binary.Record{
			IP:        ip,
			PrefixLen: uint8(ones),
			IsIPv6:    ip.To4() == nil,
		})
	}

	// 2. Update BPF Maps / 更新 BPF Map
	for _, r := range records {
		var targetMap *ebpf.Map
		targetMap = m.lockList

		if targetMap == nil {
			continue
		}

		if err := LockIP(targetMap, fmt.Sprintf("%s/%d", r.IP.String(), r.PrefixLen)); err != nil {
			m.logger.Warnf("⚠️  Failed to lock %s/%d: %v", r.IP.String(), r.PrefixLen, err)
		}
	}

	// 3. Sync IP+Port rules from config to maps / 从配置同步 IP+端口规则到 Map
	for _, rule := range cfg.Port.IPPortRules {
		_, ipNet, err := net.ParseCIDR(rule.IP)
		if err != nil {
			ip := net.ParseIP(rule.IP)
			if ip != nil {
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				ipNet = &net.IPNet{IP: ip, Mask: mask}
			}
		}
		if ipNet != nil {
			if err := m.AddIPPortRule(ipNet, rule.Port, rule.Action, nil); err != nil {
				m.logger.Warnf("⚠️  Failed to add IP+Port rule %s:%d (action %d): %v", rule.IP, rule.Port, rule.Action, err)
			}
		}
	}

	// 4. Sync allowed ports from config to maps / 从配置同步允许端口到 Map
	for _, port := range cfg.Port.AllowedPorts {
		if err := m.AllowPort(port, nil); err != nil {
			m.logger.Warnf("⚠️  Failed to allow port %d: %v", port, err)
		}
	}

	// 5. Sync rate limit rules from config to maps / 从配置同步速率限制规则到 Map
	for _, rule := range cfg.RateLimit.Rules {
		_, ipNet, err := net.ParseCIDR(rule.IP)
		if err != nil {
			ip := net.ParseIP(rule.IP)
			if ip != nil {
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				ipNet = &net.IPNet{IP: ip, Mask: mask}
			}
		}
		if ipNet != nil {
			if err := m.AddRateLimitRule(ipNet, rule.Rate, rule.Burst); err != nil {
				m.logger.Warnf("⚠️  Failed to add rate limit rule %s: %v", rule.IP, err)
			}
		}
	}

	// 6. Sync Global Config from config to maps / 从配置同步全局设置到 Map
	m.SetDefaultDeny(cfg.Base.DefaultDeny)
	m.SetAllowReturnTraffic(cfg.Base.AllowReturnTraffic)
	m.SetAllowICMP(cfg.Base.AllowICMP)
	m.SetEnableAFXDP(cfg.Base.EnableAFXDP)
	m.SetICMPRateLimit(cfg.Base.ICMPRate, cfg.Base.ICMPBurst)
	m.SetEnableRateLimit(cfg.RateLimit.Enabled)
	m.SetConntrack(cfg.Conntrack.Enabled)
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

	// 7. (Optional) Update binary cache for fast loading on restart
	// 7. （可选）更新二进制缓存以便在重启时快速加载
	go m.UpdateBinaryCache(cfg, records)

	return nil
}

// UpdateBinaryCache encodes records to binary format and compresses them.
// UpdateBinaryCache 将记录编码为二进制格式并进行压缩。
func (m *Manager) UpdateBinaryCache(cfg *types.GlobalConfig, records []binary.Record) {
	if cfg.Base.LockListBinary == "" {
		return
	}

	tmpBin := cfg.Base.LockListBinary + ".tmp"
	tmpFile, err := os.Create(tmpBin)
	if err != nil {
		m.logger.Errorf("❌ Failed to create temporary binary file: %v", err)
		return
	}

	if err := binary.Encode(tmpFile, records); err != nil {
		tmpFile.Close()
		os.Remove(tmpBin)
		m.logger.Errorf("❌ Failed to encode binary records: %v", err)
		return
	}
	tmpFile.Close()

	cmd := exec.Command("zstd", "-f", "-o", cfg.Base.LockListBinary, tmpBin)
	if output, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmpBin)
		m.logger.Errorf("❌ Failed to compress with zstd: %v\nOutput: %s", err, string(output))
		return
	}
	os.Remove(tmpBin)
	m.logger.Infof("✅ Successfully updated binary cache %s", cfg.Base.LockListBinary)
}

// SyncToFiles dumps current BPF map rules back to text files.
// SyncToFiles 将当前 BPF Map 规则转储回文本文件。
func (m *Manager) SyncToFiles(cfg *types.GlobalConfig) error {
	if cfg.Base.LockListFile == "" {
		return fmt.Errorf("lock_list_file must be configured")
	}

	m.logger.Infof("💾 Syncing BPF maps to %s and config object...", cfg.Base.LockListFile)

	// 1. Sync Whitelist from maps to config object / 从 Map 同步白名单到配置对象
	wl, _, err := ListBlockedIPs(m.whitelist, false, 0, "")
	if err == nil {
		newWhitelist := []string{}
		for _, entry := range wl {
			if entry.RuleValue.Counter > 1 {
				newWhitelist = append(newWhitelist, fmt.Sprintf("%s:%d", entry.IP, entry.RuleValue.Counter))
			} else {
				newWhitelist = append(newWhitelist, entry.IP)
			}
		}
		cfg.Base.Whitelist = newWhitelist
	}

	// 2. List all blocked IPs / 列出所有封禁的 IP
	ips, _, err := ListBlockedIPs(m.lockList, false, 0, "")
	if err != nil {
		return err
	}

	// 3. Sync IP+Port rules from maps to config object / 从 Map 同步 IP+端口规则到配置对象
	ipPortRules, _, err := m.ListIPPortRules(false, 0, "")
	if err == nil {
		var newIPPortRules []types.IPPortRule

		// Helper to parse the map back to struct / 将 Map 解析回结构体的辅助函数
		processRules := func(rules map[string]string) {
			for key, actionStr := range rules {
				// Key is "IP/PrefixLen:Port" / 键格式为 "IP/PrefixLen:Port"
				lastColon := strings.LastIndex(key, ":")
				if lastColon != -1 {
					ipCIDR := key[:lastColon]
					portStr := key[lastColon+1:]
					port := uint16(0)
					fmt.Sscanf(portStr, "%d", &port)

					action := uint8(2) // deny
					if actionStr == "allow" {
						action = 1
					}

					newIPPortRules = append(newIPPortRules, types.IPPortRule{
						IP:     ipCIDR,
						Port:   port,
						Action: action,
					})
				}
			}
		}

		processRules(ipPortRules)
		cfg.Port.IPPortRules = newIPPortRules
	}

	// 4. Sync allowed ports from map to config object / 从 Map 同步允许端口到配置对象
	if ports, err := m.ListAllowedPorts(); err == nil {
		cfg.Port.AllowedPorts = ports
	}

	// 5. Sync rate limit rules from map to config object / 从 Map 同步速率限制规则到配置对象
	if rules, _, err := m.ListRateLimitRules(0, ""); err == nil {
		var newRateRules []types.RateLimitRule
		for target, conf := range rules {
			newRateRules = append(newRateRules, types.RateLimitRule{
				IP:    target,
				Rate:  conf.Rate,
				Burst: conf.Burst,
			})
		}
		cfg.RateLimit.Rules = newRateRules
	}

	// 6. Sync Global Config from map to config object / 从 Map 同步全局配置到配置对象
	if m.globalConfig != nil {
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
			cfg.Conntrack.TCPTimeout = time.Duration(val).String()
		}
	}

	// 7. Write lock_list to file / 将锁定列表写入文件
	file, err := os.Create(cfg.Base.LockListFile)
	if err != nil {
		return fmt.Errorf("failed to create lock list file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, entry := range ips {
		// Only write if it's a simple block (counter == 0) and not a dynamic rule (check expiresAt?)
		// Actually, lock_list contains static blocks. dyn_lock_list is separate.
		// So we just dump everything from lock_list.
		if _, err := writer.WriteString(entry.IP + "\n"); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	return nil
}

// ClearMaps clears all rules from blacklist and whitelist maps.
// ClearMaps 清除黑名单和白名单 Map 中的所有规则。
func (m *Manager) ClearMaps() {
	maps := []*ebpf.Map{m.lockList, m.whitelist, m.ipPortRules}
	for _, emap := range maps {
		if emap == nil {
			continue
		}
		var key []byte
		iter := emap.Iterate()
		for iter.Next(&key, nil) {
			emap.Delete(key)
		}
	}
	log.Printf("✅ All BPF maps cleared.")
}

// ClearMap clears all rules from a specific BPF map.
// ClearMap 清除特定 BPF Map 中的所有规则。
func ClearMap(mapPtr *ebpf.Map) (int, error) {
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
