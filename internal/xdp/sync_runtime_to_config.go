package xdp

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/ipmerge"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// SyncToFiles dumps current BPF map rules back to text files.
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
func (m *Manager) syncWhitelistToConfig(cfg *types.GlobalConfig) {
	if m.whitelist == nil {
		cfg.Base.Whitelist = nil
		return
	}

	groupedByPort := make(map[uint16][]string)
	iter := m.whitelist.Iterate()
	var key NetXfwLpmKey
	var val NetXfwRuleValue
	for iter.Next(&key, &val) {
		port := uint16(0)
		if val.Counter > 1 && val.Counter <= uint64(^uint16(0)) {
			port = uint16(val.Counter)
		}
		groupedByPort[port] = append(groupedByPort[port], FormatLpmKey(&key))
	}
	if err := iter.Err(); err != nil {
		return
	}

	mergedByPort := make(map[uint16][]string, len(groupedByPort))
	ports := make([]int, 0, len(groupedByPort))
	for port, cidrs := range groupedByPort {
		merged, err := ipmerge.MergeCIDRs(cidrs)
		if err != nil {
			merged = cidrs
		}
		sort.Strings(merged)
		mergedByPort[port] = merged
		ports = append(ports, int(port))
	}

	if err := m.replaceWhitelistCIDRsByPort(mergedByPort); err != nil {
		m.logger.Warnf("[WARN]  Failed to optimize whitelist map during sync: %v", err)
	}

	sort.Ints(ports)
	newWhitelist := make([]string, 0)
	for _, p := range ports {
		port := uint16(p)
		for _, cidr := range mergedByPort[port] {
			if port > 0 {
				newWhitelist = append(newWhitelist, fmt.Sprintf("%s:%d", cidr, port))
			} else {
				newWhitelist = append(newWhitelist, cidr)
			}
		}
	}
	cfg.Base.Whitelist = newWhitelist
}

func (m *Manager) replaceWhitelistCIDRsByPort(grouped map[uint16][]string) error {
	var keys []NetXfwLpmKey
	iter := m.whitelist.Iterate()
	var key NetXfwLpmKey
	var val NetXfwRuleValue
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}

	for i := range keys {
		if err := m.whitelist.Delete(&keys[i]); err != nil && !strings.Contains(err.Error(), "key does not exist") {
			return err
		}
	}

	ports := make([]int, 0, len(grouped))
	for port := range grouped {
		ports = append(ports, int(port))
	}
	sort.Ints(ports)

	for _, p := range ports {
		port := uint16(p)
		for _, cidr := range grouped[port] {
			if err := AllowIP(m.whitelist, cidr, port); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) syncBlacklistToConfig(cfg *types.GlobalConfig) ([]sdk.BlockedIP, error) {
	ips, _, err := ListBlockedIPs(m.staticBlacklist, false, 0, "")
	return ips, err
}

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

		action := uint8(0)
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

func (m *Manager) syncAllowedPortsToConfig(cfg *types.GlobalConfig) {
	ports, err := m.ListAllowedPorts()
	if err != nil {
		return
	}
	cfg.Port.AllowedPorts = ports
}

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
		cfg.Conntrack.TCPTimeout = time.Duration(val).String()
	}
}

func (m *Manager) writeLockListFile(cfg *types.GlobalConfig, ips []sdk.BlockedIP) error {
	var buf bytes.Buffer
	for _, entry := range ips {
		buf.WriteString(entry.IP + "\n")
	}
	return fileutil.AtomicWriteFile(cfg.Base.LockListFile, buf.Bytes(), 0644)
}
