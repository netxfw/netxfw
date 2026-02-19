package xdp

import (
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/pkg/sdk"
)

type MockManager struct {
	Blacklist       map[string]bool
	WhitelistMap    map[string]uint16
	IPPortRulesMap  map[string]IPPortRule
	AllowedPortsMap map[uint16]bool
	RateLimitRules  map[string]RateLimitConf

	// Configs
	DefaultDeny     bool
	StrictTCP       bool
	SYNLimit        bool
	BogonFilter     bool
	EnableAFXDP     bool
	EnableRateLimit bool
	DropFragments   bool
}

// MockConfigSnapshot represents a snapshot of the mock configuration state.
// MockConfigSnapshot 表示 mock 配置状态的快照。
type MockConfigSnapshot struct {
	DefaultDeny     bool
	StrictTCP       bool
	SYNLimit        bool
	BogonFilter     bool
	EnableAFXDP     bool
	EnableRateLimit bool
	DropFragments   bool
}

// GetConfigSnapshot returns a snapshot of the current configuration state.
// GetConfigSnapshot 返回当前配置状态的快照。
func (m *MockManager) GetConfigSnapshot() MockConfigSnapshot {
	return MockConfigSnapshot{
		DefaultDeny:     m.DefaultDeny,
		StrictTCP:       m.StrictTCP,
		SYNLimit:        m.SYNLimit,
		BogonFilter:     m.BogonFilter,
		EnableAFXDP:     m.EnableAFXDP,
		EnableRateLimit: m.EnableRateLimit,
		DropFragments:   m.DropFragments,
	}
}

// Sync Operations
func (m *MockManager) SyncFromFiles(cfg *types.GlobalConfig, overwrite bool) error {
	if overwrite {
		_ = m.ClearBlacklist()
		_ = m.ClearWhitelist()
		_ = m.ClearIPPortRules()
		_ = m.ClearAllowedPorts()
		_ = m.ClearRateLimitRules()
	}

	// Sync Whitelist from config
	for _, rule := range cfg.Base.Whitelist {
		normalized := rule
		if strings.Contains(rule, ":") {
			parts := strings.Split(rule, ":")
			if len(parts) == 2 {
				normalized = parts[0]
			}
		}
		normalized = iputil.NormalizeCIDR(normalized)
		m.WhitelistMap[normalized] = 0
	}
	return nil
}

func (m *MockManager) VerifyAndRepair(cfg *types.GlobalConfig) error {
	return m.SyncFromFiles(cfg, true)
}

func (m *MockManager) SyncToFiles(cfg *types.GlobalConfig) error {
	// Sync Whitelist to config
	var wl []string
	for ip := range m.WhitelistMap {
		wl = append(wl, ip)
	}
	cfg.Base.Whitelist = wl
	return nil
}

func NewMockManager() *MockManager {
	return &MockManager{
		Blacklist:       make(map[string]bool),
		WhitelistMap:    make(map[string]uint16),
		IPPortRulesMap:  make(map[string]IPPortRule),
		AllowedPortsMap: make(map[uint16]bool),
		RateLimitRules:  make(map[string]RateLimitConf),
	}
}

// Map Getters (Return nil for mock)
func (m *MockManager) LockList() *ebpf.Map        { return nil }
func (m *MockManager) DynLockList() *ebpf.Map     { return nil }
func (m *MockManager) Whitelist() *ebpf.Map       { return nil }
func (m *MockManager) IPPortRules() *ebpf.Map     { return nil }
func (m *MockManager) AllowedPorts() *ebpf.Map    { return nil }
func (m *MockManager) RateLimitConfig() *ebpf.Map { return nil }
func (m *MockManager) GlobalConfig() *ebpf.Map    { return nil }
func (m *MockManager) ConntrackMap() *ebpf.Map    { return nil }

// Configuration
func (m *MockManager) SetDefaultDeny(enable bool) error {
	m.DefaultDeny = enable
	return nil
}
func (m *MockManager) SetStrictTCP(enable bool) error {
	m.StrictTCP = enable
	return nil
}
func (m *MockManager) SetSYNLimit(enable bool) error {
	m.SYNLimit = enable
	return nil
}
func (m *MockManager) SetBogonFilter(enable bool) error {
	m.BogonFilter = enable
	return nil
}
func (m *MockManager) SetEnableAFXDP(enable bool) error {
	m.EnableAFXDP = enable
	return nil
}
func (m *MockManager) SetEnableRateLimit(enable bool) error {
	m.EnableRateLimit = enable
	return nil
}
func (m *MockManager) SetDropFragments(enable bool) error {
	m.DropFragments = enable
	return nil
}

func (m *MockManager) SetAutoBlock(enable bool) error {
	m.EnableRateLimit = enable // Mock implementation uses this for simplicity or add a new field
	return nil
}
func (m *MockManager) SetAutoBlockExpiry(duration time.Duration) error {
	return nil
}
func (m *MockManager) SetConntrack(enable bool) error                  { return nil }
func (m *MockManager) SetConntrackTimeout(timeout time.Duration) error { return nil }
func (m *MockManager) SetAllowReturnTraffic(enable bool) error         { return nil }
func (m *MockManager) SetAllowICMP(enable bool) error                  { return nil }
func (m *MockManager) SetStrictProtocol(enable bool) error             { return nil }
func (m *MockManager) SetICMPRateLimit(rate, burst uint64) error       { return nil }

// Blacklist Operations
func (m *MockManager) AddBlacklistIP(cidr string) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.Blacklist[normalized] = true
	return nil
}
func (m *MockManager) AddBlacklistIPWithFile(cidr string, file string) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.Blacklist[normalized] = true
	return nil
}
func (m *MockManager) AddDynamicBlacklistIP(cidr string, ttl time.Duration) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.Blacklist[normalized] = true
	return nil
}
func (m *MockManager) RemoveBlacklistIP(cidr string) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	delete(m.Blacklist, normalized)
	return nil
}
func (m *MockManager) ClearBlacklist() error {
	m.Blacklist = make(map[string]bool)
	return nil
}
func (m *MockManager) IsIPInBlacklist(cidr string) (bool, error) {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	_, ok := m.Blacklist[normalized]
	return ok, nil
}
func (m *MockManager) ListBlacklistIPs(limit int, search string) ([]BlockedIP, int, error) {
	var ips []BlockedIP
	for ip := range m.Blacklist {
		if search != "" && !strings.Contains(ip, search) {
			continue
		}
		ips = append(ips, BlockedIP{IP: ip})
	}
	return ips, len(ips), nil
}
func (m *MockManager) ListDynamicBlacklistIPs(limit int, search string) ([]BlockedIP, int, error) {
	return nil, 0, nil
}

// Whitelist Operations
func (m *MockManager) AddWhitelistIP(cidr string, port uint16) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.WhitelistMap[normalized] = port
	return nil
}
func (m *MockManager) RemoveWhitelistIP(cidr string) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	delete(m.WhitelistMap, normalized)
	return nil
}
func (m *MockManager) ClearWhitelist() error {
	m.WhitelistMap = make(map[string]uint16)
	return nil
}
func (m *MockManager) IsIPInWhitelist(cidr string) (bool, error) {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	_, ok := m.WhitelistMap[normalized]
	return ok, nil
}
func (m *MockManager) ListWhitelistIPs(limit int, search string) ([]string, int, error) {
	var ips []string
	for ip, port := range m.WhitelistMap {
		if search != "" && !strings.Contains(ip, search) {
			continue
		}
		entry := ip
		if port > 0 {
			// Mock format
		}
		ips = append(ips, entry)
	}
	return ips, len(ips), nil
}

// IP Port Rules Operations
func (m *MockManager) AddIPPortRule(cidr string, port uint16, action uint8) error {
	// key := cidr + "/32" // simplified - REMOVED this assumption
	m.IPPortRulesMap[cidr] = sdk.IPPortRule{IP: cidr, Port: port, Action: action}
	return nil
}
func (m *MockManager) RemoveIPPortRule(cidr string, port uint16) error {
	delete(m.IPPortRulesMap, cidr)
	return nil
}
func (m *MockManager) ClearIPPortRules() error {
	m.IPPortRulesMap = make(map[string]sdk.IPPortRule)
	return nil
}
func (m *MockManager) ListIPPortRules(isIPv6 bool, limit int, search string) ([]sdk.IPPortRule, int, error) {
	var rules []sdk.IPPortRule
	for _, rule := range m.IPPortRulesMap {
		rules = append(rules, rule)
	}
	return rules, len(rules), nil
}

// Allowed Ports Operations
func (m *MockManager) AllowPort(port uint16) error {
	m.AllowedPortsMap[port] = true
	return nil
}
func (m *MockManager) RemoveAllowedPort(port uint16) error {
	delete(m.AllowedPortsMap, port)
	return nil
}
func (m *MockManager) ClearAllowedPorts() error {
	m.AllowedPortsMap = make(map[uint16]bool)
	return nil
}
func (m *MockManager) ListAllowedPorts() ([]uint16, error) {
	var ports []uint16
	for port := range m.AllowedPortsMap {
		ports = append(ports, port)
	}
	return ports, nil
}

// Rate Limit Operations
func (m *MockManager) AddRateLimitRule(cidr string, rate uint64, burst uint64) error {
	m.RateLimitRules[cidr] = sdk.RateLimitConf{Rate: rate, Burst: burst}
	return nil
}
func (m *MockManager) RemoveRateLimitRule(cidr string) error {
	delete(m.RateLimitRules, cidr)
	return nil
}
func (m *MockManager) ClearRateLimitRules() error {
	m.RateLimitRules = make(map[string]sdk.RateLimitConf)
	return nil
}
func (m *MockManager) ListRateLimitRules(limit int, search string) (map[string]sdk.RateLimitConf, int, error) {
	return m.RateLimitRules, len(m.RateLimitRules), nil
}

// Conntrack Operations
func (m *MockManager) ListAllConntrackEntries() ([]ConntrackEntry, error) {
	return nil, nil
}

// Stats
func (m *MockManager) GetDropDetails() ([]DropDetailEntry, error) { return nil, nil }
func (m *MockManager) GetPassDetails() ([]DropDetailEntry, error) { return nil, nil }
func (m *MockManager) GetDropCount() (uint64, error)              { return 0, nil }
func (m *MockManager) GetPassCount() (uint64, error)              { return 0, nil }
func (m *MockManager) GetLockedIPCount() (int, error)             { return len(m.Blacklist), nil }
func (m *MockManager) GetWhitelistCount() (int, error)            { return len(m.WhitelistMap), nil }
func (m *MockManager) GetConntrackCount() (int, error)            { return 0, nil }
func (m *MockManager) GetDynLockListCount() (uint64, error)       { return 0, nil }
func (m *MockManager) InvalidateStatsCache()                      {}

// PerfStats returns a mock performance stats tracker.
// PerfStats 返回模拟的性能统计跟踪器。
func (m *MockManager) PerfStats() any {
	return NewPerformanceStats()
}

func (m *MockManager) Close() error { return nil }
