package xdp

import (
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/pkg/sdk"
)

type MockManager struct {
	mu sync.RWMutex // Protects all maps from concurrent access / 保护所有 map 免受并发访问

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
	wl := make([]string, 0, len(m.WhitelistMap))
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
	m.mu.Lock()
	m.Blacklist[normalized] = true
	m.mu.Unlock()
	return nil
}
func (m *MockManager) AddBlacklistIPWithFile(cidr string, file string) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.mu.Lock()
	m.Blacklist[normalized] = true
	m.mu.Unlock()
	return nil
}
func (m *MockManager) AddDynamicBlacklistIP(cidr string, ttl time.Duration) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.mu.Lock()
	m.Blacklist[normalized] = true
	m.mu.Unlock()
	return nil
}
func (m *MockManager) RemoveBlacklistIP(cidr string) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.mu.Lock()
	delete(m.Blacklist, normalized)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) ClearBlacklist() error {
	m.mu.Lock()
	m.Blacklist = make(map[string]bool)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) IsIPInBlacklist(cidr string) (bool, error) {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.mu.RLock()
	_, ok := m.Blacklist[normalized]
	m.mu.RUnlock()
	return ok, nil
}
func (m *MockManager) ListBlacklistIPs(limit int, search string) ([]BlockedIP, int, error) {
	m.mu.RLock()
	ips := make([]BlockedIP, 0, len(m.Blacklist))
	for ip := range m.Blacklist {
		if search != "" && !strings.Contains(ip, search) {
			continue
		}
		ips = append(ips, BlockedIP{IP: ip})
	}
	m.mu.RUnlock()
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
	m.mu.Lock()
	m.WhitelistMap[normalized] = port
	m.mu.Unlock()
	return nil
}
func (m *MockManager) RemoveWhitelistIP(cidr string) error {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.mu.Lock()
	delete(m.WhitelistMap, normalized)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) ClearWhitelist() error {
	m.mu.Lock()
	m.WhitelistMap = make(map[string]uint16)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) IsIPInWhitelist(cidr string) (bool, error) {
	normalized := cidr
	if !strings.Contains(cidr, "/") {
		normalized = cidr + "/32"
	}
	m.mu.RLock()
	_, ok := m.WhitelistMap[normalized]
	m.mu.RUnlock()
	return ok, nil
}
func (m *MockManager) ListWhitelistIPs(limit int, search string) ([]string, int, error) {
	m.mu.RLock()
	ips := make([]string, 0, len(m.WhitelistMap))
	for ip, port := range m.WhitelistMap {
		if search != "" && !strings.Contains(ip, search) {
			continue
		}
		entry := ip
		_ = port // Port info not used in mock list format
		ips = append(ips, entry)
	}
	m.mu.RUnlock()
	return ips, len(ips), nil
}

// IP Port Rules Operations
func (m *MockManager) AddIPPortRule(cidr string, port uint16, action uint8) error {
	m.mu.Lock()
	m.IPPortRulesMap[cidr] = sdk.IPPortRule{IP: cidr, Port: port, Action: action}
	m.mu.Unlock()
	return nil
}
func (m *MockManager) RemoveIPPortRule(cidr string, port uint16) error {
	m.mu.Lock()
	delete(m.IPPortRulesMap, cidr)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) ClearIPPortRules() error {
	m.mu.Lock()
	m.IPPortRulesMap = make(map[string]sdk.IPPortRule)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) ListIPPortRules(isIPv6 bool, limit int, search string) ([]sdk.IPPortRule, int, error) {
	m.mu.RLock()
	rules := make([]sdk.IPPortRule, 0, len(m.IPPortRulesMap))
	for _, rule := range m.IPPortRulesMap {
		rules = append(rules, rule)
	}
	m.mu.RUnlock()
	return rules, len(rules), nil
}

// Allowed Ports Operations
func (m *MockManager) AllowPort(port uint16) error {
	m.mu.Lock()
	m.AllowedPortsMap[port] = true
	m.mu.Unlock()
	return nil
}
func (m *MockManager) RemoveAllowedPort(port uint16) error {
	m.mu.Lock()
	delete(m.AllowedPortsMap, port)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) ClearAllowedPorts() error {
	m.mu.Lock()
	m.AllowedPortsMap = make(map[uint16]bool)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) ListAllowedPorts() ([]uint16, error) {
	m.mu.RLock()
	ports := make([]uint16, 0, len(m.AllowedPortsMap))
	for port := range m.AllowedPortsMap {
		ports = append(ports, port)
	}
	m.mu.RUnlock()
	return ports, nil
}

// Rate Limit Operations
func (m *MockManager) AddRateLimitRule(cidr string, rate uint64, burst uint64) error {
	m.mu.Lock()
	m.RateLimitRules[cidr] = sdk.RateLimitConf{Rate: rate, Burst: burst}
	m.mu.Unlock()
	return nil
}
func (m *MockManager) RemoveRateLimitRule(cidr string) error {
	m.mu.Lock()
	delete(m.RateLimitRules, cidr)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) ClearRateLimitRules() error {
	m.mu.Lock()
	m.RateLimitRules = make(map[string]sdk.RateLimitConf)
	m.mu.Unlock()
	return nil
}
func (m *MockManager) ListRateLimitRules(limit int, search string) (map[string]sdk.RateLimitConf, int, error) {
	m.mu.RLock()
	rules := m.RateLimitRules
	count := len(m.RateLimitRules)
	m.mu.RUnlock()
	return rules, count, nil
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
func (m *MockManager) GetLockedIPCount() (int, error) {
	m.mu.RLock()
	count := len(m.Blacklist)
	m.mu.RUnlock()
	return count, nil
}
func (m *MockManager) GetWhitelistCount() (int, error) {
	m.mu.RLock()
	count := len(m.WhitelistMap)
	m.mu.RUnlock()
	return count, nil
}
func (m *MockManager) GetConntrackCount() (int, error)      { return 0, nil }
func (m *MockManager) GetDynLockListCount() (uint64, error) { return 0, nil }
func (m *MockManager) InvalidateStatsCache()                {}

// PerfStats returns a mock performance stats tracker.
// PerfStats 返回模拟的性能统计跟踪器。
func (m *MockManager) PerfStats() any {
	return NewPerformanceStats()
}

func (m *MockManager) Close() error { return nil }
