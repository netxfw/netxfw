package xdp

import (
	"strings"
	"time"

	"github.com/cilium/ebpf"
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

func (m *MockManager) SetAutoBlock(enable bool) error                  { return nil }
func (m *MockManager) SetAutoBlockExpiry(duration time.Duration) error { return nil }
func (m *MockManager) SetConntrack(enable bool) error                  { return nil }
func (m *MockManager) SetConntrackTimeout(timeout time.Duration) error { return nil }
func (m *MockManager) SetAllowReturnTraffic(enable bool) error         { return nil }
func (m *MockManager) SetAllowICMP(enable bool) error                  { return nil }
func (m *MockManager) SetStrictProtocol(enable bool) error             { return nil }
func (m *MockManager) SetICMPRateLimit(rate, burst uint64) error       { return nil }

// Blacklist Operations
func (m *MockManager) AddBlacklistIP(cidr string) error {
	m.Blacklist[cidr] = true
	return nil
}
func (m *MockManager) AddBlacklistIPWithFile(cidr string, file string) error {
	m.Blacklist[cidr] = true
	return nil
}
func (m *MockManager) AddDynamicBlacklistIP(cidr string, ttl time.Duration) error {
	m.Blacklist[cidr] = true
	return nil
}
func (m *MockManager) RemoveBlacklistIP(cidr string) error {
	delete(m.Blacklist, cidr)
	return nil
}
func (m *MockManager) ClearBlacklist() error {
	m.Blacklist = make(map[string]bool)
	return nil
}
func (m *MockManager) IsIPInBlacklist(cidr string) (bool, error) {
	_, ok := m.Blacklist[cidr]
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
	m.WhitelistMap[cidr] = port
	return nil
}
func (m *MockManager) RemoveWhitelistIP(cidr string) error {
	delete(m.WhitelistMap, cidr)
	return nil
}
func (m *MockManager) ClearWhitelist() error {
	m.WhitelistMap = make(map[string]uint16)
	return nil
}
func (m *MockManager) IsIPInWhitelist(cidr string) (bool, error) {
	_, ok := m.WhitelistMap[cidr]
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
	key := cidr // Simplified key
	m.IPPortRulesMap[key] = IPPortRule{IP: cidr, Port: port, Action: action}
	return nil
}
func (m *MockManager) RemoveIPPortRule(cidr string, port uint16) error {
	delete(m.IPPortRulesMap, cidr)
	return nil
}
func (m *MockManager) ClearIPPortRules() error {
	m.IPPortRulesMap = make(map[string]IPPortRule)
	return nil
}
func (m *MockManager) ListIPPortRules(isIPv6 bool, limit int, search string) ([]IPPortRule, int, error) {
	var rules []IPPortRule
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
	m.RateLimitRules[cidr] = RateLimitConf{Rate: rate, Burst: burst}
	return nil
}
func (m *MockManager) RemoveRateLimitRule(cidr string) error {
	delete(m.RateLimitRules, cidr)
	return nil
}
func (m *MockManager) ClearRateLimitRules() error {
	m.RateLimitRules = make(map[string]RateLimitConf)
	return nil
}
func (m *MockManager) ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error) {
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

func (m *MockManager) Close() error { return nil }
