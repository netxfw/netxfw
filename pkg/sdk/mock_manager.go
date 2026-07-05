package sdk

import (
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// MockManager is a unified mock implementation of ManagerInterface for testing.
// MockManager 是用于测试的 ManagerInterface 统一 mock 实现。
// This should be used across all test files instead of creating local mocks.
// 应该在所有测试文件中使用此 mock，而不是创建本地 mock。
type MockManager struct {
	mu sync.RWMutex

	// Blacklist data
	// 黑名单数据
	blacklist map[string]*MockBlacklistEntry

	// Whitelist data
	// 白名单数据
	whitelist map[string]uint16

	// IP Port rules
	// IP 端口规则
	ipPortRules map[string]IPPortRule

	// Allowed ports
	// 允许的端口
	allowedPorts map[uint16]bool

	// Rate limit rules
	// 限速规则
	rateLimitRules map[string]RateLimitConf

	// Conntrack entries
	// 连接跟踪条目
	conntrackEntries []ConntrackEntry

	// Configuration state
	// 配置状态
	config MockConfig

	// Statistics
	// 统计信息
	dropCount uint64
	passCount uint64
}

// MockBlacklistEntry represents a blacklist entry with metadata.
// MockBlacklistEntry 表示带有元数据的黑名单条目。
type MockBlacklistEntry struct {
	Counter   uint64
	ExpiresAt uint64
	IsDynamic bool
}

// MockConfig holds configuration state for the mock manager.
// MockConfig 保存 mock 管理器的配置状态。
type MockConfig struct {
	DefaultDeny        bool
	EnableAFXDP        bool
	EnableRateLimit    bool
	DropFragments      bool
	StrictTCP          bool
	SYNLimit           bool
	BogonFilter        bool
	AutoBlock          bool
	AutoBlockExpiry    time.Duration
	Conntrack          bool
	ConntrackTimeout   time.Duration
	AllowReturnTraffic bool
	AllowICMP          bool
	StrictProtocol     bool
	ICMPRate           uint64
	ICMPBurst          uint64
}

// NewMockManager creates a new unified MockManager instance.
// NewMockManager 创建新的统一 MockManager 实例。
func NewMockManager() *MockManager {
	return &MockManager{
		blacklist:        make(map[string]*MockBlacklistEntry),
		whitelist:        make(map[string]uint16),
		ipPortRules:      make(map[string]IPPortRule),
		allowedPorts:     make(map[uint16]bool),
		rateLimitRules:   make(map[string]RateLimitConf),
		conntrackEntries: make([]ConntrackEntry, 0),
	}
}

// Sync Operations
// 同步操作

func (m *MockManager) SyncFromFiles(cfg *GlobalConfig, overwrite bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if overwrite {
		m.blacklist = make(map[string]*MockBlacklistEntry)
		m.whitelist = make(map[string]uint16)
		m.ipPortRules = make(map[string]IPPortRule)
		m.allowedPorts = make(map[uint16]bool)
		m.rateLimitRules = make(map[string]RateLimitConf)
	}

	for _, ip := range cfg.Base.Whitelist {
		m.whitelist[ip] = 0
	}
	for _, rule := range cfg.Port.IPPortRules {
		m.ipPortRules[makeIPPortRuleKey(rule.IP, rule.Port)] = rule
	}
	for _, port := range cfg.Port.AllowedPorts {
		m.allowedPorts[port] = true
	}
	for _, rule := range cfg.RateLimit.Rules {
		m.rateLimitRules[rule.IP] = RateLimitConf{Rate: rule.Rate, Burst: rule.Burst}
	}

	return nil
}

func (m *MockManager) SyncToFiles(cfg *GlobalConfig) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	wl := make([]string, 0, len(m.whitelist))
	for ip, port := range m.whitelist {
		if port > 0 {
			wl = append(wl, makeIPPortRuleKey(ip, port))
		} else {
			wl = append(wl, ip)
		}
	}
	sort.Strings(wl)
	cfg.Base.Whitelist = wl

	ports := make([]uint16, 0, len(m.allowedPorts))
	for port := range m.allowedPorts {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	cfg.Port.AllowedPorts = cloneAllowedPorts(ports)

	rules := make([]IPPortRule, 0, len(m.ipPortRules))
	for _, rule := range m.ipPortRules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].IP == rules[j].IP {
			return rules[i].Port < rules[j].Port
		}
		return rules[i].IP < rules[j].IP
	})
	cfg.Port.IPPortRules = cloneIPPortRules(rules)

	rateRules := make([]RateLimitRule, 0, len(m.rateLimitRules))
	for ip, conf := range m.rateLimitRules {
		rateRules = append(rateRules, RateLimitRule{IP: ip, Rate: conf.Rate, Burst: conf.Burst})
	}
	sort.Slice(rateRules, func(i, j int) bool { return rateRules[i].IP < rateRules[j].IP })
	cfg.RateLimit.Rules = append([]RateLimitRule(nil), rateRules...)

	return nil
}

func (m *MockManager) VerifyAndRepair(cfg *GlobalConfig) error {
	return m.SyncFromFiles(cfg, true)
}

// Map Getters (return nil for mock)
// Map 获取器（mock 返回 nil）

func (m *MockManager) StaticBlacklist() *ebpf.Map  { return nil }
func (m *MockManager) DynamicBlacklist() *ebpf.Map { return nil }
func (m *MockManager) Whitelist() *ebpf.Map        { return nil }
func (m *MockManager) RuleMap() *ebpf.Map          { return nil }
func (m *MockManager) RatelimitMap() *ebpf.Map     { return nil }
func (m *MockManager) GlobalConfig() *ebpf.Map     { return nil }
func (m *MockManager) ConntrackMap() *ebpf.Map    { return nil }

// Configuration methods
// 配置方法

func (m *MockManager) SetDefaultDeny(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.DefaultDeny = enable
	return nil
}

func (m *MockManager) SetStrictTCP(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.StrictTCP = enable
	return nil
}

func (m *MockManager) SetSYNLimit(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.SYNLimit = enable
	return nil
}

func (m *MockManager) SetBogonFilter(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.BogonFilter = enable
	return nil
}

func (m *MockManager) SetEnableAFXDP(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.EnableAFXDP = enable
	return nil
}

func (m *MockManager) SetEnableRateLimit(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.EnableRateLimit = enable
	return nil
}

func (m *MockManager) SetDropFragments(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.DropFragments = enable
	return nil
}

func (m *MockManager) SetAutoBlock(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.AutoBlock = enable
	return nil
}

func (m *MockManager) SetAutoBlockExpiry(duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.AutoBlockExpiry = duration
	return nil
}

func (m *MockManager) SetConntrack(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.Conntrack = enable
	return nil
}

func (m *MockManager) SetConntrackTimeout(timeout time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.ConntrackTimeout = timeout
	return nil
}

func (m *MockManager) SetAllowReturnTraffic(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.AllowReturnTraffic = enable
	return nil
}

func (m *MockManager) SetAllowICMP(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.AllowICMP = enable
	return nil
}

func (m *MockManager) SetStrictProtocol(enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.StrictProtocol = enable
	return nil
}

func (m *MockManager) SetICMPRateLimit(rate, burst uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.ICMPRate = rate
	m.config.ICMPBurst = burst
	return nil
}

// Blacklist Operations
// 黑名单操作

func (m *MockManager) AddBlacklistIP(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blacklist[cidr] = &MockBlacklistEntry{Counter: 0, IsDynamic: false}
	return nil
}

func (m *MockManager) AddBlacklistIPWithFile(cidr string, file string) error {
	return m.AddBlacklistIP(cidr)
}

func (m *MockManager) AddDynamicBlacklistIP(cidr string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blacklist[cidr] = &MockBlacklistEntry{
		Counter:   0,
		ExpiresAt: uint64(time.Now().Add(ttl).Unix()), // #nosec G115 // timestamp is always valid
		IsDynamic: true,
	}
	return nil
}

func (m *MockManager) RemoveBlacklistIP(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blacklist, cidr)
	return nil
}

func (m *MockManager) RemoveDynamicBlacklistIP(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, exists := m.blacklist[cidr]; exists && entry.IsDynamic {
		delete(m.blacklist, cidr)
	}
	return nil
}

func (m *MockManager) ClearBlacklist() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blacklist = make(map[string]*MockBlacklistEntry)
	return nil
}

func (m *MockManager) IsIPInBlacklist(cidr string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.blacklist[cidr]
	return exists, nil
}

func (m *MockManager) ListBlacklistIPs(limit int, search string) ([]BlockedIP, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]BlockedIP, 0, len(m.blacklist))
	for ip, entry := range m.blacklist {
		if entry.IsDynamic || !matchSearch(ip, search) {
			continue
		}
		result = append(result, BlockedIP{IP: ip, Counter: entry.Counter, ExpiresAt: entry.ExpiresAt})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IP < result[j].IP })
	total := len(result)
	return cloneBlockedIPs(applyLimit(result, limit)), total, nil
}

func (m *MockManager) ListDynamicBlacklistIPs(limit int, search string) ([]BlockedIP, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]BlockedIP, 0, len(m.blacklist))
	for ip, entry := range m.blacklist {
		if !entry.IsDynamic || !matchSearch(ip, search) {
			continue
		}
		result = append(result, BlockedIP{IP: ip, Counter: entry.Counter, ExpiresAt: entry.ExpiresAt})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IP < result[j].IP })
	total := len(result)
	return cloneBlockedIPs(applyLimit(result, limit)), total, nil
}

// Whitelist Operations
// 白名单操作

func (m *MockManager) AddWhitelistIP(cidr string, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.whitelist[cidr] = port
	return nil
}

func (m *MockManager) RemoveWhitelistIP(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.whitelist, cidr)
	return nil
}

func (m *MockManager) ClearWhitelist() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.whitelist = make(map[string]uint16)
	return nil
}

func (m *MockManager) IsIPInWhitelist(cidr string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.whitelist[cidr]
	return exists, nil
}

func (m *MockManager) ListWhitelistIPs(limit int, search string) ([]string, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0, len(m.whitelist))
	for ip, port := range m.whitelist {
		entry := ip
		if port > 0 {
			entry = makeIPPortRuleKey(ip, port)
		}
		if matchSearch(entry, search) {
			result = append(result, entry)
		}
	}
	sort.Strings(result)
	total := len(result)
	return cloneWhitelistEntries(applyLimit(result, limit)), total, nil
}

// IP Port Rules Operations
// IP 端口规则操作

func (m *MockManager) AddIPPortRule(cidr string, port uint16, action uint8) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := makeIPPortRuleKey(cidr, port)
	m.ipPortRules[key] = IPPortRule{IP: cidr, Port: port, Action: action}
	return nil
}

func (m *MockManager) RemoveIPPortRule(cidr string, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := makeIPPortRuleKey(cidr, port)
	delete(m.ipPortRules, key)
	return nil
}

func (m *MockManager) ClearIPPortRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipPortRules = make(map[string]IPPortRule)
	return nil
}

func (m *MockManager) ListIPPortRules(isIPv6 bool, limit int, search string) ([]IPPortRule, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]IPPortRule, 0, len(m.ipPortRules))
	for _, rule := range m.ipPortRules {
		if !matchSearch(makeIPPortRuleKey(rule.IP, rule.Port), search) {
			continue
		}
		result = append(result, rule)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IP == result[j].IP {
			return result[i].Port < result[j].Port
		}
		return result[i].IP < result[j].IP
	})
	total := len(result)
	return cloneIPPortRules(applyLimit(result, limit)), total, nil
}

// Allowed Ports Operations
// 允许端口操作

func (m *MockManager) AllowPort(port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowedPorts[port] = true
	return nil
}

func (m *MockManager) RemoveAllowedPort(port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.allowedPorts, port)
	return nil
}

func (m *MockManager) ClearAllowedPorts() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowedPorts = make(map[uint16]bool)
	return nil
}

func (m *MockManager) ListAllowedPorts() ([]uint16, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]uint16, 0, len(m.allowedPorts))
	for port := range m.allowedPorts {
		result = append(result, port)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return cloneAllowedPorts(result), nil
}

// Rate Limit Operations
// 限速操作

func (m *MockManager) AddRateLimitRule(cidr string, rate uint64, burst uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rateLimitRules[cidr] = RateLimitConf{Rate: rate, Burst: burst}
	return nil
}

func (m *MockManager) RemoveRateLimitRule(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rateLimitRules, cidr)
	return nil
}

func (m *MockManager) ClearRateLimitRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rateLimitRules = make(map[string]RateLimitConf)
	return nil
}

func (m *MockManager) ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filtered := make(map[string]RateLimitConf)
	keys := make([]string, 0, len(m.rateLimitRules))
	for ip := range m.rateLimitRules {
		if matchSearch(ip, search) {
			keys = append(keys, ip)
		}
	}
	sort.Strings(keys)
	total := len(keys)
	for _, ip := range applyLimit(keys, limit) {
		filtered[ip] = m.rateLimitRules[ip]
	}
	return cloneRateLimitRules(filtered), total, nil
}

// Conntrack Operations
// 连接跟踪操作

func (m *MockManager) ListAllConntrackEntries() ([]ConntrackEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneConntrackEntries(m.conntrackEntries), nil
}

// Stats Operations
// 统计操作

func (m *MockManager) GetDropDetails() ([]DropDetailEntry, error) {
	return []DropDetailEntry{}, nil
}

func (m *MockManager) GetPassDetails() ([]DropDetailEntry, error) {
	return []DropDetailEntry{}, nil
}

func (m *MockManager) GetDropCount() (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dropCount, nil
}

func (m *MockManager) GetPassCount() (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.passCount, nil
}

func (m *MockManager) GetLockedIPCount() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.blacklist), nil
}

func (m *MockManager) GetWhitelistCount() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.whitelist), nil
}

func (m *MockManager) GetConntrackCount() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.conntrackEntries), nil
}

// GetDynLockListCount returns the count of dynamic blacklist entries.
// GetDynLockListCount 返回动态黑名单条目数量。
func (m *MockManager) GetDynLockListCount() (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var count uint64
	for _, entry := range m.blacklist {
		if entry.IsDynamic {
			count++
		}
	}
	return count, nil
}

// GetGlobalStats returns global statistics.
// GetGlobalStats 返回全局统计信息。
func (m *MockManager) GetGlobalStats() (*GlobalStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &GlobalStats{
		TotalDrop: m.dropCount,
		TotalPass: m.passCount,
	}, nil
}

// InvalidateStatsCache invalidates the stats cache.
// InvalidateStatsCache 使统计缓存失效。
func (m *MockManager) InvalidateStatsCache() {
	// No-op for mock
	// mock 中无操作
}

// PerfStats returns performance statistics.
// PerfStats 返回性能统计。
func (m *MockManager) PerfStats() any {
	return nil
}

// Close closes the manager.
// Close 关闭管理器。
func (m *MockManager) Close() error {
	return nil
}

// AddConntrackEntry adds a conntrack entry for testing.
// AddConntrackEntry 添加用于测试的连接跟踪条目。
func (m *MockManager) AddConntrackEntry(entry ConntrackEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conntrackEntries = append(m.conntrackEntries, entry)
}

// SetDropCount sets the drop count for testing.
// SetDropCount 设置用于测试的丢弃计数。
func (m *MockManager) SetDropCount(count uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropCount = count
}

// SetPassCount sets the pass count for testing.
// SetPassCount 设置用于测试的通过计数。
func (m *MockManager) SetPassCount(count uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.passCount = count
}

// GetConfig returns the current configuration state.
// GetConfig 返回当前配置状态。
func (m *MockManager) GetConfig() MockConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}
