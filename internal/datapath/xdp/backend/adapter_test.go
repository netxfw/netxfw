package xdp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewMockManager tests NewMockManager function
// TestNewMockManager 测试 NewMockManager 函数
func TestNewMockManager(t *testing.T) {
	mockMgr := NewMockManager()

	assert.NotNil(t, mockMgr)
	assert.NotNil(t, mockMgr.Blacklist)
	assert.NotNil(t, mockMgr.WhitelistMap)
	assert.NotNil(t, mockMgr.IPPortRulesMap)
	assert.NotNil(t, mockMgr.AllowedPortsMap)
	assert.NotNil(t, mockMgr.RateLimitRules)
}

// TestMockManager_SyncOperations tests sync operations
// TestMockManager_SyncOperations 测试同步操作
func TestMockManager_SyncOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Verify that the mock manager was created successfully
	// 验证模拟管理器已成功创建
	assert.NotNil(t, mockMgr)
}

// TestMockManager_ConfigurationMethods tests all configuration methods
// TestMockManager_ConfigurationMethods 测试所有配置方法
func TestMockManager_ConfigurationMethods(t *testing.T) {
	mockMgr := NewMockManager()

	// Test SetDefaultDeny
	// 测试 SetDefaultDeny
	err := mockMgr.SetDefaultDeny(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DefaultDeny)

	// Test SetStrictTCP
	// 测试 SetStrictTCP
	err = mockMgr.SetStrictTCP(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.StrictTCP)

	// Test SetSYNLimit
	// 测试 SetSYNLimit
	err = mockMgr.SetSYNLimit(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.SYNLimit)

	// Test SetBogonFilter
	// 测试 SetBogonFilter
	err = mockMgr.SetBogonFilter(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.BogonFilter)

	// Test SetEnableAFXDP
	// 测试 SetEnableAFXDP
	err = mockMgr.SetEnableAFXDP(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableAFXDP)

	// Test SetEnableRateLimit
	// 测试 SetEnableRateLimit
	err = mockMgr.SetEnableRateLimit(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableRateLimit)

	// Test SetDropFragments
	// 测试 SetDropFragments
	err = mockMgr.SetDropFragments(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DropFragments)

	// Test SetAutoBlock
	// 测试 SetAutoBlock
	err = mockMgr.SetAutoBlock(true)
	assert.NoError(t, err)

	// Test SetAutoBlockExpiry
	// 测试 SetAutoBlockExpiry
	err = mockMgr.SetAutoBlockExpiry(time.Hour)
	assert.NoError(t, err)

	// Test SetConntrack
	// 测试 SetConntrack
	err = mockMgr.SetConntrack(true)
	assert.NoError(t, err)

	// Test SetConntrackTimeout
	// 测试 SetConntrackTimeout
	err = mockMgr.SetConntrackTimeout(time.Minute * 30)
	assert.NoError(t, err)

	// Test SetAllowReturnTraffic
	// 测试 SetAllowReturnTraffic
	err = mockMgr.SetAllowReturnTraffic(true)
	assert.NoError(t, err)

	// Test SetAllowICMP
	// 测试 SetAllowICMP
	err = mockMgr.SetAllowICMP(true)
	assert.NoError(t, err)

	// Test SetStrictProtocol
	// 测试 SetStrictProtocol
	err = mockMgr.SetStrictProtocol(true)
	assert.NoError(t, err)

	// Test SetICMPRateLimit
	// 测试 SetICMPRateLimit
	err = mockMgr.SetICMPRateLimit(100, 200)
	assert.NoError(t, err)
}

// TestMockManager_BlacklistOperations tests blacklist operations
// TestMockManager_BlacklistOperations 测试黑名单操作
func TestMockManager_BlacklistOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddBlacklistIP
	// 测试 AddBlacklistIP
	err := mockMgr.AddBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	// Test IsIPInBlacklist
	// 测试 IsIPInBlacklist
	contains, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)

	// Test ListBlacklistIPs
	// 测试 ListBlacklistIPs
	ips, count, err := mockMgr.ListBlacklistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, ips, 1)

	// Test RemoveBlacklistIP
	// 测试 RemoveBlacklistIP
	err = mockMgr.RemoveBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	contains, err = mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.False(t, contains)

	// Test ClearBlacklist
	// 测试 ClearBlacklist
	err = mockMgr.AddBlacklistIP("192.168.1.2/32")
	assert.NoError(t, err)
	err = mockMgr.AddBlacklistIP("192.168.1.3/32")
	assert.NoError(t, err)

	err = mockMgr.ClearBlacklist()
	assert.NoError(t, err)

	ips, count, err = mockMgr.ListBlacklistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, ips)
}

// TestMockManager_BlacklistIP_NoCIDR tests blacklist with IP without CIDR notation
// TestMockManager_BlacklistIP_NoCIDR 测试黑名单使用不带 CIDR 表示法的 IP
func TestMockManager_BlacklistIP_NoCIDR(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddBlacklistIP without CIDR
	// 测试 AddBlacklistIP 不带 CIDR
	err := mockMgr.AddBlacklistIP("192.168.1.1")
	assert.NoError(t, err)

	// Should be normalized to /32
	// 应该规范化为 /32
	contains, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)

	// Test IsIPInBlacklist without CIDR
	// 测试 IsIPInBlacklist 不带 CIDR
	contains, err = mockMgr.IsIPInBlacklist("192.168.1.1")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestMockManager_DynamicBlacklistOperations tests dynamic blacklist operations
// TestMockManager_DynamicBlacklistOperations 测试动态黑名单操作
func TestMockManager_DynamicBlacklistOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddDynamicBlacklistIP
	// 测试 AddDynamicBlacklistIP
	err := mockMgr.AddDynamicBlacklistIP("192.168.1.1/32", time.Hour)
	assert.NoError(t, err)

	// Test ListDynamicBlacklistIPs
	// 测试 ListDynamicBlacklistIPs
	ips, count, err := mockMgr.ListDynamicBlacklistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, ips)
}

// TestMockManager_WhitelistOperations tests whitelist operations
// TestMockManager_WhitelistOperations 测试白名单操作
func TestMockManager_WhitelistOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddWhitelistIP
	// 测试 AddWhitelistIP
	err := mockMgr.AddWhitelistIP("10.0.0.1/32", 80)
	assert.NoError(t, err)

	// Test IsIPInWhitelist
	// 测试 IsIPInWhitelist
	contains, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)

	// Test ListWhitelistIPs
	// 测试 ListWhitelistIPs
	ips, count, err := mockMgr.ListWhitelistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, ips, 1)

	// Test RemoveWhitelistIP
	// 测试 RemoveWhitelistIP
	err = mockMgr.RemoveWhitelistIP("10.0.0.1/32")
	assert.NoError(t, err)

	contains, err = mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.False(t, contains)

	// Test ClearWhitelist
	// 测试 ClearWhitelist
	err = mockMgr.AddWhitelistIP("10.0.0.2/32", 443)
	assert.NoError(t, err)

	err = mockMgr.ClearWhitelist()
	assert.NoError(t, err)

	ips, count, err = mockMgr.ListWhitelistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, ips)
}

// TestMockManager_WhitelistIP_NoCIDR tests whitelist with IP without CIDR notation
// TestMockManager_WhitelistIP_NoCIDR 测试白名单使用不带 CIDR 表示法的 IP
func TestMockManager_WhitelistIP_NoCIDR(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddWhitelistIP without CIDR
	// 测试 AddWhitelistIP 不带 CIDR
	err := mockMgr.AddWhitelistIP("10.0.0.1", 80)
	assert.NoError(t, err)

	// Should be normalized to /32
	// 应该规范化为 /32
	contains, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestMockManager_IPPortRuleOperations tests IP port rule operations
// TestMockManager_IPPortRuleOperations 测试 IP 端口规则操作
func TestMockManager_IPPortRuleOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddIPPortRule
	// 测试 AddIPPortRule
	err := mockMgr.AddIPPortRule("172.16.0.1/32", 8080, 1)
	assert.NoError(t, err)

	// Test ListIPPortRules
	// 测试 ListIPPortRules
	rules, count, err := mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, rules, 1)

	// Test RemoveIPPortRule
	// 测试 RemoveIPPortRule
	err = mockMgr.RemoveIPPortRule("172.16.0.1/32", 8080)
	assert.NoError(t, err)

	// Test ClearIPPortRules
	// 测试 ClearIPPortRules
	err = mockMgr.AddIPPortRule("172.16.0.2/32", 9090, 0)
	assert.NoError(t, err)

	err = mockMgr.ClearIPPortRules()
	assert.NoError(t, err)

	rules, count, err = mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, rules)
}

// TestMockManager_AllowedPortsOperations tests allowed ports operations
// TestMockManager_AllowedPortsOperations 测试允许端口操作
func TestMockManager_AllowedPortsOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AllowPort
	// 测试 AllowPort
	err := mockMgr.AllowPort(443)
	assert.NoError(t, err)

	// Test ListAllowedPorts
	// 测试 ListAllowedPorts
	ports, err := mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	assert.Len(t, ports, 1)
	assert.Contains(t, ports, uint16(443))

	// Test RemoveAllowedPort
	// 测试 RemoveAllowedPort
	err = mockMgr.RemoveAllowedPort(443)
	assert.NoError(t, err)

	ports, err = mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	assert.Empty(t, ports)

	// Test ClearAllowedPorts
	// 测试 ClearAllowedPorts
	err = mockMgr.AllowPort(80)
	assert.NoError(t, err)

	err = mockMgr.ClearAllowedPorts()
	assert.NoError(t, err)

	ports, err = mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	assert.Empty(t, ports)
}

// TestMockManager_RateLimitOperations tests rate limit operations
// TestMockManager_RateLimitOperations 测试速率限制操作
func TestMockManager_RateLimitOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddRateLimitRule
	// 测试 AddRateLimitRule
	err := mockMgr.AddRateLimitRule("192.168.100.0/24", 1000, 2000)
	assert.NoError(t, err)

	// Test ListRateLimitRules
	// 测试 ListRateLimitRules
	rules, count, err := mockMgr.ListRateLimitRules(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, rules, 1)

	// Test RemoveRateLimitRule
	// 测试 RemoveRateLimitRule
	err = mockMgr.RemoveRateLimitRule("192.168.100.0/24")
	assert.NoError(t, err)

	rules, count, err = mockMgr.ListRateLimitRules(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, rules)

	// Test ClearRateLimitRules
	// 测试 ClearRateLimitRules
	err = mockMgr.AddRateLimitRule("10.10.0.0/16", 500, 1000)
	assert.NoError(t, err)

	err = mockMgr.ClearRateLimitRules()
	assert.NoError(t, err)

	rules, count, err = mockMgr.ListRateLimitRules(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, rules)
}

// TestMockManager_Stats tests stats operations
// TestMockManager_Stats 测试统计操作
func TestMockManager_Stats(t *testing.T) {
	mockMgr := NewMockManager()

	// Test GetDropCount
	// 测试 GetDropCount
	dropCount, err := mockMgr.GetDropCount()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), dropCount)

	// Test GetPassCount
	// 测试 GetPassCount
	passCount, err := mockMgr.GetPassCount()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), passCount)

	// Test GetLockedIPCount
	// 测试 GetLockedIPCount
	lockedCount, err := mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, lockedCount)

	// Add some IPs and test count
	// 添加一些 IP 并测试计数
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.2/32")

	lockedCount, err = mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 2, lockedCount)

	// Test GetWhitelistCount
	// 测试 GetWhitelistCount
	whitelistCount, err := mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, whitelistCount)

	// Add some whitelist IPs and test count
	// 添加一些白名单 IP 并测试计数
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	whitelistCount, err = mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 1, whitelistCount)

	// Test GetConntrackCount
	// 测试 GetConntrackCount
	conntrackCount, err := mockMgr.GetConntrackCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, conntrackCount)
}

// TestMockManager_GetDropDetails tests GetDropDetails method
// TestMockManager_GetDropDetails 测试 GetDropDetails 方法
func TestMockManager_GetDropDetails(t *testing.T) {
	mockMgr := NewMockManager()

	details, err := mockMgr.GetDropDetails()
	assert.NoError(t, err)
	assert.Nil(t, details)
}

// TestMockManager_GetPassDetails tests GetPassDetails method
// TestMockManager_GetPassDetails 测试 GetPassDetails 方法
func TestMockManager_GetPassDetails(t *testing.T) {
	mockMgr := NewMockManager()

	details, err := mockMgr.GetPassDetails()
	assert.NoError(t, err)
	assert.Nil(t, details)
}

// TestMockManager_ListAllConntrackEntries tests ListAllConntrackEntries method
// TestMockManager_ListAllConntrackEntries 测试 ListAllConntrackEntries 方法
func TestMockManager_ListAllConntrackEntries(t *testing.T) {
	mockMgr := NewMockManager()

	entries, err := mockMgr.ListAllConntrackEntries()
	assert.NoError(t, err)
	assert.Nil(t, entries)
}

// TestMockManager_Close tests Close method
// TestMockManager_Close 测试 Close 方法
func TestMockManager_Close(t *testing.T) {
	mockMgr := NewMockManager()

	err := mockMgr.Close()
	assert.NoError(t, err)
}

// TestMockManager_MapGetters tests map getter methods
// TestMockManager_MapGetters 测试 Map 获取器方法
func TestMockManager_MapGetters(t *testing.T) {
	mockMgr := NewMockManager()

	// All map getters should return nil for MockManager
	// 所有 Map 获取器对于 MockManager 应该返回 nil
	assert.Nil(t, mockMgr.LockList())
	assert.Nil(t, mockMgr.DynLockList())
	assert.Nil(t, mockMgr.Whitelist())
	assert.Nil(t, mockMgr.IPPortRules())
	assert.Nil(t, mockMgr.AllowedPorts())
	assert.Nil(t, mockMgr.RateLimitConfig())
	assert.Nil(t, mockMgr.GlobalConfig())
	assert.Nil(t, mockMgr.ConntrackMap())
}

// TestMockManager_ListBlacklistIPs_WithSearch tests ListBlacklistIPs with search
// TestMockManager_ListBlacklistIPs_WithSearch 测试 ListBlacklistIPs 使用搜索
func TestMockManager_ListBlacklistIPs_WithSearch(t *testing.T) {
	mockMgr := NewMockManager()

	// Add some IPs
	// 添加一些 IP
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.2/32")
	_ = mockMgr.AddBlacklistIP("10.0.0.1/32")

	// Test search
	// 测试搜索
	ips, count, err := mockMgr.ListBlacklistIPs(100, "192.168")
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Len(t, ips, 2)

	// Test search with no match
	// 测试搜索无匹配
	ips, count, err = mockMgr.ListBlacklistIPs(100, "172.16")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, ips)
}

// TestMockManager_ListWhitelistIPs_WithSearch tests ListWhitelistIPs with search
// TestMockManager_ListWhitelistIPs_WithSearch 测试 ListWhitelistIPs 使用搜索
func TestMockManager_ListWhitelistIPs_WithSearch(t *testing.T) {
	mockMgr := NewMockManager()

	// Add some IPs
	// 添加一些 IP
	_ = mockMgr.AddWhitelistIP("192.168.1.1/32", 0)
	_ = mockMgr.AddWhitelistIP("192.168.1.2/32", 0)
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	// Test search
	// 测试搜索
	ips, count, err := mockMgr.ListWhitelistIPs(100, "192.168")
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Len(t, ips, 2)
}

// TestMockManager_AddBlacklistIPWithFile tests AddBlacklistIPWithFile method
// TestMockManager_AddBlacklistIPWithFile 测试 AddBlacklistIPWithFile 方法
func TestMockManager_AddBlacklistIPWithFile(t *testing.T) {
	mockMgr := NewMockManager()

	err := mockMgr.AddBlacklistIPWithFile("192.168.1.1/32", "/path/to/file.txt")
	assert.NoError(t, err)

	contains, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)
}
