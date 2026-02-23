package xdp

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
)

// TestManager_MatchesCapacity tests capacity matching
// TestManager_MatchesCapacity 测试容量匹配
func TestManager_MatchesCapacity(t *testing.T) {
	// Skip this test since MockManager doesn't have MatchesCapacity method
	// 跳过此测试，因为 MockManager 没有 MatchesCapacity 方法
	t.Skip("MatchesCapacity method not implemented in MockManager")
}

// TestManager_ConfigurationMethods tests configuration methods
// TestManager_ConfigurationMethods 测试配置方法
func TestManager_ConfigurationMethods(t *testing.T) {
	mockMgr := NewMockManager()

	// Test SetDefaultDeny
	// 测试 SetDefaultDeny
	err := mockMgr.SetDefaultDeny(true)
	assert.NoError(t, err)

	// Test SetAllowReturnTraffic
	// 测试 SetAllowReturnTraffic
	err = mockMgr.SetAllowReturnTraffic(true)
	assert.NoError(t, err)

	// Test SetAllowICMP
	// 测试 SetAllowICMP
	err = mockMgr.SetAllowICMP(true)
	assert.NoError(t, err)

	// Test SetConntrack
	// 测试 SetConntrack
	err = mockMgr.SetConntrack(true)
	assert.NoError(t, err)

	// Test SetEnableRateLimit
	// 测试 SetEnableRateLimit
	err = mockMgr.SetEnableRateLimit(true)
	assert.NoError(t, err)

	// Test SetBogonFilter
	// 测试 SetBogonFilter
	err = mockMgr.SetBogonFilter(true)
	assert.NoError(t, err)

	// Test SetAutoBlock
	// 测试 SetAutoBlock
	err = mockMgr.SetAutoBlock(true)
	assert.NoError(t, err)
}

// TestManager_IPListOperations tests IP list operations
// TestManager_IPListOperations 测试 IP 列表操作
func TestManager_IPListOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Test IsIPInWhitelist
	// 测试 IsIPInWhitelist
	whitelisted, err := mockMgr.IsIPInWhitelist("127.0.0.1/32")
	assert.NoError(t, err)
	assert.False(t, whitelisted) // Should initially be false

	// Test AddWhitelistIP
	// 测试 AddWhitelistIP
	err = mockMgr.AddWhitelistIP("127.0.0.1/32", 0)
	assert.NoError(t, err)

	whitelisted, err = mockMgr.IsIPInWhitelist("127.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, whitelisted)

	// Test RemoveWhitelistIP
	// 测试 RemoveWhitelistIP
	err = mockMgr.RemoveWhitelistIP("127.0.0.1/32")
	assert.NoError(t, err)

	whitelisted, err = mockMgr.IsIPInWhitelist("127.0.0.1/32")
	assert.NoError(t, err)
	assert.False(t, whitelisted)
}

// TestManager_BlacklistOperations tests blacklist operations
// TestManager_BlacklistOperations 测试黑名单操作
func TestManager_BlacklistOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Test IsIPInBlacklist
	// 测试 IsIPInBlacklist
	blacklisted, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.False(t, blacklisted) // Should initially be false

	// Test AddBlacklistIP
	// 测试 AddBlacklistIP
	err = mockMgr.AddBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	blacklisted, err = mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, blacklisted)

	// Test RemoveBlacklistIP
	// 测试 RemoveBlacklistIP
	err = mockMgr.RemoveBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	blacklisted, err = mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.False(t, blacklisted)
}

// TestManager_IPPortRuleOperations tests IP port rule operations
// TestManager_IPPortRuleOperations 测试 IP 端口规则操作
func TestManager_IPPortRuleOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddIPPortRule
	// 测试 AddIPPortRule
	err := mockMgr.AddIPPortRule("10.0.0.1/32", 80, 1) // 1 = Allow
	assert.NoError(t, err)

	// Test ListIPPortRules to verify the rule was added
	// 测试 ListIPPortRules 验证规则已添加
	rules, count, err := mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)
	assert.Greater(t, count, 0)

	foundRule := false
	for _, rule := range rules {
		if rule.IP == "10.0.0.1/32" && rule.Port == 80 && rule.Action == 1 {
			foundRule = true
			break
		}
	}
	assert.True(t, foundRule, "Expected to find the added IP port rule")

	// Test RemoveIPPortRule
	// 测试 RemoveIPPortRule
	err = mockMgr.RemoveIPPortRule("10.0.0.1/32", 80)
	assert.NoError(t, err)

	// Verify the rule was removed
	// 验证规则已删除
	rules, _, err = mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)

	foundRule = false
	for _, rule := range rules {
		if rule.IP == "10.0.0.1/32" && rule.Port == 80 {
			foundRule = true
			break
		}
	}
	assert.False(t, foundRule, "Expected the IP port rule to be removed")
}

// TestManager_ConntrackOperations tests conntrack operations
// TestManager_ConntrackOperations 测试连接跟踪操作
func TestManager_ConntrackOperations(t *testing.T) {
	// Skip conntrack tests since MockManager doesn't implement these methods
	// 跳过连接跟踪测试，因为 MockManager 没有实现这些方法
	t.Skip("Conntrack methods not implemented in MockManager")
}

// TestMockManager_ClearOperations tests clear operations
// TestMockManager_ClearOperations 测试清除操作
func TestMockManager_ClearOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Add some data
	// 添加一些数据
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	_ = mockMgr.AddIPPortRule("10.0.0.2/32", 80, 1)
	_ = mockMgr.AllowPort(443)
	_ = mockMgr.AddRateLimitRule("10.0.0.0/24", 1000, 2000)

	// Test ClearBlacklist
	// 测试 ClearBlacklist
	err := mockMgr.ClearBlacklist()
	assert.NoError(t, err)
	count, err := mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	// Test ClearWhitelist
	// 测试 ClearWhitelist
	err = mockMgr.ClearWhitelist()
	assert.NoError(t, err)
	count, err = mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	// Test ClearIPPortRules
	// 测试 ClearIPPortRules
	err = mockMgr.ClearIPPortRules()
	assert.NoError(t, err)
	_, count, err = mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	// Test ClearAllowedPorts
	// 测试 ClearAllowedPorts
	err = mockMgr.ClearAllowedPorts()
	assert.NoError(t, err)
	ports, err := mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	assert.Len(t, ports, 0)

	// Test ClearRateLimitRules
	// 测试 ClearRateLimitRules
	err = mockMgr.ClearRateLimitRules()
	assert.NoError(t, err)
	_, count, err = mockMgr.ListRateLimitRules(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_StatsOperations tests stats operations
// TestMockManager_StatsOperations 测试统计操作
func TestMockManager_StatsOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Add some blacklist IPs
	// 添加一些黑名单 IP
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.2/32")
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	// Test GetLockedIPCount
	// 测试 GetLockedIPCount
	count, err := mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 2, count)

	// Test GetWhitelistCount
	// 测试 GetWhitelistCount
	count, err = mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 1, count)

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

	// Test GetDropDetails
	// 测试 GetDropDetails
	dropDetails, err := mockMgr.GetDropDetails()
	assert.NoError(t, err)
	assert.Nil(t, dropDetails)

	// Test GetPassDetails
	// 测试 GetPassDetails
	passDetails, err := mockMgr.GetPassDetails()
	assert.NoError(t, err)
	assert.Nil(t, passDetails)
}

// TestMockManager_ListWithSearch tests list operations with search filter
// TestMockManager_ListWithSearch 测试带搜索过滤的列表操作
func TestMockManager_ListWithSearch(t *testing.T) {
	mockMgr := NewMockManager()

	// Add multiple IPs
	// 添加多个 IP
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.2/32")
	_ = mockMgr.AddBlacklistIP("10.0.0.1/32")

	// Test ListBlacklistIPs with search
	// 测试带搜索的 ListBlacklistIPs
	ips, count, err := mockMgr.ListBlacklistIPs(100, "192.168")
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Len(t, ips, 2)

	// Test ListBlacklistIPs with empty search returns all
	// 测试带空搜索的 ListBlacklistIPs 返回全部
	ips, count, err = mockMgr.ListBlacklistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 3, count)
	assert.Len(t, ips, 3)
}

// TestMockManager_IPNormalization tests IP normalization
// TestMockManager_IPNormalization 测试 IP 规范化
func TestMockManager_IPNormalization(t *testing.T) {
	mockMgr := NewMockManager()

	// Test adding IP without CIDR suffix
	// 测试添加不带 CIDR 后缀的 IP
	err := mockMgr.AddBlacklistIP("192.168.1.1")
	assert.NoError(t, err)

	// Should be able to find with /32 suffix
	// 应该能用 /32 后缀找到
	blacklisted, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, blacklisted)

	// Test whitelist IP normalization
	// 测试白名单 IP 规范化
	err = mockMgr.AddWhitelistIP("10.0.0.1", 0)
	assert.NoError(t, err)

	whitelisted, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, whitelisted)
}

// TestMockManager_DynamicBlacklist tests dynamic blacklist operations
// TestMockManager_DynamicBlacklist 测试动态黑名单操作
func TestMockManager_DynamicBlacklist(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddDynamicBlacklistIP
	// 测试 AddDynamicBlacklistIP
	err := mockMgr.AddDynamicBlacklistIP("192.168.1.100", time.Hour)
	assert.NoError(t, err)

	// Should be in blacklist
	// 应该在黑名单中
	blacklisted, err := mockMgr.IsIPInBlacklist("192.168.1.100/32")
	assert.NoError(t, err)
	assert.True(t, blacklisted)

	// Test ListDynamicBlacklistIPs
	// 测试 ListDynamicBlacklistIPs
	ips, count, err := mockMgr.ListDynamicBlacklistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count) // Mock returns empty for dynamic list
	assert.Nil(t, ips)
}

// TestMockManager_SyncFromFiles tests SyncFromFiles method
// TestMockManager_SyncFromFiles 测试 SyncFromFiles 方法
func TestMockManager_SyncFromFiles(t *testing.T) {
	mockMgr := NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{"10.0.0.1/32", "10.0.0.2/32"},
		},
	}

	// Test SyncFromFiles without overwrite
	// 测试不带覆盖的 SyncFromFiles
	err := mockMgr.SyncFromFiles(cfg, false)
	assert.NoError(t, err)

	// Verify whitelist was synced
	// 验证白名单已同步
	count, err := mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 2, count)

	// Test SyncFromFiles with overwrite
	// 测试带覆盖的 SyncFromFiles
	_ = mockMgr.AddWhitelistIP("192.168.1.1/32", 0)
	err = mockMgr.SyncFromFiles(cfg, true)
	assert.NoError(t, err)

	count, err = mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 2, count) // Should be reset to config whitelist
}

// TestMockManager_VerifyAndRepair tests VerifyAndRepair method
// TestMockManager_VerifyAndRepair 测试 VerifyAndRepair 方法
func TestMockManager_VerifyAndRepair(t *testing.T) {
	mockMgr := NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{"10.0.0.1/32"},
		},
	}

	err := mockMgr.VerifyAndRepair(cfg)
	assert.NoError(t, err)
}

// TestMockManager_SyncToFiles tests SyncToFiles method
// TestMockManager_SyncToFiles 测试 SyncToFiles 方法
func TestMockManager_SyncToFiles(t *testing.T) {
	mockMgr := NewMockManager()

	// Add some whitelist IPs
	// 添加一些白名单 IP
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	_ = mockMgr.AddWhitelistIP("10.0.0.2/32", 0)

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{},
	}

	err := mockMgr.SyncToFiles(cfg)
	assert.NoError(t, err)
	assert.Len(t, cfg.Base.Whitelist, 2)
}

// TestMockManager_ConfigurationAdvanced tests advanced configuration methods
// TestMockManager_ConfigurationAdvanced 测试高级配置方法
func TestMockManager_ConfigurationAdvanced(t *testing.T) {
	mockMgr := NewMockManager()

	// Test SetStrictTCP
	// 测试 SetStrictTCP
	err := mockMgr.SetStrictTCP(true)
	assert.NoError(t, err)

	// Test SetSYNLimit
	// 测试 SetSYNLimit
	err = mockMgr.SetSYNLimit(true)
	assert.NoError(t, err)

	// Test SetEnableAFXDP
	// 测试 SetEnableAFXDP
	err = mockMgr.SetEnableAFXDP(true)
	assert.NoError(t, err)

	// Test SetDropFragments
	// 测试 SetDropFragments
	err = mockMgr.SetDropFragments(true)
	assert.NoError(t, err)

	// Test SetAutoBlockExpiry
	// 测试 SetAutoBlockExpiry
	err = mockMgr.SetAutoBlockExpiry(time.Hour)
	assert.NoError(t, err)

	// Test SetConntrackTimeout
	// 测试 SetConntrackTimeout
	err = mockMgr.SetConntrackTimeout(time.Minute * 30)
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

// TestMockManager_GetConntrackCount tests GetConntrackCount method
// TestMockManager_GetConntrackCount 测试 GetConntrackCount 方法
func TestMockManager_GetConntrackCount(t *testing.T) {
	mockMgr := NewMockManager()

	count, err := mockMgr.GetConntrackCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}
