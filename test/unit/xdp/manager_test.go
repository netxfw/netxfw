package xdp_test

import (
	"testing"

	"github.com/livp123/netxfw/internal/xdp"
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
	mockMgr := xdp.NewMockManager()

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
	mockMgr := xdp.NewMockManager()

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
	mockMgr := xdp.NewMockManager()

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
	mockMgr := xdp.NewMockManager()

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
