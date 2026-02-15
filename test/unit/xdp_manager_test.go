package unit

import (
	"testing"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

func TestManager_MatchesCapacity(t *testing.T) {
	// Skip this test since MockManager doesn't have MatchesCapacity method
	t.Skip("MatchesCapacity method not implemented in MockManager")
}

func TestManager_ConfigurationMethods(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Test SetDefaultDeny
	err := mockMgr.SetDefaultDeny(true)
	assert.NoError(t, err)

	// Test SetAllowReturnTraffic
	err = mockMgr.SetAllowReturnTraffic(true)
	assert.NoError(t, err)

	// Test SetAllowICMP
	err = mockMgr.SetAllowICMP(true)
	assert.NoError(t, err)

	// Test SetConntrack
	err = mockMgr.SetConntrack(true)
	assert.NoError(t, err)

	// Test SetEnableRateLimit
	err = mockMgr.SetEnableRateLimit(true)
	assert.NoError(t, err)

	// Test SetBogonFilter
	err = mockMgr.SetBogonFilter(true)
	assert.NoError(t, err)

	// Test SetAutoBlock
	err = mockMgr.SetAutoBlock(true)
	assert.NoError(t, err)
}

func TestManager_IPListOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Test IsIPInWhitelist
	whitelisted, err := mockMgr.IsIPInWhitelist("127.0.0.1/32")
	assert.NoError(t, err)
	assert.False(t, whitelisted) // Should initially be false

	// Test AddWhitelistIP
	err = mockMgr.AddWhitelistIP("127.0.0.1/32", 0)
	assert.NoError(t, err)

	whitelisted, err = mockMgr.IsIPInWhitelist("127.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, whitelisted)

	// Test RemoveWhitelistIP
	err = mockMgr.RemoveWhitelistIP("127.0.0.1/32")
	assert.NoError(t, err)

	whitelisted, err = mockMgr.IsIPInWhitelist("127.0.0.1/32")
	assert.NoError(t, err)
	assert.False(t, whitelisted)
}

func TestManager_BlacklistOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Test IsIPInBlacklist
	blacklisted, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.False(t, blacklisted) // Should initially be false

	// Test AddBlacklistIP
	err = mockMgr.AddBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	blacklisted, err = mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, blacklisted)

	// Test RemoveBlacklistIP
	err = mockMgr.RemoveBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	blacklisted, err = mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.False(t, blacklisted)
}

func TestManager_IPPortRuleOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Test AddIPPortRule
	err := mockMgr.AddIPPortRule("10.0.0.1/32", 80, 1) // 1 = Allow
	assert.NoError(t, err)

	// Test ListIPPortRules to verify the rule was added
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
	err = mockMgr.RemoveIPPortRule("10.0.0.1/32", 80)
	assert.NoError(t, err)

	// Verify the rule was removed
	rules, count, err = mockMgr.ListIPPortRules(false, 100, "")
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

func TestManager_ConntrackOperations(t *testing.T) {
	// Skip conntrack tests since MockManager doesn't implement these methods
	t.Skip("Conntrack methods not implemented in MockManager")
}
