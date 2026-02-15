package unit

import (
	"context"
	"testing"

	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

func TestCore_SyncLockMap(t *testing.T) {
	ctx := context.Background()
	mockMgr := xdp.NewMockManager()

	// Test adding an IP to blacklist
	err := core.SyncLockMap(ctx, mockMgr, "192.168.1.100/32", true, false)
	assert.NoError(t, err)

	// Verify the IP is in the blacklist
	isBlocked, err := mockMgr.IsIPInBlacklist("192.168.1.100/32")
	assert.NoError(t, err)
	assert.True(t, isBlocked)

	// Test removing an IP from blacklist
	err = core.SyncLockMap(ctx, mockMgr, "192.168.1.100/32", false, false)
	assert.NoError(t, err)

	// Verify the IP is no longer in the blacklist
	isBlocked, err = mockMgr.IsIPInBlacklist("192.168.1.100/32")
	assert.NoError(t, err)
	assert.False(t, isBlocked)
}

func TestCore_SyncWhitelistMap(t *testing.T) {
	ctx := context.Background()
	mockMgr := xdp.NewMockManager()

	// Test adding an IP to whitelist
	err := core.SyncWhitelistMap(ctx, mockMgr, "10.0.0.100/32", 0, true, false) // port 0 means any port
	assert.NoError(t, err)

	// Verify the IP is in the whitelist
	isWhitelisted, err := mockMgr.IsIPInWhitelist("10.0.0.100/32")
	assert.NoError(t, err)
	assert.True(t, isWhitelisted)

	// Test removing an IP from whitelist
	err = core.SyncWhitelistMap(ctx, mockMgr, "10.0.0.100/32", 0, false, false)
	assert.NoError(t, err)

	// Verify the IP is no longer in the whitelist
	isWhitelisted, err = mockMgr.IsIPInWhitelist("10.0.0.100/32")
	assert.NoError(t, err)
	assert.False(t, isWhitelisted)
}

func TestCore_SyncIPPortRule(t *testing.T) {
	ctx := context.Background()
	mockMgr := xdp.NewMockManager()

	// Test adding an IP port rule (allow)
	err := core.SyncIPPortRule(ctx, mockMgr, "192.168.1.100/32", 80, 1, true) // 1 = Allow
	assert.NoError(t, err)

	// Verify the rule exists by listing
	rules, count, err := mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)
	assert.Greater(t, count, 0)

	foundRule := false
	for _, rule := range rules {
		if rule.IP == "192.168.1.100/32" && rule.Port == 80 && rule.Action == 1 {
			foundRule = true
			break
		}
	}
	assert.True(t, foundRule, "Expected to find the added IP port rule")

	// Test removing the IP port rule
	err = core.SyncIPPortRule(ctx, mockMgr, "192.168.1.100/32", 80, 0, false) // 0 = Remove
	assert.NoError(t, err)

	// Verify the rule no longer exists
	rules, count, err = mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)

	foundRule = false
	for _, rule := range rules {
		if rule.IP == "192.168.1.100/32" && rule.Port == 80 {
			foundRule = true
			break
		}
	}
	assert.False(t, foundRule, "Expected the IP port rule to be removed")
}

func TestCore_SyncRateLimitRule(t *testing.T) {
	ctx := context.Background()
	mockMgr := xdp.NewMockManager()

	// Test adding a rate limit rule
	err := core.SyncRateLimitRule(ctx, mockMgr, "192.168.1.100/32", 100, 200, true) // 100 pps, 200 burst
	assert.NoError(t, err)

	// Note: Testing rate limit rules might require specific methods in mock manager
	// depending on the implementation details

	// Test removing a rate limit rule
	err = core.SyncRateLimitRule(ctx, mockMgr, "192.168.1.100/32", 100, 200, false) // Remove
	assert.NoError(t, err)
}

func TestCore_ConflictHandling(t *testing.T) {
	ctx := context.Background()
	mockMgr := xdp.NewMockManager()

	// Add IP to whitelist first
	err := core.SyncWhitelistMap(ctx, mockMgr, "1.2.3.4/32", 0, true, false) // port 0 means any port
	assert.NoError(t, err)

	// Try to add the same IP to blacklist (should handle conflict)
	err = core.SyncLockMap(ctx, mockMgr, "1.2.3.4/32", true, true) // force = true
	assert.NoError(t, err)

	// With force=true, IP should now be in blacklist and not in whitelist
	isBlocked, err := mockMgr.IsIPInBlacklist("1.2.3.4/32")
	assert.NoError(t, err)
	assert.True(t, isBlocked)

	isWhitelisted, err := mockMgr.IsIPInWhitelist("1.2.3.4/32")
	assert.NoError(t, err)
	assert.False(t, isWhitelisted)
}
