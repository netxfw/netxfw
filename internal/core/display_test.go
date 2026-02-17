package core

import (
	"context"
	"testing"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestShowWhitelist tests ShowWhitelist function
// TestShowWhitelist 测试 ShowWhitelist 函数
func TestShowWhitelist(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Add some whitelist IPs
	// 添加一些白名单 IP
	mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	mockMgr.AddWhitelistIP("10.0.0.2/32", 0)

	err := ShowWhitelist(ctx, mockMgr, 100, "")
	assert.NoError(t, err)
}

// TestShowWhitelist_Empty tests ShowWhitelist with empty list
// TestShowWhitelist_Empty 测试空列表的 ShowWhitelist
func TestShowWhitelist_Empty(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := ShowWhitelist(ctx, mockMgr, 100, "")
	assert.NoError(t, err)
}

// TestShowWhitelist_WithSearch tests ShowWhitelist with search filter
// TestShowWhitelist_WithSearch 测试带搜索过滤的 ShowWhitelist
func TestShowWhitelist_WithSearch(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	mockMgr.AddWhitelistIP("192.168.1.1/32", 0)

	err := ShowWhitelist(ctx, mockMgr, 100, "10.0")
	assert.NoError(t, err)
}

// TestShowConntrack tests ShowConntrack function
// TestShowConntrack 测试 ShowConntrack 函数
func TestShowConntrack(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := ShowConntrack(ctx, mockMgr)
	assert.NoError(t, err)
}

// TestShowIPPortRules tests ShowIPPortRules function
// TestShowIPPortRules 测试 ShowIPPortRules 函数
func TestShowIPPortRules(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Add some IP port rules
	// 添加一些 IP 端口规则
	mockMgr.AddIPPortRule("192.168.1.1", 80, 1)
	mockMgr.AddIPPortRule("10.0.0.1", 443, 2)

	err := ShowIPPortRules(ctx, mockMgr, 100, "")
	assert.NoError(t, err)
}

// TestShowIPPortRules_Empty tests ShowIPPortRules with empty list
// TestShowIPPortRules_Empty 测试空列表的 ShowIPPortRules
func TestShowIPPortRules_Empty(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := ShowIPPortRules(ctx, mockMgr, 100, "")
	assert.NoError(t, err)
}

// TestShowRateLimitRules tests ShowRateLimitRules function
// TestShowRateLimitRules 测试 ShowRateLimitRules 函数
func TestShowRateLimitRules(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Add some rate limit rules
	// 添加一些速率限制规则
	mockMgr.AddRateLimitRule("192.168.1.1", 1000, 100)

	err := ShowRateLimitRules(ctx, mockMgr)
	assert.NoError(t, err)
}

// TestShowRateLimitRules_Empty tests ShowRateLimitRules with empty list
// TestShowRateLimitRules_Empty 测试空列表的 ShowRateLimitRules
func TestShowRateLimitRules_Empty(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := ShowRateLimitRules(ctx, mockMgr)
	assert.NoError(t, err)
}

// TestShowStatus tests ShowStatus function
// TestShowStatus 测试 ShowStatus 函数
func TestShowStatus(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := ShowStatus(ctx, mockMgr)
	assert.NoError(t, err)
}

// TestShowTopStats tests ShowTopStats function
// TestShowTopStats 测试 ShowTopStats 函数
func TestShowTopStats(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := ShowTopStats(ctx, mockMgr, 10, "drop")
	assert.NoError(t, err)
}

// TestShowTopStats_SortByPass tests ShowTopStats sorted by pass
// TestShowTopStats_SortByPass 测试按 pass 排序的 ShowTopStats
func TestShowTopStats_SortByPass(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := ShowTopStats(ctx, mockMgr, 10, "pass")
	assert.NoError(t, err)
}
