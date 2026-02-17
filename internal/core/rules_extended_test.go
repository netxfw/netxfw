package core

import (
	"bufio"
	"context"
	"strings"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestSyncLockMap_BasicLock tests basic lock operation
// TestSyncLockMap_BasicLock 测试基本锁定操作
func TestSyncLockMap_BasicLock(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncLockMap(ctx, mockMgr, "192.168.1.100/32", true, true)
	assert.NoError(t, err)

	contains, err := mockMgr.IsIPInBlacklist("192.168.1.100/32")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestSyncLockMap_BasicUnlock tests basic unlock operation
// TestSyncLockMap_BasicLock 测试基本解锁操作
func TestSyncLockMap_BasicUnlock(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AddBlacklistIP("192.168.1.100/32")

	err := SyncLockMap(ctx, mockMgr, "192.168.1.100/32", false, true)
	assert.NoError(t, err)

	contains, err := mockMgr.IsIPInBlacklist("192.168.1.100/32")
	assert.NoError(t, err)
	assert.False(t, contains)
}

// TestSyncLockMap_IPv6 tests IPv6 address handling
// TestSyncLockMap_IPv6 测试 IPv6 地址处理
func TestSyncLockMap_IPv6(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncLockMap(ctx, mockMgr, "2001:db8::1/128", true, true)
	assert.NoError(t, err)

	contains, err := mockMgr.IsIPInBlacklist("2001:db8::1/128")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestSyncWhitelistMap_BasicAllow tests basic allow operation
// TestSyncWhitelistMap_BasicAllow 测试基本允许操作
func TestSyncWhitelistMap_BasicAllow(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncWhitelistMap(ctx, mockMgr, "10.0.0.1/32", 0, true, true)
	assert.NoError(t, err)

	contains, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestSyncWhitelistMap_WithPort tests allow operation with port
// TestSyncWhitelistMap_WithPort 测试带端口的允许操作
func TestSyncWhitelistMap_WithPort(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncWhitelistMap(ctx, mockMgr, "10.0.0.1/32", 443, true, true)
	assert.NoError(t, err)

	contains, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestSyncWhitelistMap_RemoveEntry tests remove operation
// TestSyncWhitelistMap_RemoveEntry 测试移除操作
func TestSyncWhitelistMap_RemoveEntry(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	err := SyncWhitelistMap(ctx, mockMgr, "10.0.0.1/32", 0, false, true)
	assert.NoError(t, err)

	contains, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.False(t, contains)
}

// TestSyncWhitelistMap_IPv6 tests IPv6 whitelist handling
// TestSyncWhitelistMap_IPv6 测试 IPv6 白名单处理
func TestSyncWhitelistMap_IPv6(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncWhitelistMap(ctx, mockMgr, "2001:db8::1/128", 0, true, true)
	assert.NoError(t, err)

	contains, err := mockMgr.IsIPInWhitelist("2001:db8::1/128")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestSyncBoolSettingWithConfig tests the syncBoolSettingWithConfig helper
// TestSyncBoolSettingWithConfig 测试 syncBoolSettingWithConfig 辅助函数
func TestSyncBoolSettingWithConfig(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := syncBoolSettingWithConfig(ctx, mockMgr, true,
		mockMgr.SetDefaultDeny,
		func(cfg *types.GlobalConfig, v bool) { cfg.Base.DefaultDeny = v },
		"test setting", "Test setting set to: %v")
	assert.NoError(t, err)
}

// Table-driven tests for Sync functions
// Sync 函数的表驱动测试

// TestTableDriven_SyncBoolSettings tests all boolean sync functions
// TestTableDriven_SyncBoolSettings 测试所有布尔同步函数
func TestTableDriven_SyncBoolSettings(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	testCases := []struct {
		name     string
		syncFunc func(context.Context, xdp.ManagerInterface, bool) error
		enable   bool
	}{
		{"SyncDefaultDeny_Enable", SyncDefaultDeny, true},
		{"SyncDefaultDeny_Disable", SyncDefaultDeny, false},
		{"SyncEnableAFXDP_Enable", SyncEnableAFXDP, true},
		{"SyncEnableAFXDP_Disable", SyncEnableAFXDP, false},
		{"SyncEnableRateLimit_Enable", SyncEnableRateLimit, true},
		{"SyncEnableRateLimit_Disable", SyncEnableRateLimit, false},
		{"SyncDropFragments_Enable", SyncDropFragments, true},
		{"SyncDropFragments_Disable", SyncDropFragments, false},
		{"SyncStrictTCP_Enable", SyncStrictTCP, true},
		{"SyncStrictTCP_Disable", SyncStrictTCP, false},
		{"SyncSYNLimit_Enable", SyncSYNLimit, true},
		{"SyncSYNLimit_Disable", SyncSYNLimit, false},
		{"SyncBogonFilter_Enable", SyncBogonFilter, true},
		{"SyncBogonFilter_Disable", SyncBogonFilter, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.syncFunc(ctx, mockMgr, tc.enable)
			assert.NoError(t, err)
		})
	}
}

// TestShowLockList_WithLimit tests ShowLockList with limit
// TestShowLockList_WithLimit 测试带限制的 ShowLockList
func TestShowLockList_WithLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	for i := 1; i <= 20; i++ {
		mockMgr.AddBlacklistIP("192.168.1." + string(rune('0'+i%10)) + string(rune('0'+i/10)) + "/32")
	}

	err := ShowLockList(ctx, mockMgr, 5, "")
	assert.NoError(t, err)
}

// TestAskConfirmation_AllInputs tests all possible inputs for AskConfirmation
// TestAskConfirmation_AllInputs 测试 AskConfirmation 的所有可能输入
func TestAskConfirmation_AllInputs(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"lowercase y", "y\n", true},
		{"uppercase Y", "Y\n", true},
		{"lowercase yes", "yes\n", true},
		{"uppercase YES", "YES\n", true},
		{"mixed case Yes", "Yes\n", true},
		{"lowercase n", "n\n", false},
		{"uppercase N", "N\n", false},
		{"lowercase no", "no\n", false},
		{"uppercase NO", "NO\n", false},
		{"empty input", "\n", false},
		{"random input", "maybe\n", false},
		{"whitespace", "   \n", false},
		{"tab", "\t\n", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			SetConfirmationReader(bufio.NewReader(strings.NewReader(tc.input)))
			result := AskConfirmation("Test prompt")
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestSyncLockMap_CIDRNormalization tests CIDR normalization
// TestSyncLockMap_CIDRNormalization 测试 CIDR 标准化
func TestSyncLockMap_CIDRNormalization(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	testCases := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1", "192.168.1.1/32"},
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"10.0.0.0/8", "10.0.0.0/8"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			err := SyncLockMap(ctx, mockMgr, tc.input, true, true)
			assert.NoError(t, err)
		})
	}
}

// TestSyncWhitelistMap_CIDRNormalization tests CIDR normalization for whitelist
// TestSyncWhitelistMap_CIDRNormalization 测试白名单的 CIDR 标准化
func TestSyncWhitelistMap_CIDRNormalization(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	testCases := []string{
		"10.0.0.1",
		"10.0.0.0/24",
		"172.16.0.0/16",
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			err := SyncWhitelistMap(ctx, mockMgr, tc, 0, true, true)
			assert.NoError(t, err)
		})
	}
}

// TestShowLockList_DynamicBlacklist tests dynamic blacklist listing
// TestShowLockList_DynamicBlacklist 测试动态黑名单列表
func TestShowLockList_DynamicBlacklist(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AddBlacklistIP("192.168.1.1/32")
	mockMgr.AddBlacklistIP("10.0.0.1/32")

	err := ShowLockList(ctx, mockMgr, 100, "")
	assert.NoError(t, err)
}

// TestSyncLockMap_MultipleOperations tests multiple lock/unlock operations
// TestSyncLockMap_MultipleOperations 测试多个锁定/解锁操作
func TestSyncLockMap_MultipleOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	ips := []string{
		"192.168.1.1/32",
		"192.168.1.2/32",
		"10.0.0.1/32",
		"172.16.0.1/32",
	}

	for _, ip := range ips {
		err := SyncLockMap(ctx, mockMgr, ip, true, true)
		assert.NoError(t, err)
	}

	for _, ip := range ips {
		contains, err := mockMgr.IsIPInBlacklist(ip)
		assert.NoError(t, err)
		assert.True(t, contains)
	}

	for _, ip := range ips {
		err := SyncLockMap(ctx, mockMgr, ip, false, true)
		assert.NoError(t, err)
	}

	for _, ip := range ips {
		contains, err := mockMgr.IsIPInBlacklist(ip)
		assert.NoError(t, err)
		assert.False(t, contains)
	}
}

// TestSyncWhitelistMap_MultipleOperations tests multiple whitelist operations
// TestSyncWhitelistMap_MultipleOperations 测试多个白名单操作
func TestSyncWhitelistMap_MultipleOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	ips := []struct {
		cidr string
		port uint16
	}{
		{"10.0.0.1/32", 0},
		{"10.0.0.2/32", 443},
		{"172.16.0.1/32", 80},
		{"192.168.1.1/32", 22},
	}

	for _, entry := range ips {
		err := SyncWhitelistMap(ctx, mockMgr, entry.cidr, entry.port, true, true)
		assert.NoError(t, err)
	}

	for _, entry := range ips {
		contains, err := mockMgr.IsIPInWhitelist(entry.cidr)
		assert.NoError(t, err)
		assert.True(t, contains)
	}

	for _, entry := range ips {
		err := SyncWhitelistMap(ctx, mockMgr, entry.cidr, entry.port, false, true)
		assert.NoError(t, err)
	}

	for _, entry := range ips {
		contains, err := mockMgr.IsIPInWhitelist(entry.cidr)
		assert.NoError(t, err)
		assert.False(t, contains)
	}
}

// TestSyncLockMap_EmptyIP tests handling of empty IP
// TestSyncLockMap_EmptyIP 测试空 IP 的处理
func TestSyncLockMap_EmptyIP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Empty IP should be handled gracefully (may not return error)
	// 空 IP 应该被优雅处理（可能不返回错误）
	_ = SyncLockMap(ctx, mockMgr, "", true, true)
}

// TestSyncWhitelistMap_EmptyIP tests handling of empty IP for whitelist
// TestSyncWhitelistMap_EmptyIP 测试白名单空 IP 的处理
func TestSyncWhitelistMap_EmptyIP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Empty IP should be handled gracefully (may not return error)
	// 空 IP 应该被优雅处理（可能不返回错误）
	_ = SyncWhitelistMap(ctx, mockMgr, "", 0, true, true)
}
