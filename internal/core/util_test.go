package core

import (
	"bufio"
	"context"
	"strings"
	"testing"

	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestAskConfirmation_Yes tests confirmation with yes response
// TestAskConfirmation_Yes 测试 yes 响应的确认
func TestAskConfirmation_Yes(t *testing.T) {
	tests := []struct {
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
		{"no", "no\n", false},
		{"empty", "\n", false},
		{"random", "maybe\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetConfirmationReader(bufio.NewReader(strings.NewReader(tt.input)))
			result := AskConfirmation("Test prompt")
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSetConfirmationReader tests setting the confirmation reader
// TestSetConfirmationReader 测试设置确认读取器
func TestSetConfirmationReader(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("y\n"))
	SetConfirmationReader(reader)

	result := AskConfirmation("Test")
	assert.True(t, result)
}

// TestMockXDPManager_BlacklistOperations tests blacklist operations
// TestMockXDPManager_BlacklistOperations 测试黑名单操作
func TestMockXDPManager_BlacklistOperations(t *testing.T) {
	mgr := xdp.NewMockManager()

	// Test AddBlacklistIP
	// 测试 AddBlacklistIP
	err := mgr.AddBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	// Test IsIPInBlacklist
	// 测试 IsIPInBlacklist
	blacklisted, err := mgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, blacklisted)

	// Test RemoveBlacklistIP
	// 测试 RemoveBlacklistIP
	err = mgr.RemoveBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	blacklisted, err = mgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.False(t, blacklisted)
}

// TestMockXDPManager_WhitelistOperations tests whitelist operations
// TestMockXDPManager_WhitelistOperations 测试白名单操作
func TestMockXDPManager_WhitelistOperations(t *testing.T) {
	mgr := xdp.NewMockManager()

	// Test AddWhitelistIP
	// 测试 AddWhitelistIP
	err := mgr.AddWhitelistIP("10.0.0.1/32", 0)
	assert.NoError(t, err)

	// Test IsIPInWhitelist
	// 测试 IsIPInWhitelist
	whitelisted, err := mgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, whitelisted)

	// Test RemoveWhitelistIP
	// 测试 RemoveWhitelistIP
	err = mgr.RemoveWhitelistIP("10.0.0.1/32")
	assert.NoError(t, err)

	whitelisted, err = mgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.False(t, whitelisted)
}

// TestMockXDPManager_ConfigOperations tests config operations
// TestMockXDPManager_ConfigOperations 测试配置操作
func TestMockXDPManager_ConfigOperations(t *testing.T) {
	mgr := xdp.NewMockManager()

	// Test SetDefaultDeny
	// 测试 SetDefaultDeny
	err := mgr.SetDefaultDeny(true)
	assert.NoError(t, err)
	assert.True(t, mgr.DefaultDeny)

	// Test SetEnableAFXDP
	// 测试 SetEnableAFXDP
	err = mgr.SetEnableAFXDP(true)
	assert.NoError(t, err)
	assert.True(t, mgr.EnableAFXDP)

	// Test SetEnableRateLimit
	// 测试 SetEnableRateLimit
	err = mgr.SetEnableRateLimit(true)
	assert.NoError(t, err)
	assert.True(t, mgr.EnableRateLimit)

	// Test SetDropFragments
	// 测试 SetDropFragments
	err = mgr.SetDropFragments(true)
	assert.NoError(t, err)
	assert.True(t, mgr.DropFragments)

	// Test SetStrictTCP
	// 测试 SetStrictTCP
	err = mgr.SetStrictTCP(true)
	assert.NoError(t, err)
	assert.True(t, mgr.StrictTCP)

	// Test SetSYNLimit
	// 测试 SetSYNLimit
	err = mgr.SetSYNLimit(true)
	assert.NoError(t, err)
	assert.True(t, mgr.SYNLimit)

	// Test SetBogonFilter
	// 测试 SetBogonFilter
	err = mgr.SetBogonFilter(true)
	assert.NoError(t, err)
	assert.True(t, mgr.BogonFilter)
}

// TestSyncDefaultDeny tests SyncDefaultDeny function
// TestSyncDefaultDeny 测试 SyncDefaultDeny 函数
func TestSyncDefaultDeny(t *testing.T) {
	// Use xdp.MockManager which implements the full interface
	// 使用实现了完整接口的 xdp.MockManager
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncDefaultDeny(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DefaultDeny)

	err = SyncDefaultDeny(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.DefaultDeny)
}

// TestSyncEnableAFXDP tests SyncEnableAFXDP function
// TestSyncEnableAFXDP 测试 SyncEnableAFXDP 函数
func TestSyncEnableAFXDP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableAFXDP(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableAFXDP)

	err = SyncEnableAFXDP(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.EnableAFXDP)
}

// TestSyncEnableRateLimit tests SyncEnableRateLimit function
// TestSyncEnableRateLimit 测试 SyncEnableRateLimit 函数
func TestSyncEnableRateLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableRateLimit(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableRateLimit)

	err = SyncEnableRateLimit(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.EnableRateLimit)
}

// TestSyncDropFragments tests SyncDropFragments function
// TestSyncDropFragments 测试 SyncDropFragments 函数
func TestSyncDropFragments(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncDropFragments(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DropFragments)

	err = SyncDropFragments(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.DropFragments)
}

// TestSyncStrictTCP tests SyncStrictTCP function
// TestSyncStrictTCP 测试 SyncStrictTCP 函数
func TestSyncStrictTCP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncStrictTCP(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.StrictTCP)

	err = SyncStrictTCP(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.StrictTCP)
}

// TestSyncSYNLimit tests SyncSYNLimit function
// TestSyncSYNLimit 测试 SyncSYNLimit 函数
func TestSyncSYNLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncSYNLimit(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.SYNLimit)

	err = SyncSYNLimit(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.SYNLimit)
}

// TestSyncBogonFilter tests SyncBogonFilter function
// TestSyncBogonFilter 测试 SyncBogonFilter 函数
func TestSyncBogonFilter(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncBogonFilter(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.BogonFilter)

	err = SyncBogonFilter(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.BogonFilter)
}

// TestShowLockList tests ShowLockList function
// TestShowLockList 测试 ShowLockList 函数
func TestShowLockList(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Add some IPs to blacklist
	// 添加一些 IP 到黑名单
	mockMgr.AddBlacklistIP("192.168.1.1/32")
	mockMgr.AddBlacklistIP("192.168.1.2/32")

	err := ShowLockList(ctx, mockMgr, 100, "")
	assert.NoError(t, err)
}

// TestShowLockList_Empty tests ShowLockList with empty list
// TestShowLockList_Empty 测试空列表的 ShowLockList
func TestShowLockList_Empty(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := ShowLockList(ctx, mockMgr, 100, "")
	assert.NoError(t, err)
}

// TestShowLockList_WithSearch tests ShowLockList with search filter
// TestShowLockList_WithSearch 测试带搜索过滤的 ShowLockList
func TestShowLockList_WithSearch(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AddBlacklistIP("192.168.1.1/32")
	mockMgr.AddBlacklistIP("10.0.0.1/32")

	err := ShowLockList(ctx, mockMgr, 100, "192.168")
	assert.NoError(t, err)
}
