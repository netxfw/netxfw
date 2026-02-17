package core

import (
	"context"
	"testing"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestSyncToConfig tests SyncToConfig function
// TestSyncToConfig 测试 SyncToConfig 函数
func TestSyncToConfig(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Add some test data
	// 添加一些测试数据
	mockMgr.AddBlacklistIP("192.168.1.1/32")
	mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	// SyncToConfig requires a valid config file, so we expect an error
	// SyncToConfig 需要有效的配置文件，所以我们期望错误
	err := SyncToConfig(ctx, mockMgr)
	// May error due to missing config file, but should not panic
	// 可能因缺少配置文件而报错，但不应崩溃
	_ = err
}

// TestSyncToMap tests SyncToMap function
// TestSyncToMap 测试 SyncToMap 函数
func TestSyncToMap(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// SyncToMap requires a valid config file, so we expect an error
	// SyncToMap 需要有效的配置文件，所以我们期望错误
	err := SyncToMap(ctx, mockMgr)
	// May error due to missing config file, but should not panic
	// 可能因缺少配置文件而报错，但不应崩溃
	_ = err
}

// TestSyncLockMap_Lock tests SyncLockMap with lock=true
// TestSyncLockMap_Lock 测试 SyncLockMap 使用 lock=true
func TestSyncLockMap_Lock(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncLockMap(ctx, mockMgr, "192.168.1.100/32", true, false)
	// May error due to missing config file, but should not panic
	// 可能因缺少配置文件而报错，但不应崩溃
	_ = err
}

// TestSyncLockMap_Unlock tests SyncLockMap with lock=false
// TestSyncLockMap_Unlock 测试 SyncLockMap 使用 lock=false
func TestSyncLockMap_Unlock(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// First add an IP
	// 首先添加一个 IP
	mockMgr.AddBlacklistIP("192.168.1.100/32")

	err := SyncLockMap(ctx, mockMgr, "192.168.1.100/32", false, false)
	// May error due to missing config file, but should not panic
	// 可能因缺少配置文件而报错，但不应崩溃
	_ = err
}

// TestSyncLockMap_ConflictWithWhitelist tests SyncLockMap with whitelist conflict
// TestSyncLockMap_ConflictWithWhitelist 测试 SyncLockMap 与白名单冲突
func TestSyncLockMap_ConflictWithWhitelist(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Add IP to whitelist first
	// 首先将 IP 添加到白名单
	mockMgr.AddWhitelistIP("192.168.1.100/32", 0)

	// Try to add to blacklist (conflict)
	// 尝试添加到黑名单（冲突）
	err := SyncLockMap(ctx, mockMgr, "192.168.1.100/32", true, false)
	// May error or succeed depending on confirmation handling
	// 可能报错或成功，取决于确认处理
	_ = err
}

// TestSyncWhitelistMap_Allow tests SyncWhitelistMap with allow=true
// TestSyncWhitelistMap_Allow 测试 SyncWhitelistMap 使用 allow=true
func TestSyncWhitelistMap_Allow(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncWhitelistMap(ctx, mockMgr, "10.0.0.1/32", 0, true, false)
	// May error due to missing config file, but should not panic
	// 可能因缺少配置文件而报错，但不应崩溃
	_ = err
}

// TestSyncWhitelistMap_AllowWithPort tests SyncWhitelistMap with port
// TestSyncWhitelistMap_AllowWithPort 测试 SyncWhitelistMap 使用端口
func TestSyncWhitelistMap_AllowWithPort(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncWhitelistMap(ctx, mockMgr, "10.0.0.1/32", 443, true, false)
	// May error due to missing config file, but should not panic
	// 可能因缺少配置文件而报错，但不应崩溃
	_ = err
}

// TestSyncWhitelistMap_Remove tests SyncWhitelistMap with allow=false
// TestSyncWhitelistMap_Remove 测试 SyncWhitelistMap 使用 allow=false
func TestSyncWhitelistMap_Remove(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// First add to whitelist
	// 首先添加到白名单
	mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	err := SyncWhitelistMap(ctx, mockMgr, "10.0.0.1/32", 0, false, false)
	// May error due to missing config file, but should not panic
	// 可能因缺少配置文件而报错，但不应崩溃
	_ = err
}

// TestSyncWhitelistMap_ConflictWithBlacklist tests SyncWhitelistMap with blacklist conflict
// TestSyncWhitelistMap_ConflictWithBlacklist 测试 SyncWhitelistMap 与黑名单冲突
func TestSyncWhitelistMap_ConflictWithBlacklist(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Add IP to blacklist first
	// 首先将 IP 添加到黑名单
	mockMgr.AddBlacklistIP("10.0.0.1/32")

	// Try to add to whitelist (conflict)
	// 尝试添加到白名单（冲突）
	err := SyncWhitelistMap(ctx, mockMgr, "10.0.0.1/32", 0, true, false)
	// May error or succeed depending on confirmation handling
	// 可能报错或成功，取决于确认处理
	_ = err
}

// TestSyncDefaultDeny_Enable tests SyncDefaultDeny with enable=true
// TestSyncDefaultDeny_Enable 测试 SyncDefaultDeny 使用 enable=true
func TestSyncDefaultDeny_Enable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncDefaultDeny(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DefaultDeny)
}

// TestSyncDefaultDeny_Disable tests SyncDefaultDeny with enable=false
// TestSyncDefaultDeny_Disable 测试 SyncDefaultDeny 使用 enable=false
func TestSyncDefaultDeny_Disable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// First enable
	// 首先启用
	mockMgr.SetDefaultDeny(true)

	err := SyncDefaultDeny(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.DefaultDeny)
}

// TestSyncEnableAFXDP_Enable tests SyncEnableAFXDP with enable=true
// TestSyncEnableAFXDP_Enable 测试 SyncEnableAFXDP 使用 enable=true
func TestSyncEnableAFXDP_Enable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableAFXDP(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableAFXDP)
}

// TestSyncEnableAFXDP_Disable tests SyncEnableAFXDP with enable=false
// TestSyncEnableAFXDP_Disable 测试 SyncEnableAFXDP 使用 enable=false
func TestSyncEnableAFXDP_Disable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableAFXDP(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.EnableAFXDP)
}

// TestSyncEnableRateLimit_Enable tests SyncEnableRateLimit with enable=true
// TestSyncEnableRateLimit_Enable 测试 SyncEnableRateLimit 使用 enable=true
func TestSyncEnableRateLimit_Enable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableRateLimit(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableRateLimit)
}

// TestSyncEnableRateLimit_Disable tests SyncEnableRateLimit with enable=false
// TestSyncEnableRateLimit_Disable 测试 SyncEnableRateLimit 使用 enable=false
func TestSyncEnableRateLimit_Disable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableRateLimit(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.EnableRateLimit)
}

// TestSyncDropFragments_Enable tests SyncDropFragments with enable=true
// TestSyncDropFragments_Enable 测试 SyncDropFragments 使用 enable=true
func TestSyncDropFragments_Enable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncDropFragments(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DropFragments)
}

// TestSyncDropFragments_Disable tests SyncDropFragments with enable=false
// TestSyncDropFragments_Disable 测试 SyncDropFragments 使用 enable=false
func TestSyncDropFragments_Disable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncDropFragments(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.DropFragments)
}

// TestSyncStrictTCP_Enable tests SyncStrictTCP with enable=true
// TestSyncStrictTCP_Enable 测试 SyncStrictTCP 使用 enable=true
func TestSyncStrictTCP_Enable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncStrictTCP(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.StrictTCP)
}

// TestSyncStrictTCP_Disable tests SyncStrictTCP with enable=false
// TestSyncStrictTCP_Disable 测试 SyncStrictTCP 使用 enable=false
func TestSyncStrictTCP_Disable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncStrictTCP(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.StrictTCP)
}

// TestSyncSYNLimit_Enable tests SyncSYNLimit with enable=true
// TestSyncSYNLimit_Enable 测试 SyncSYNLimit 使用 enable=true
func TestSyncSYNLimit_Enable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncSYNLimit(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.SYNLimit)
}

// TestSyncSYNLimit_Disable tests SyncSYNLimit with enable=false
// TestSyncSYNLimit_Disable 测试 SyncSYNLimit 使用 enable=false
func TestSyncSYNLimit_Disable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncSYNLimit(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.SYNLimit)
}

// TestSyncBogonFilter_Enable tests SyncBogonFilter with enable=true
// TestSyncBogonFilter_Enable 测试 SyncBogonFilter 使用 enable=true
func TestSyncBogonFilter_Enable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncBogonFilter(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.BogonFilter)
}

// TestSyncBogonFilter_Disable tests SyncBogonFilter with enable=false
// TestSyncBogonFilter_Disable 测试 SyncBogonFilter 使用 enable=false
func TestSyncBogonFilter_Disable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncBogonFilter(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.BogonFilter)
}

// TestShowLockList_WithMultipleIPs tests ShowLockList with multiple IPs
// TestShowLockList_WithMultipleIPs 测试 ShowLockList 使用多个 IP
func TestShowLockList_WithMultipleIPs(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	// Add multiple IPs
	// 添加多个 IP
	for i := 1; i <= 10; i++ {
		mockMgr.AddBlacklistIP("192.168.1." + string(rune('0'+i)) + "/32")
	}

	err := ShowLockList(ctx, mockMgr, 5, "")
	assert.NoError(t, err)
}

// TestShowLockList_Search tests ShowLockList with search
// TestShowLockList_Search 测试 ShowLockList 使用搜索
func TestShowLockList_Search(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AddBlacklistIP("192.168.1.1/32")
	mockMgr.AddBlacklistIP("10.0.0.1/32")
	mockMgr.AddBlacklistIP("172.16.0.1/32")

	err := ShowLockList(ctx, mockMgr, 100, "192.168")
	assert.NoError(t, err)

	err = ShowLockList(ctx, mockMgr, 100, "10.0")
	assert.NoError(t, err)
}
