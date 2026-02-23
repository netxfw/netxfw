package xdp_test

import (
	"testing"

	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestXDPMiscFunctions tests miscellaneous XDP functions
// TestXDPMiscFunctions 测试杂项 XDP 函数
func TestXDPMiscFunctions(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Test basic operations that should work with mock
	// 测试应该与 mock 一起工作的基本操作
	count, err := mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)

	count, err = mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)

	// Test close operation
	// 测试关闭操作
	err = mockMgr.Close()
	assert.NoError(t, err)
}

// TestXDPLifecycle tests XDP lifecycle
// TestXDPLifecycle 测试 XDP 生命周期
func TestXDPLifecycle(t *testing.T) {
	// Test that we can create and use the mock manager properly
	// 测试我们可以正确创建和使用 mock manager
	mockMgr := xdp.NewMockManager()

	// Add some data
	// 添加一些数据
	err := mockMgr.AddBlacklistIP("1.2.3.4/32")
	assert.NoError(t, err)

	// Verify it was added
	// 验证已添加
	inBlacklist, err := mockMgr.IsIPInBlacklist("1.2.3.4/32")
	assert.NoError(t, err)
	assert.True(t, inBlacklist)

	// Remove it
	// 删除它
	err = mockMgr.RemoveBlacklistIP("1.2.3.4/32")
	assert.NoError(t, err)

	// Verify it was removed
	// 验证已删除
	inBlacklist, err = mockMgr.IsIPInBlacklist("1.2.3.4/32")
	assert.NoError(t, err)
	assert.False(t, inBlacklist)
}
