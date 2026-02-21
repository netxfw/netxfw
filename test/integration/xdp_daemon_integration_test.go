package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestXDP_Integration_FullWorkflow tests the complete XDP workflow
// TestXDP_Integration_FullWorkflow 测试完整的 XDP 工作流
func TestXDP_Integration_FullWorkflow(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Step 1: Configure the manager
	// 步骤 1：配置管理器
	err := mockMgr.SetDefaultDeny(true)
	assert.NoError(t, err)

	err = mockMgr.SetAllowReturnTraffic(true)
	assert.NoError(t, err)

	err = mockMgr.SetAllowICMP(true)
	assert.NoError(t, err)

	err = mockMgr.SetConntrack(true)
	assert.NoError(t, err)

	err = mockMgr.SetEnableRateLimit(true)
	assert.NoError(t, err)

	// Step 2: Add blacklist IPs
	// 步骤 2：添加黑名单 IP
	err = mockMgr.AddBlacklistIP("192.168.1.100/32")
	assert.NoError(t, err)

	err = mockMgr.AddBlacklistIP("10.0.0.50/32")
	assert.NoError(t, err)

	count, err := mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 2, count)

	// Step 3: Add whitelist IPs
	// 步骤 3：添加白名单 IP
	err = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	assert.NoError(t, err)

	err = mockMgr.AddWhitelistIP("10.0.0.2/32", 80)
	assert.NoError(t, err)

	count, err = mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 2, count)

	// Step 4: Add IP port rules
	// 步骤 4：添加 IP 端口规则
	err = mockMgr.AddIPPortRule("172.16.0.1/32", 8080, 1) // Allow
	assert.NoError(t, err)

	err = mockMgr.AddIPPortRule("172.16.0.2/32", 9090, 0) // Deny
	assert.NoError(t, err)

	rules, count, err := mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Len(t, rules, 2)

	// Step 5: Add allowed ports
	// 步骤 5：添加允许端口
	err = mockMgr.AllowPort(80)
	assert.NoError(t, err)

	err = mockMgr.AllowPort(443)
	assert.NoError(t, err)

	ports, err := mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	assert.Len(t, ports, 2)

	// Step 6: Add rate limit rules
	// 步骤 6：添加速率限制规则
	err = mockMgr.AddRateLimitRule("192.168.100.0/24", 1000, 2000)
	assert.NoError(t, err)

	rateRules, count, err := mockMgr.ListRateLimitRules(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Contains(t, rateRules, "192.168.100.0/24")

	// Step 7: Verify all operations
	// 步骤 7：验证所有操作
	blacklisted, err := mockMgr.IsIPInBlacklist("192.168.1.100/32")
	assert.NoError(t, err)
	assert.True(t, blacklisted)

	whitelisted, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, whitelisted)

	// Step 8: Remove and verify
	// 步骤 8：移除并验证
	err = mockMgr.RemoveBlacklistIP("192.168.1.100/32")
	assert.NoError(t, err)

	blacklisted, err = mockMgr.IsIPInBlacklist("192.168.1.100/32")
	assert.NoError(t, err)
	assert.False(t, blacklisted)

	// Step 9: Clear all
	// 步骤 9：清除所有
	err = mockMgr.ClearBlacklist()
	assert.NoError(t, err)

	err = mockMgr.ClearWhitelist()
	assert.NoError(t, err)

	err = mockMgr.ClearIPPortRules()
	assert.NoError(t, err)

	err = mockMgr.ClearAllowedPorts()
	assert.NoError(t, err)

	err = mockMgr.ClearRateLimitRules()
	assert.NoError(t, err)

	// Verify all cleared
	// 验证所有已清除
	count, err = mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	count, err = mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestXDP_Integration_SyncOperations tests sync operations
// TestXDP_Integration_SyncOperations 测试同步操作
func TestXDP_Integration_SyncOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{
				"10.0.0.1/32",
				"10.0.0.2/32",
				"10.0.0.3/32",
			},
		},
	}

	// Test SyncFromFiles
	// 测试 SyncFromFiles
	err := mockMgr.SyncFromFiles(cfg, false)
	assert.NoError(t, err)

	count, err := mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 3, count)

	// Add extra IP and sync with overwrite
	// 添加额外 IP 并带覆盖同步
	_ = mockMgr.AddWhitelistIP("192.168.1.1/32", 0)

	err = mockMgr.SyncFromFiles(cfg, true)
	assert.NoError(t, err)

	count, err = mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 3, count)

	// Test VerifyAndRepair
	// 测试 VerifyAndRepair
	err = mockMgr.VerifyAndRepair(cfg)
	assert.NoError(t, err)

	// Test SyncToFiles
	// 测试 SyncToFiles
	_ = mockMgr.AddWhitelistIP("10.0.0.4/32", 0)

	newCfg := &types.GlobalConfig{
		Base: types.BaseConfig{},
	}

	err = mockMgr.SyncToFiles(newCfg)
	assert.NoError(t, err)
	assert.Len(t, newCfg.Base.Whitelist, 4)
}

// TestXDP_Integration_DynamicBlacklist tests dynamic blacklist operations
// TestXDP_Integration_DynamicBlacklist 测试动态黑名单操作
func TestXDP_Integration_DynamicBlacklist(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add dynamic blacklist IPs with TTL
	// 添加带 TTL 的动态黑名单 IP
	err := mockMgr.AddDynamicBlacklistIP("192.168.1.100", time.Hour)
	assert.NoError(t, err)

	err = mockMgr.AddDynamicBlacklistIP("192.168.1.101", 30*time.Minute)
	assert.NoError(t, err)

	// Verify they are in blacklist
	// 验证它们在黑名单中
	blacklisted, err := mockMgr.IsIPInBlacklist("192.168.1.100/32")
	assert.NoError(t, err)
	assert.True(t, blacklisted)

	blacklisted, err = mockMgr.IsIPInBlacklist("192.168.1.101/32")
	assert.NoError(t, err)
	assert.True(t, blacklisted)

	// List dynamic blacklist
	// 列出动态黑名单
	ips, count, err := mockMgr.ListDynamicBlacklistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count) // Mock returns empty
	assert.Nil(t, ips)
}

// TestXDP_Integration_StatsOperations tests stats operations
// TestXDP_Integration_StatsOperations 测试统计操作
func TestXDP_Integration_StatsOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add some data
	// 添加一些数据
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.2/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.3/32")
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	_ = mockMgr.AddWhitelistIP("10.0.0.2/32", 0)

	// Get stats
	// 获取统计
	lockedCount, err := mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 3, lockedCount)

	whitelistCount, err := mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.Equal(t, 2, whitelistCount)

	dropCount, err := mockMgr.GetDropCount()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), dropCount)

	passCount, err := mockMgr.GetPassCount()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), passCount)

	conntrackCount, err := mockMgr.GetConntrackCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, conntrackCount)

	// Get details
	// 获取详情
	dropDetails, err := mockMgr.GetDropDetails()
	assert.NoError(t, err)
	assert.Nil(t, dropDetails)

	passDetails, err := mockMgr.GetPassDetails()
	assert.NoError(t, err)
	assert.Nil(t, passDetails)

	conntrackEntries, err := mockMgr.ListAllConntrackEntries()
	assert.NoError(t, err)
	assert.Nil(t, conntrackEntries)
}

// TestXDP_Integration_SearchOperations tests search operations
// TestXDP_Integration_SearchOperations 测试搜索操作
func TestXDP_Integration_SearchOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add multiple IPs
	// 添加多个 IP
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.2/32")
	_ = mockMgr.AddBlacklistIP("192.168.2.1/32")
	_ = mockMgr.AddBlacklistIP("10.0.0.1/32")
	_ = mockMgr.AddBlacklistIP("10.0.0.2/32")

	// Search for 192.168.1.x
	// 搜索 192.168.1.x
	ips, count, err := mockMgr.ListBlacklistIPs(100, "192.168.1")
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Len(t, ips, 2)

	// Search for 10.0.0.x
	// 搜索 10.0.0.x
	ips, count, err = mockMgr.ListBlacklistIPs(100, "10.0.0")
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Len(t, ips, 2)

	// Search with no matches
	// 搜索无匹配
	ips, count, err = mockMgr.ListBlacklistIPs(100, "172.16")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, ips)
}

// TestXDP_Integration_IPNormalization tests IP normalization
// TestXDP_Integration_IPNormalization 测试 IP 规范化
func TestXDP_Integration_IPNormalization(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add IPs without CIDR notation
	// 添加不带 CIDR 表示法的 IP
	err := mockMgr.AddBlacklistIP("192.168.1.1")
	assert.NoError(t, err)

	err = mockMgr.AddWhitelistIP("10.0.0.1", 0)
	assert.NoError(t, err)

	// Verify they are normalized to /32
	// 验证它们被规范化为 /32
	blacklisted, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, blacklisted)

	whitelisted, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, whitelisted)

	// Verify original format also works
	// 验证原始格式也有效
	blacklisted, err = mockMgr.IsIPInBlacklist("192.168.1.1")
	assert.NoError(t, err)
	assert.True(t, blacklisted)
}

// TestXDP_Integration_Close tests Close operation
// TestXDP_Integration_Close 测试 Close 操作
func TestXDP_Integration_Close(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add some data
	// 添加一些数据
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	// Close should not error
	// Close 不应报错
	err := mockMgr.Close()
	assert.NoError(t, err)
}

// TestXDP_Integration_ContextCancellation tests context cancellation
// TestXDP_Integration_ContextCancellation 测试上下文取消
func TestXDP_Integration_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Simulate context cancellation
	// 模拟上下文取消
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	// Verify context is cancelled
	// 验证上下文已取消
	<-ctx.Done()
	assert.Error(t, ctx.Err())
}
