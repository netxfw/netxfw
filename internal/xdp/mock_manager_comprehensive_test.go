package xdp

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMockManager_Comprehensive tests MockManager comprehensive operations
// TestMockManager_Comprehensive 测试 MockManager 综合操作
func TestMockManager_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()
	require.NotNil(t, mockMgr)

	// Test all configuration methods
	// 测试所有配置方法
	configTests := []struct {
		name  string
		setFn func() error
		check func() bool
	}{
		{"SetDefaultDeny", func() error { return mockMgr.SetDefaultDeny(true) }, func() bool { return mockMgr.DefaultDeny }},
		{"SetStrictTCP", func() error { return mockMgr.SetStrictTCP(true) }, func() bool { return mockMgr.StrictTCP }},
		{"SetSYNLimit", func() error { return mockMgr.SetSYNLimit(true) }, func() bool { return mockMgr.SYNLimit }},
		{"SetBogonFilter", func() error { return mockMgr.SetBogonFilter(true) }, func() bool { return mockMgr.BogonFilter }},
		{"SetEnableAFXDP", func() error { return mockMgr.SetEnableAFXDP(true) }, func() bool { return mockMgr.EnableAFXDP }},
		{"SetEnableRateLimit", func() error { return mockMgr.SetEnableRateLimit(true) }, func() bool { return mockMgr.EnableRateLimit }},
		{"SetDropFragments", func() error { return mockMgr.SetDropFragments(true) }, func() bool { return mockMgr.DropFragments }},
	}

	for _, tc := range configTests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.setFn()
			require.NoError(t, err)
			assert.True(t, tc.check())
		})
	}
}

// TestMockManager_BlacklistComprehensive tests comprehensive blacklist operations
// TestMockManager_BlacklistComprehensive 测试综合黑名单操作
func TestMockManager_BlacklistComprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// Test adding multiple IPs
	// 测试添加多个 IP
	ips := []string{
		"192.168.1.1/32",
		"192.168.1.2/32",
		"10.0.0.0/8",
		"172.16.0.0/16",
	}

	for _, ip := range ips {
		err := mockMgr.AddBlacklistIP(ip)
		require.NoError(t, err)
	}

	// Verify all IPs are in blacklist
	// 验证所有 IP 都在黑名单中
	for _, ip := range ips {
		contains, err := mockMgr.IsIPInBlacklist(ip)
		require.NoError(t, err)
		assert.True(t, contains)
	}

	// Test listing with limit (MockManager returns all entries regardless of limit)
	// 测试使用限制列出（MockManager 返回所有条目，忽略限制）
	list, count, err := mockMgr.ListBlacklistIPs(2, "")
	require.NoError(t, err)
	assert.Equal(t, 4, count)
	assert.Len(t, list, 4) // MockManager returns all entries

	// Test search
	// 测试搜索
	_, searchCount, err := mockMgr.ListBlacklistIPs(100, "192.168")
	require.NoError(t, err)
	assert.Equal(t, 2, searchCount)

	// Test remove
	// 测试删除
	err = mockMgr.RemoveBlacklistIP("192.168.1.1/32")
	require.NoError(t, err)

	contains, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	require.NoError(t, err)
	assert.False(t, contains)

	// Test clear
	// 测试清除
	err = mockMgr.ClearBlacklist()
	require.NoError(t, err)

	_, count, err = mockMgr.ListBlacklistIPs(100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_WhitelistComprehensive tests comprehensive whitelist operations
// TestMockManager_WhitelistComprehensive 测试综合白名单操作
func TestMockManager_WhitelistComprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// Test adding with different ports
	// 测试使用不同端口添加
	testCases := []struct {
		ip   string
		port uint16
	}{
		{"10.0.0.1/32", 80},
		{"10.0.0.2/32", 443},
		{"192.168.0.0/16", 0},
		{"172.16.0.0/12", 8080},
	}

	for _, tc := range testCases {
		err := mockMgr.AddWhitelistIP(tc.ip, tc.port)
		require.NoError(t, err)
	}

	// Verify all IPs are in whitelist
	// 验证所有 IP 都在白名单中
	for _, tc := range testCases {
		contains, err := mockMgr.IsIPInWhitelist(tc.ip)
		require.NoError(t, err)
		assert.True(t, contains)
	}

	// Test listing
	// 测试列出
	_, count, err := mockMgr.ListWhitelistIPs(100, "")
	require.NoError(t, err)
	assert.Equal(t, 4, count)

	// Test search
	// 测试搜索
	_, searchCount, err := mockMgr.ListWhitelistIPs(100, "10.0")
	require.NoError(t, err)
	assert.Equal(t, 2, searchCount)

	// Test remove
	// 测试删除
	err = mockMgr.RemoveWhitelistIP("10.0.0.1/32")
	require.NoError(t, err)

	// Test clear
	// 测试清除
	err = mockMgr.ClearWhitelist()
	require.NoError(t, err)

	_, count, err = mockMgr.ListWhitelistIPs(100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_IPPortRulesComprehensive tests comprehensive IP port rules
// TestMockManager_IPPortRulesComprehensive 测试综合 IP 端口规则
func TestMockManager_IPPortRulesComprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// Test adding rules with different actions
	// 测试使用不同操作添加规则
	rules := []struct {
		ip     string
		port   uint16
		action uint8
	}{
		{"192.168.1.1/32", 80, 1},
		{"192.168.1.2/32", 443, 0},
		{"10.0.0.1/32", 8080, 1},
	}

	for _, r := range rules {
		err := mockMgr.AddIPPortRule(r.ip, r.port, r.action)
		require.NoError(t, err)
	}

	// Test listing
	// 测试列出
	list, count, err := mockMgr.ListIPPortRules(false, 100, "")
	require.NoError(t, err)
	assert.Equal(t, 3, count)
	assert.Len(t, list, 3)

	// Test remove
	// 测试删除
	err = mockMgr.RemoveIPPortRule("192.168.1.1/32", 80)
	require.NoError(t, err)

	// Test clear
	// 测试清除
	err = mockMgr.ClearIPPortRules()
	require.NoError(t, err)

	_, count, err = mockMgr.ListIPPortRules(false, 100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_AllowedPortsComprehensive tests comprehensive allowed ports
// TestMockManager_AllowedPortsComprehensive 测试综合允许端口
func TestMockManager_AllowedPortsComprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// Test adding multiple ports
	// 测试添加多个端口
	ports := []uint16{22, 80, 443, 8080, 8443}

	for _, port := range ports {
		err := mockMgr.AllowPort(port)
		require.NoError(t, err)
	}

	// Test listing
	// 测试列出
	list, err := mockMgr.ListAllowedPorts()
	require.NoError(t, err)
	assert.Len(t, list, 5)

	// Test remove
	// 测试删除
	err = mockMgr.RemoveAllowedPort(22)
	require.NoError(t, err)

	list, err = mockMgr.ListAllowedPorts()
	require.NoError(t, err)
	assert.Len(t, list, 4)

	// Test clear
	// 测试清除
	err = mockMgr.ClearAllowedPorts()
	require.NoError(t, err)

	list, err = mockMgr.ListAllowedPorts()
	require.NoError(t, err)
	assert.Empty(t, list)
}

// TestMockManager_RateLimitComprehensive tests comprehensive rate limit rules
// TestMockManager_RateLimitComprehensive 测试综合速率限制规则
func TestMockManager_RateLimitComprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// Test adding multiple rules
	// 测试添加多个规则
	rules := []struct {
		cidr  string
		rate  uint64
		burst uint64
	}{
		{"192.168.1.0/24", 1000, 2000},
		{"10.0.0.0/8", 500, 1000},
		{"172.16.0.0/16", 2000, 4000},
	}

	for _, r := range rules {
		err := mockMgr.AddRateLimitRule(r.cidr, r.rate, r.burst)
		require.NoError(t, err)
	}

	// Test listing
	// 测试列出
	list, count, err := mockMgr.ListRateLimitRules(100, "")
	require.NoError(t, err)
	assert.Equal(t, 3, count)
	assert.Len(t, list, 3)

	// Verify specific rule
	// 验证特定规则
	assert.Contains(t, list, "192.168.1.0/24")
	assert.Equal(t, uint64(1000), list["192.168.1.0/24"].Rate)
	assert.Equal(t, uint64(2000), list["192.168.1.0/24"].Burst)

	// Test remove
	// 测试删除
	err = mockMgr.RemoveRateLimitRule("192.168.1.0/24")
	require.NoError(t, err)

	_, count, err = mockMgr.ListRateLimitRules(100, "")
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Test clear
	// 测试清除
	err = mockMgr.ClearRateLimitRules()
	require.NoError(t, err)

	_, count, err = mockMgr.ListRateLimitRules(100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_StatsComprehensive tests comprehensive stats operations
// TestMockManager_StatsComprehensive 测试综合统计操作
func TestMockManager_StatsComprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// Test initial stats
	// 测试初始统计
	dropCount, err := mockMgr.GetDropCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), dropCount)

	passCount, err := mockMgr.GetPassCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), passCount)

	lockedCount, err := mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 0, lockedCount)

	whitelistCount, err := mockMgr.GetWhitelistCount()
	require.NoError(t, err)
	assert.Equal(t, 0, whitelistCount)

	conntrackCount, err := mockMgr.GetConntrackCount()
	require.NoError(t, err)
	assert.Equal(t, 0, conntrackCount)

	// Add some entries and verify counts
	// 添加一些条目并验证计数
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.2/32")
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 80)

	lockedCount, err = mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 2, lockedCount)

	whitelistCount, err = mockMgr.GetWhitelistCount()
	require.NoError(t, err)
	assert.Equal(t, 1, whitelistCount)

	// Test drop/pass details
	// 测试丢弃/通过详情
	dropDetails, err := mockMgr.GetDropDetails()
	require.NoError(t, err)
	assert.Nil(t, dropDetails)

	passDetails, err := mockMgr.GetPassDetails()
	require.NoError(t, err)
	assert.Nil(t, passDetails)

	// Test conntrack entries
	// 测试连接跟踪条目
	conntrackEntries, err := mockMgr.ListAllConntrackEntries()
	require.NoError(t, err)
	assert.Nil(t, conntrackEntries)
}

// TestMockManager_SyncOperationsComprehensive tests comprehensive sync operations
// TestMockManager_SyncOperationsComprehensive 测试综合同步操作
func TestMockManager_SyncOperationsComprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
	}

	// Test SyncFromFiles without overwrite
	// 测试 SyncFromFiles 不覆盖
	err := mockMgr.SyncFromFiles(cfg, false)
	require.NoError(t, err)

	// Verify whitelist was synced
	// 验证白名单已同步
	contains, err := mockMgr.IsIPInWhitelist("10.0.0.0/8")
	require.NoError(t, err)
	assert.True(t, contains)

	// Add an extra entry
	// 添加额外条目
	_ = mockMgr.AddWhitelistIP("172.16.0.0/12", 0)

	// Test SyncFromFiles with overwrite
	// 测试 SyncFromFiles 覆盖
	err = mockMgr.SyncFromFiles(cfg, true)
	require.NoError(t, err)

	// Verify only config entries exist
	// 验证只有配置条目存在
	contains, err = mockMgr.IsIPInWhitelist("172.16.0.0/12")
	require.NoError(t, err)
	assert.False(t, contains)

	// Test SyncToFiles
	// 测试 SyncToFiles
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	err = mockMgr.SyncToFiles(cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, cfg.Base.Whitelist)

	// Test VerifyAndRepair
	// 测试 VerifyAndRepair
	err = mockMgr.VerifyAndRepair(cfg)
	require.NoError(t, err)
}

// TestMockManager_DynamicBlacklistExtended tests dynamic blacklist operations
// TestMockManager_DynamicBlacklistExtended 测试动态黑名单操作
func TestMockManager_DynamicBlacklistExtended(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddDynamicBlacklistIP with TTL
	// 测试 AddDynamicBlacklistIP 使用 TTL
	err := mockMgr.AddDynamicBlacklistIP("192.168.1.1/32", time.Hour)
	require.NoError(t, err)

	// Test AddDynamicBlacklistIP without CIDR
	// 测试 AddDynamicBlacklistIP 不使用 CIDR
	err = mockMgr.AddDynamicBlacklistIP("192.168.1.2", time.Minute*30)
	require.NoError(t, err)

	// Verify IPs are in blacklist
	// 验证 IP 在黑名单中
	contains, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	require.NoError(t, err)
	assert.True(t, contains)

	contains, err = mockMgr.IsIPInBlacklist("192.168.1.2/32")
	require.NoError(t, err)
	assert.True(t, contains)

	// Test ListDynamicBlacklistIPs
	// 测试 ListDynamicBlacklistIPs
	_, count, err := mockMgr.ListDynamicBlacklistIPs(100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count) // Mock returns empty for dynamic list
}

// TestMockManager_AdvancedConfig tests advanced configuration methods
// TestMockManager_AdvancedConfig 测试高级配置方法
func TestMockManager_AdvancedConfig(t *testing.T) {
	mockMgr := NewMockManager()

	// Test SetAutoBlock
	// 测试 SetAutoBlock
	err := mockMgr.SetAutoBlock(true)
	require.NoError(t, err)

	// Test SetAutoBlockExpiry
	// 测试 SetAutoBlockExpiry
	err = mockMgr.SetAutoBlockExpiry(time.Hour)
	require.NoError(t, err)

	// Test SetConntrack
	// 测试 SetConntrack
	err = mockMgr.SetConntrack(true)
	require.NoError(t, err)

	// Test SetConntrackTimeout
	// 测试 SetConntrackTimeout
	err = mockMgr.SetConntrackTimeout(time.Minute * 30)
	require.NoError(t, err)

	// Test SetAllowReturnTraffic
	// 测试 SetAllowReturnTraffic
	err = mockMgr.SetAllowReturnTraffic(true)
	require.NoError(t, err)

	// Test SetAllowICMP
	// 测试 SetAllowICMP
	err = mockMgr.SetAllowICMP(true)
	require.NoError(t, err)

	// Test SetStrictProtocol
	// 测试 SetStrictProtocol
	err = mockMgr.SetStrictProtocol(true)
	require.NoError(t, err)

	// Test SetICMPRateLimit
	// 测试 SetICMPRateLimit
	err = mockMgr.SetICMPRateLimit(100, 200)
	require.NoError(t, err)
}

// TestMockManager_CloseExtended tests Close method
// TestMockManager_CloseExtended 测试 Close 方法
func TestMockManager_CloseExtended(t *testing.T) {
	mockMgr := NewMockManager()

	// Add some data
	// 添加一些数据
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 80)

	// Close should not error
	// Close 不应该出错
	err := mockMgr.Close()
	require.NoError(t, err)
}

// TestMockManager_IPNormalizationExtended tests IP normalization
// TestMockManager_IPNormalizationExtended 测试 IP 规范化
func TestMockManager_IPNormalizationExtended(t *testing.T) {
	mockMgr := NewMockManager()

	// Test adding IP without CIDR
	// 测试添加不带 CIDR 的 IP
	err := mockMgr.AddBlacklistIP("192.168.1.1")
	require.NoError(t, err)

	// Should be normalized to /32
	// 应该规范化为 /32
	contains, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	require.NoError(t, err)
	assert.True(t, contains)

	// Test whitelist IP normalization
	// 测试白名单 IP 规范化
	err = mockMgr.AddWhitelistIP("10.0.0.1", 80)
	require.NoError(t, err)

	contains, err = mockMgr.IsIPInWhitelist("10.0.0.1/32")
	require.NoError(t, err)
	assert.True(t, contains)
}
