package xdp

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMockManager_SyncOperations_Extended tests sync operations
// TestMockManager_SyncOperations_Extended 测试同步操作
func TestMockManager_SyncOperations_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	// Verify that the mock manager was created successfully
	// 验证模拟管理器已成功创建
	assert.NotNil(t, mockMgr)
}

// TestMockManager_ConfigurationMethods_Extended tests all configuration methods
// TestMockManager_ConfigurationMethods_Extended 测试所有配置方法
func TestMockManager_ConfigurationMethods_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	// Test SetDefaultDeny
	// 测试 SetDefaultDeny
	err := mockMgr.SetDefaultDeny(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DefaultDeny)

	// Test SetStrictTCP
	// 测试 SetStrictTCP
	err = mockMgr.SetStrictTCP(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.StrictTCP)

	// Test SetSYNLimit
	// 测试 SetSYNLimit
	err = mockMgr.SetSYNLimit(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.SYNLimit)

	// Test SetBogonFilter
	// 测试 SetBogonFilter
	err = mockMgr.SetBogonFilter(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.BogonFilter)

	// Test SetEnableAFXDP
	// 测试 SetEnableAFXDP
	err = mockMgr.SetEnableAFXDP(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableAFXDP)

	// Test SetEnableRateLimit
	// 测试 SetEnableRateLimit
	err = mockMgr.SetEnableRateLimit(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableRateLimit)

	// Test SetDropFragments
	// 测试 SetDropFragments
	err = mockMgr.SetDropFragments(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DropFragments)

	// Test SetAutoBlock
	// 测试 SetAutoBlock
	err = mockMgr.SetAutoBlock(true)
	assert.NoError(t, err)

	// Test SetAutoBlockExpiry
	// 测试 SetAutoBlockExpiry
	err = mockMgr.SetAutoBlockExpiry(time.Hour)
	assert.NoError(t, err)

	// Test SetConntrack
	// 测试 SetConntrack
	err = mockMgr.SetConntrack(true)
	assert.NoError(t, err)

	// Test SetConntrackTimeout
	// 测试 SetConntrackTimeout
	err = mockMgr.SetConntrackTimeout(time.Minute * 30)
	assert.NoError(t, err)

	// Test SetAllowReturnTraffic
	// 测试 SetAllowReturnTraffic
	err = mockMgr.SetAllowReturnTraffic(true)
	assert.NoError(t, err)

	// Test SetAllowICMP
	// 测试 SetAllowICMP
	err = mockMgr.SetAllowICMP(true)
	assert.NoError(t, err)

	// Test SetStrictProtocol
	// 测试 SetStrictProtocol
	err = mockMgr.SetStrictProtocol(true)
	assert.NoError(t, err)

	// Test SetICMPRateLimit
	// 测试 SetICMPRateLimit
	err = mockMgr.SetICMPRateLimit(100, 200)
	assert.NoError(t, err)
}

// TestMockManager_BlacklistOperations_Extended tests blacklist operations
// TestMockManager_BlacklistOperations_Extended 测试黑名单操作
func TestMockManager_BlacklistOperations_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddBlacklistIP
	// 测试 AddBlacklistIP
	err := mockMgr.AddBlacklistIP("192.168.1.1/32")
	require.NoError(t, err)

	// Test IsIPInBlacklist
	// 测试 IsIPInBlacklist
	contains, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	require.NoError(t, err)
	assert.True(t, contains)

	// Test ListBlacklistIPs
	// 测试 ListBlacklistIPs
	ips, count, err := mockMgr.ListBlacklistIPs(100, "")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, ips, 1)

	// Test RemoveBlacklistIP
	// 测试 RemoveBlacklistIP
	err = mockMgr.RemoveBlacklistIP("192.168.1.1/32")
	require.NoError(t, err)

	contains, err = mockMgr.IsIPInBlacklist("192.168.1.1/32")
	require.NoError(t, err)
	assert.False(t, contains)

	// Test ClearBlacklist
	// 测试 ClearBlacklist
	_ = mockMgr.AddBlacklistIP("192.168.1.2/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.3/32")

	err = mockMgr.ClearBlacklist()
	require.NoError(t, err)

	_, count, err = mockMgr.ListBlacklistIPs(100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_WhitelistOperations_Extended tests whitelist operations
// TestMockManager_WhitelistOperations_Extended 测试白名单操作
func TestMockManager_WhitelistOperations_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddWhitelistIP
	// 测试 AddWhitelistIP
	err := mockMgr.AddWhitelistIP("10.0.0.1/32", 80)
	require.NoError(t, err)

	// Test IsIPInWhitelist
	// 测试 IsIPInWhitelist
	contains, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	require.NoError(t, err)
	assert.True(t, contains)

	// Test ListWhitelistIPs
	// 测试 ListWhitelistIPs
	ips, count, err := mockMgr.ListWhitelistIPs(100, "")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, ips, 1)

	// Test RemoveWhitelistIP
	// 测试 RemoveWhitelistIP
	err = mockMgr.RemoveWhitelistIP("10.0.0.1/32")
	require.NoError(t, err)

	contains, err = mockMgr.IsIPInWhitelist("10.0.0.1/32")
	require.NoError(t, err)
	assert.False(t, contains)

	// Test ClearWhitelist
	// 测试 ClearWhitelist
	_ = mockMgr.AddWhitelistIP("10.0.0.2/32", 443)

	err = mockMgr.ClearWhitelist()
	require.NoError(t, err)

	_, count, err = mockMgr.ListWhitelistIPs(100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_IPPortRuleOperations_Extended tests IP port rule operations
// TestMockManager_IPPortRuleOperations_Extended 测试 IP 端口规则操作
func TestMockManager_IPPortRuleOperations_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddIPPortRule
	// 测试 AddIPPortRule
	err := mockMgr.AddIPPortRule("172.16.0.1/32", 8080, 1)
	require.NoError(t, err)

	// Test ListIPPortRules
	// 测试 ListIPPortRules
	rules, count, err := mockMgr.ListIPPortRules(false, 100, "")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, rules, 1)

	// Test RemoveIPPortRule
	// 测试 RemoveIPPortRule
	err = mockMgr.RemoveIPPortRule("172.16.0.1/32", 8080)
	require.NoError(t, err)

	// Test ClearIPPortRules
	// 测试 ClearIPPortRules
	_ = mockMgr.AddIPPortRule("172.16.0.2/32", 9090, 0)

	err = mockMgr.ClearIPPortRules()
	require.NoError(t, err)

	_, count, err = mockMgr.ListIPPortRules(false, 100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_AllowedPortsOperations_Extended tests allowed ports operations
// TestMockManager_AllowedPortsOperations_Extended 测试允许端口操作
func TestMockManager_AllowedPortsOperations_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AllowPort
	// 测试 AllowPort
	err := mockMgr.AllowPort(443)
	require.NoError(t, err)

	// Test ListAllowedPorts
	// 测试 ListAllowedPorts
	ports, err := mockMgr.ListAllowedPorts()
	require.NoError(t, err)
	assert.Len(t, ports, 1)
	assert.Contains(t, ports, uint16(443))

	// Test RemoveAllowedPort
	// 测试 RemoveAllowedPort
	err = mockMgr.RemoveAllowedPort(443)
	require.NoError(t, err)

	ports, err = mockMgr.ListAllowedPorts()
	require.NoError(t, err)
	assert.Empty(t, ports)

	// Test ClearAllowedPorts
	// 测试 ClearAllowedPorts
	_ = mockMgr.AllowPort(80)

	err = mockMgr.ClearAllowedPorts()
	require.NoError(t, err)

	ports, err = mockMgr.ListAllowedPorts()
	require.NoError(t, err)
	assert.Empty(t, ports)
}

// TestMockManager_RateLimitOperations_Extended tests rate limit operations
// TestMockManager_RateLimitOperations_Extended 测试速率限制操作
func TestMockManager_RateLimitOperations_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddRateLimitRule
	// 测试 AddRateLimitRule
	err := mockMgr.AddRateLimitRule("192.168.100.0/24", 1000, 2000)
	require.NoError(t, err)

	// Test ListRateLimitRules
	// 测试 ListRateLimitRules
	rules, count, err := mockMgr.ListRateLimitRules(100, "")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, rules, 1)

	// Test RemoveRateLimitRule
	// 测试 RemoveRateLimitRule
	err = mockMgr.RemoveRateLimitRule("192.168.100.0/24")
	require.NoError(t, err)

	_, count, err = mockMgr.ListRateLimitRules(100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	// Test ClearRateLimitRules
	// 测试 ClearRateLimitRules
	_ = mockMgr.AddRateLimitRule("10.10.0.0/16", 500, 1000)

	err = mockMgr.ClearRateLimitRules()
	require.NoError(t, err)

	_, count, err = mockMgr.ListRateLimitRules(100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_Stats_Extended tests stats operations
// TestMockManager_Stats_Extended 测试统计操作
func TestMockManager_Stats_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	// Test GetDropCount
	// 测试 GetDropCount
	dropCount, err := mockMgr.GetDropCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), dropCount)

	// Test GetPassCount
	// 测试 GetPassCount
	passCount, err := mockMgr.GetPassCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), passCount)

	// Test GetLockedIPCount
	// 测试 GetLockedIPCount
	lockedCount, err := mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 0, lockedCount)

	// Add some IPs and test count
	// 添加一些 IP 并测试计数
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddBlacklistIP("192.168.1.2/32")

	lockedCount, err = mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 2, lockedCount)

	// Test GetWhitelistCount
	// 测试 GetWhitelistCount
	whitelistCount, err := mockMgr.GetWhitelistCount()
	require.NoError(t, err)
	assert.Equal(t, 0, whitelistCount)

	// Add some whitelist IPs and test count
	// 添加一些白名单 IP 并测试计数
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	whitelistCount, err = mockMgr.GetWhitelistCount()
	require.NoError(t, err)
	assert.Equal(t, 1, whitelistCount)

	// Test GetConntrackCount
	// 测试 GetConntrackCount
	conntrackCount, err := mockMgr.GetConntrackCount()
	require.NoError(t, err)
	assert.Equal(t, 0, conntrackCount)
}

// TestTableDriven_BlacklistIPs tests blacklist with table-driven tests
// TestTableDriven_BlacklistIPs 测试黑名单使用表驱动测试
func TestTableDriven_BlacklistIPs(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"valid_ipv4", "192.168.1.1/32", true},
		{"valid_ipv4_no_cidr", "192.168.1.2", true},
		{"valid_cidr", "10.0.0.0/8", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockMgr := NewMockManager()
			err := mockMgr.AddBlacklistIP(tc.ip)
			if tc.expected {
				assert.NoError(t, err)
			}
		})
	}
}

// TestTableDriven_WhitelistIPs tests whitelist with table-driven tests
// TestTableDriven_WhitelistIPs 测试白名单使用表驱动测试
func TestTableDriven_WhitelistIPs(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		port     uint16
		expected bool
	}{
		{"valid_ipv4_port_80", "192.168.1.1/32", 80, true},
		{"valid_ipv4_port_443", "192.168.1.2/32", 443, true},
		{"valid_ipv4_no_port", "192.168.1.3/32", 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockMgr := NewMockManager()
			err := mockMgr.AddWhitelistIP(tc.ip, tc.port)
			if tc.expected {
				assert.NoError(t, err)
			}
		})
	}
}

// TestTableDriven_RateLimitRules tests rate limit with table-driven tests
// TestTableDriven_RateLimitRules 测试速率限制使用表驱动测试
func TestTableDriven_RateLimitRules(t *testing.T) {
	testCases := []struct {
		name    string
		cidr    string
		rate    uint64
		burst   uint64
		wantErr bool
	}{
		{"valid_ipv4", "192.168.1.0/24", 1000, 2000, false},
		{"valid_large_network", "10.0.0.0/8", 500, 1000, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockMgr := NewMockManager()
			err := mockMgr.AddRateLimitRule(tc.cidr, tc.rate, tc.burst)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestTableDriven_Configuration tests configuration with table-driven tests
// TestTableDriven_Configuration 测试配置使用表驱动测试
func TestTableDriven_Configuration(t *testing.T) {
	testCases := []struct {
		name    string
		setFunc func(*MockManager) error
	}{
		{"SetDefaultDeny", func(m *MockManager) error { return m.SetDefaultDeny(true) }},
		{"SetStrictTCP", func(m *MockManager) error { return m.SetStrictTCP(true) }},
		{"SetSYNLimit", func(m *MockManager) error { return m.SetSYNLimit(true) }},
		{"SetBogonFilter", func(m *MockManager) error { return m.SetBogonFilter(true) }},
		{"SetEnableAFXDP", func(m *MockManager) error { return m.SetEnableAFXDP(true) }},
		{"SetEnableRateLimit", func(m *MockManager) error { return m.SetEnableRateLimit(true) }},
		{"SetDropFragments", func(m *MockManager) error { return m.SetDropFragments(true) }},
		{"SetAutoBlock", func(m *MockManager) error { return m.SetAutoBlock(true) }},
		{"SetConntrack", func(m *MockManager) error { return m.SetConntrack(true) }},
		{"SetAllowReturnTraffic", func(m *MockManager) error { return m.SetAllowReturnTraffic(true) }},
		{"SetAllowICMP", func(m *MockManager) error { return m.SetAllowICMP(true) }},
		{"SetStrictProtocol", func(m *MockManager) error { return m.SetStrictProtocol(true) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockMgr := NewMockManager()
			err := tc.setFunc(mockMgr)
			assert.NoError(t, err)
		})
	}
}

// TestMockManager_SyncFromFiles_Extended tests SyncFromFiles method
// TestMockManager_SyncFromFiles_Extended 测试 SyncFromFiles 方法
func TestMockManager_SyncFromFiles_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
	}

	err := mockMgr.SyncFromFiles(cfg, false)
	assert.NoError(t, err)

	// Verify whitelist was synced (check the actual CIDR that was added)
	// 验证白名单已同步（检查实际添加的 CIDR）
	contains, err := mockMgr.IsIPInWhitelist("10.0.0.0/8")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestMockManager_SyncToFiles_Extended tests SyncToFiles method
// TestMockManager_SyncToFiles_Extended 测试 SyncToFiles 方法
func TestMockManager_SyncToFiles_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	_ = mockMgr.AddWhitelistIP("192.168.1.1/32", 0)

	cfg := &types.GlobalConfig{}

	err := mockMgr.SyncToFiles(cfg)
	assert.NoError(t, err)
	assert.Len(t, cfg.Base.Whitelist, 2)
}

// TestMockManager_VerifyAndRepair_Extended tests VerifyAndRepair method
// TestMockManager_VerifyAndRepair_Extended 测试 VerifyAndRepair 方法
func TestMockManager_VerifyAndRepair_Extended(t *testing.T) {
	mockMgr := NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{"10.0.0.0/8"},
		},
	}

	err := mockMgr.VerifyAndRepair(cfg)
	assert.NoError(t, err)
}
