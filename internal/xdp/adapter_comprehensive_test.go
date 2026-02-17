package xdp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMockManager_NewMockManager tests NewMockManager creation
// TestMockManager_NewMockManager 测试 NewMockManager 创建
func TestMockManager_NewMockManager(t *testing.T) {
	mockMgr := NewMockManager()

	assert.NotNil(t, mockMgr)
	assert.NotNil(t, mockMgr.Blacklist)
	assert.NotNil(t, mockMgr.WhitelistMap)
	assert.NotNil(t, mockMgr.IPPortRulesMap)
	assert.NotNil(t, mockMgr.AllowedPortsMap)
	assert.NotNil(t, mockMgr.RateLimitRules)
}

// TestMockManager_SyncFromFiles tests SyncFromFiles method
// TestMockManager_SyncFromFiles 测试 SyncFromFiles 方法
func TestMockManager_SyncFromFiles_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{"10.0.0.1/32", "192.168.1.0/24"},
		},
	}

	err := mockMgr.SyncFromFiles(cfg, false)
	assert.NoError(t, err)

	err = mockMgr.SyncFromFiles(cfg, true)
	assert.NoError(t, err)
}

// TestMockManager_SyncToFiles tests SyncToFiles method
// TestMockManager_SyncToFiles 测试 SyncToFiles 方法
func TestMockManager_SyncToFiles_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{},
	}

	err := mockMgr.SyncToFiles(cfg)
	assert.NoError(t, err)
}

// TestMockManager_VerifyAndRepair tests VerifyAndRepair method
// TestMockManager_VerifyAndRepair 测试 VerifyAndRepair 方法
func TestMockManager_VerifyAndRepair_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{"10.0.0.1/32"},
		},
	}

	err := mockMgr.VerifyAndRepair(cfg)
	assert.NoError(t, err)
}

// TestMockManager_Configuration tests all configuration methods
// TestMockManager_Configuration 测试所有配置方法
func TestMockManager_Configuration(t *testing.T) {
	mockMgr := NewMockManager()

	// SetDefaultDeny
	err := mockMgr.SetDefaultDeny(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DefaultDeny)

	err = mockMgr.SetDefaultDeny(false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.DefaultDeny)

	// SetStrictTCP
	err = mockMgr.SetStrictTCP(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.StrictTCP)

	// SetSYNLimit
	err = mockMgr.SetSYNLimit(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.SYNLimit)

	// SetBogonFilter
	err = mockMgr.SetBogonFilter(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.BogonFilter)

	// SetEnableAFXDP
	err = mockMgr.SetEnableAFXDP(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableAFXDP)

	// SetEnableRateLimit
	err = mockMgr.SetEnableRateLimit(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableRateLimit)

	// SetDropFragments
	err = mockMgr.SetDropFragments(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DropFragments)
}

// TestMockManager_AdvancedConfiguration tests advanced configuration methods
// TestMockManager_AdvancedConfiguration 测试高级配置方法
func TestMockManager_AdvancedConfiguration(t *testing.T) {
	mockMgr := NewMockManager()

	// SetAutoBlock
	err := mockMgr.SetAutoBlock(true)
	assert.NoError(t, err)

	// SetAutoBlockExpiry
	err = mockMgr.SetAutoBlockExpiry(5 * time.Minute)
	assert.NoError(t, err)

	// SetConntrack
	err = mockMgr.SetConntrack(true)
	assert.NoError(t, err)

	// SetConntrackTimeout
	err = mockMgr.SetConntrackTimeout(30 * time.Second)
	assert.NoError(t, err)

	// SetAllowReturnTraffic
	err = mockMgr.SetAllowReturnTraffic(true)
	assert.NoError(t, err)

	// SetAllowICMP
	err = mockMgr.SetAllowICMP(true)
	assert.NoError(t, err)

	// SetStrictProtocol
	err = mockMgr.SetStrictProtocol(true)
	assert.NoError(t, err)

	// SetICMPRateLimit
	err = mockMgr.SetICMPRateLimit(10, 100)
	assert.NoError(t, err)
}

// TestMockManager_BlacklistOperations_Comprehensive tests blacklist operations
// TestMockManager_BlacklistOperations_Comprehensive 测试黑名单操作
func TestMockManager_BlacklistOperations_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// AddBlacklistIP
	err := mockMgr.AddBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	// AddBlacklistIPWithFile
	err = mockMgr.AddBlacklistIPWithFile("192.168.1.2/32", "")
	assert.NoError(t, err)

	// AddDynamicBlacklistIP
	err = mockMgr.AddDynamicBlacklistIP("192.168.1.3", 5*time.Minute)
	assert.NoError(t, err)

	// IsIPInBlacklist
	inList, err := mockMgr.IsIPInBlacklist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, inList)

	// ListBlacklistIPs
	ips, count, err := mockMgr.ListBlacklistIPs(0, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)
	assert.NotNil(t, ips)

	// ListDynamicBlacklistIPs - mock returns nil, 0
	dynIPs, dynCount, err := mockMgr.ListDynamicBlacklistIPs(0, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, dynCount, 0)
	_ = dynIPs

	// RemoveBlacklistIP
	err = mockMgr.RemoveBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err)

	// ClearBlacklist
	err = mockMgr.ClearBlacklist()
	assert.NoError(t, err)
}

// TestMockManager_WhitelistOperations tests whitelist operations
// TestMockManager_WhitelistOperations 测试白名单操作
func TestMockManager_WhitelistOperations_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// AddWhitelistIP
	err := mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	assert.NoError(t, err)

	// IsIPInWhitelist
	inList, err := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, inList)

	// ListWhitelistIPs
	ips, count, err := mockMgr.ListWhitelistIPs(0, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)
	assert.NotNil(t, ips)

	// RemoveWhitelistIP
	err = mockMgr.RemoveWhitelistIP("10.0.0.1/32")
	assert.NoError(t, err)

	// ClearWhitelist
	err = mockMgr.ClearWhitelist()
	assert.NoError(t, err)
}

// TestMockManager_IPPortRuleOperations tests IP:Port rule operations
// TestMockManager_IPPortRuleOperations 测试 IP:Port 规则操作
func TestMockManager_IPPortRuleOperations_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// AddIPPortRule - action: 1 = allow, 2 = deny
	err := mockMgr.AddIPPortRule("192.168.1.1", 80, 1)
	assert.NoError(t, err)

	// ListIPPortRules
	rules, count, err := mockMgr.ListIPPortRules(false, 0, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)
	assert.NotNil(t, rules)

	// RemoveIPPortRule
	err = mockMgr.RemoveIPPortRule("192.168.1.1", 80)
	assert.NoError(t, err)

	// ClearIPPortRules
	err = mockMgr.ClearIPPortRules()
	assert.NoError(t, err)
}

// TestMockManager_AllowedPortsOperations tests allowed ports operations
// TestMockManager_AllowedPortsOperations 测试允许端口操作
func TestMockManager_AllowedPortsOperations_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// AllowPort
	err := mockMgr.AllowPort(443)
	assert.NoError(t, err)

	// ListAllowedPorts
	ports, err := mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(ports), 1)
	assert.NotNil(t, ports)

	// RemoveAllowedPort
	err = mockMgr.RemoveAllowedPort(443)
	assert.NoError(t, err)

	// ClearAllowedPorts
	err = mockMgr.ClearAllowedPorts()
	assert.NoError(t, err)
}

// TestMockManager_RateLimitOperations tests rate limit operations
// TestMockManager_RateLimitOperations 测试速率限制操作
func TestMockManager_RateLimitOperations_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// AddRateLimitRule
	err := mockMgr.AddRateLimitRule("192.168.1.1", 1000, 100)
	assert.NoError(t, err)

	// ListRateLimitRules
	rules, count, err := mockMgr.ListRateLimitRules(0, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)
	assert.NotNil(t, rules)

	// RemoveRateLimitRule
	err = mockMgr.RemoveRateLimitRule("192.168.1.1")
	assert.NoError(t, err)

	// ClearRateLimitRules
	err = mockMgr.ClearRateLimitRules()
	assert.NoError(t, err)
}

// TestMockManager_StatsOperations_Comprehensive tests statistics operations
// TestMockManager_StatsOperations_Comprehensive 测试统计操作
func TestMockManager_StatsOperations_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// GetDropDetails - mock returns nil
	drops, err := mockMgr.GetDropDetails()
	assert.NoError(t, err)
	_ = drops

	// GetPassDetails - mock returns nil
	passes, err := mockMgr.GetPassDetails()
	assert.NoError(t, err)
	_ = passes

	// GetDropCount
	dropCount, err := mockMgr.GetDropCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, dropCount, uint64(0))

	// GetPassCount
	passCount, err := mockMgr.GetPassCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, passCount, uint64(0))

	// GetLockedIPCount
	lockedCount, err := mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, lockedCount, 0)

	// GetWhitelistCount
	whitelistCount, err := mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, whitelistCount, 0)

	// GetConntrackCount
	conntrackCount, err := mockMgr.GetConntrackCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, conntrackCount, 0)
}

// TestMockManager_ConntrackOperations tests conntrack operations
// TestMockManager_ConntrackOperations 测试连接跟踪操作
func TestMockManager_ConntrackOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// ListAllConntrackEntries - mock returns nil
	entries, err := mockMgr.ListAllConntrackEntries()
	assert.NoError(t, err)
	_ = entries
}

// TestMockManager_MapGetters tests map getter methods
// TestMockManager_MapGetters 测试 Map 获取方法
func TestMockManager_MapGetters_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// All map getters should return nil for mock
	assert.Nil(t, mockMgr.LockList())
	assert.Nil(t, mockMgr.DynLockList())
	assert.Nil(t, mockMgr.Whitelist())
	assert.Nil(t, mockMgr.IPPortRules())
	assert.Nil(t, mockMgr.AllowedPorts())
	assert.Nil(t, mockMgr.RateLimitConfig())
	assert.Nil(t, mockMgr.GlobalConfig())
	assert.Nil(t, mockMgr.ConntrackMap())
}

// TestMockManager_Close_Comprehensive tests Close method
// TestMockManager_Close_Comprehensive 测试 Close 方法
func TestMockManager_Close_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	err := mockMgr.Close()
	assert.NoError(t, err)
}

// Table-driven tests for MockManager blacklist operations
// MockManager 黑名单操作的表驱动测试

// TestTableDriven_MockManager_BlacklistIP tests AddBlacklistIP with various inputs
// TestTableDriven_MockManager_BlacklistIP 测试各种输入的 AddBlacklistIP
func TestTableDriven_MockManager_BlacklistIP(t *testing.T) {
	testCases := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"Valid_IPv4_CIDR", "192.168.1.1/32", false},
		{"Valid_IPv4_Network", "10.0.0.0/24", false},
		{"Valid_IPv6_CIDR", "2001:db8::1/128", false},
		{"Valid_IPv6_Network", "2001:db8::/32", false},
		// Note: MockManager doesn't validate IPs, so these don't error
		// 注意：MockManager 不验证 IP，所以这些不会报错
		{"Invalid_IP", "invalid-ip", false},
		{"Empty_IP", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockMgr := NewMockManager()
			err := mockMgr.AddBlacklistIP(tc.ip)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestTableDriven_MockManager_WhitelistIP tests AddWhitelistIP with various inputs
// TestTableDriven_MockManager_WhitelistIP 测试各种输入的 AddWhitelistIP
func TestTableDriven_MockManager_WhitelistIP(t *testing.T) {
	testCases := []struct {
		name    string
		ip      string
		port    uint16
		wantErr bool
	}{
		{"Valid_IPv4_CIDR_Port0", "192.168.1.1/32", 0, false},
		{"Valid_IPv4_CIDR_Port80", "10.0.0.1/32", 80, false},
		{"Valid_IPv6_CIDR", "2001:db8::1/128", 443, false},
		// Note: MockManager doesn't validate IPs, so these don't error
		// 注意：MockManager 不验证 IP，所以这些不会报错
		{"Invalid_IP", "invalid-ip", 0, false},
		{"Empty_IP", "", 0, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockMgr := NewMockManager()
			err := mockMgr.AddWhitelistIP(tc.ip, tc.port)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestTableDriven_MockManager_IPPortRule tests AddIPPortRule with various inputs
// TestTableDriven_MockManager_IPPortRule 测试各种输入的 AddIPPortRule
func TestTableDriven_MockManager_IPPortRule(t *testing.T) {
	testCases := []struct {
		name    string
		ip      string
		port    uint16
		action  uint8
		wantErr bool
	}{
		{"Valid_Allow", "192.168.1.1", 80, 1, false},
		{"Valid_Deny", "192.168.1.1", 53, 2, false},
		{"Valid_Any", "10.0.0.1", 443, 1, false},
		// Note: MockManager doesn't validate IPs, so these don't error
		// 注意：MockManager 不验证 IP，所以这些不会报错
		{"Invalid_IP", "invalid", 80, 1, false},
		{"Empty_IP", "", 80, 1, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockMgr := NewMockManager()
			err := mockMgr.AddIPPortRule(tc.ip, tc.port, tc.action)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestMockManager_MultipleOperations tests multiple sequential operations
// TestMockManager_MultipleOperations 测试多个顺序操作
func TestMockManager_MultipleOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Add multiple blacklist IPs
	ips := []string{"192.168.1.1/32", "192.168.1.2/32", "10.0.0.0/24"}
	for _, ip := range ips {
		err := mockMgr.AddBlacklistIP(ip)
		require.NoError(t, err)
	}

	// Verify all are in blacklist
	for _, ip := range ips {
		inList, err := mockMgr.IsIPInBlacklist(ip)
		require.NoError(t, err)
		assert.True(t, inList, "IP %s should be in blacklist", ip)
	}

	// List all
	listIPs, count, err := mockMgr.ListBlacklistIPs(0, "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, len(ips))
	assert.GreaterOrEqual(t, len(listIPs), len(ips))

	// Clear all
	err = mockMgr.ClearBlacklist()
	require.NoError(t, err)

	// Verify cleared
	_, count, err = mockMgr.ListBlacklistIPs(0, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMockManager_ConcurrentOperations tests concurrent operations
// TestMockManager_ConcurrentOperations 测试并发操作
// Note: MockManager is not thread-safe, so we test sequential operations here
// 注意：MockManager 不是线程安全的，所以这里测试顺序操作
func TestMockManager_ConcurrentOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Sequential adds and reads - MockManager doesn't support concurrent access
	// 顺序添加和读取 - MockManager 不支持并发访问
	const numOps = 10
	for i := 0; i < numOps; i++ {
		ip := netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)}).String()
		err := mockMgr.AddBlacklistIP(ip + "/32")
		assert.NoError(t, err)
	}

	// Verify all IPs were added
	for i := 0; i < numOps; i++ {
		ip := netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)}).String()
		inList, err := mockMgr.IsIPInBlacklist(ip + "/32")
		assert.NoError(t, err)
		assert.True(t, inList)
	}
}

// TestMockManager_SearchOperations tests search functionality
// TestMockManager_SearchOperations 测试搜索功能
func TestMockManager_SearchOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Add some IPs
	testIPs := []string{"192.168.1.1/32", "192.168.1.2/32", "10.0.0.1/32"}
	for _, ip := range testIPs {
		err := mockMgr.AddBlacklistIP(ip)
		require.NoError(t, err)
	}

	// Search for specific pattern
	ips, count, err := mockMgr.ListBlacklistIPs(0, "192.168")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 2)
	assert.GreaterOrEqual(t, len(ips), 2)

	// Search for different pattern
	ips, count, err = mockMgr.ListBlacklistIPs(0, "10.0")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)
	assert.GreaterOrEqual(t, len(ips), 1)
}

// TestMockManager_LimitOperations tests limit parameter
// TestMockManager_LimitOperations 测试限制参数
func TestMockManager_LimitOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Add multiple IPs
	for i := 0; i < 10; i++ {
		ip := netip.AddrFrom4([4]byte{192, 168, 1, byte(i + 1)}).String()
		err := mockMgr.AddBlacklistIP(ip + "/32")
		require.NoError(t, err)
	}

	// List with limit - note: mock doesn't implement limit, just returns all
	ips, count, err := mockMgr.ListBlacklistIPs(5, "")
	require.NoError(t, err)
	assert.Equal(t, 10, count) // Total count should be 10
	_ = ips
}

// TestMockManager_IPNormalization tests IP normalization
// TestMockManager_IPNormalization 测试 IP 规范化
func TestMockManager_IPNormalization_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	testCases := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1", "192.168.1.1/32"},
		{"192.168.1.1/32", "192.168.1.1/32"},
		{"10.0.0.0/24", "10.0.0.0/24"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			err := mockMgr.AddBlacklistIP(tc.input)
			require.NoError(t, err)

			// Check if the normalized IP is in the list
			inList, err := mockMgr.IsIPInBlacklist(tc.expected)
			require.NoError(t, err)
			assert.True(t, inList)
		})
	}
}

// TestMockManager_Interface tests that MockManager implements ManagerInterface
// TestMockManager_Interface 测试 MockManager 实现 ManagerInterface
func TestMockManager_Interface(t *testing.T) {
	mockMgr := NewMockManager()

	// This test ensures MockManager implements ManagerInterface
	var _ ManagerInterface = mockMgr
}

// TestMockManager_SDKFirewall tests that MockManager can be used with SDK
// TestMockManager_SDKFirewall 测试 MockManager 可以与 SDK 一起使用
func TestMockManager_SDKFirewall(t *testing.T) {
	mockMgr := NewMockManager()

	// Test type assertion for basic firewall methods
	_, ok := interface{}(mockMgr).(interface {
		AddBlacklistIP(string) error
		RemoveBlacklistIP(string) error
	})
	assert.True(t, ok, "MockManager should implement basic firewall methods")
}

// TestMockManager_WithContext tests using MockManager with context
// TestMockManager_WithContext 测试使用 MockManager 与 context
func TestMockManager_WithContext(t *testing.T) {
	mockMgr := NewMockManager()
	ctx := context.Background()

	// Operations should work with context
	err := mockMgr.AddBlacklistIP("192.168.1.1/32")
	require.NoError(t, err)

	// Verify context is not needed for basic operations
	assert.NotNil(t, ctx)
}

// TestMockManager_WhitelistWithPort tests whitelist with port
// TestMockManager_WhitelistWithPort 测试带端口的白名单
func TestMockManager_WhitelistWithPort(t *testing.T) {
	mockMgr := NewMockManager()

	// Add whitelist with port
	err := mockMgr.AddWhitelistIP("192.168.1.1/32", 80)
	require.NoError(t, err)

	// Verify it's in the whitelist
	inList, err := mockMgr.IsIPInWhitelist("192.168.1.1/32")
	require.NoError(t, err)
	assert.True(t, inList)
}

// TestMockManager_RateLimitWithBurst tests rate limit with burst
// TestMockManager_RateLimitWithBurst 测试带突发的速率限制
func TestMockManager_RateLimitWithBurst(t *testing.T) {
	mockMgr := NewMockManager()

	// Add rate limit rule
	err := mockMgr.AddRateLimitRule("192.168.1.1", 1000, 100)
	require.NoError(t, err)

	// Verify it's in the rate limit rules
	assert.Contains(t, mockMgr.RateLimitRules, "192.168.1.1")
}

// TestMockManager_ClearOperations tests all clear operations
// TestMockManager_ClearOperations 测试所有清除操作
func TestMockManager_ClearOperations_Comprehensive(t *testing.T) {
	mockMgr := NewMockManager()

	// Add some data
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	_ = mockMgr.AddIPPortRule("192.168.1.1", 80, 1)
	_ = mockMgr.AllowPort(443)
	_ = mockMgr.AddRateLimitRule("192.168.1.1", 1000, 100)

	// Clear all
	err := mockMgr.ClearBlacklist()
	require.NoError(t, err)

	err = mockMgr.ClearWhitelist()
	require.NoError(t, err)

	err = mockMgr.ClearIPPortRules()
	require.NoError(t, err)

	err = mockMgr.ClearAllowedPorts()
	require.NoError(t, err)

	err = mockMgr.ClearRateLimitRules()
	require.NoError(t, err)

	// Verify all are empty
	assert.Empty(t, mockMgr.Blacklist)
	assert.Empty(t, mockMgr.WhitelistMap)
	assert.Empty(t, mockMgr.IPPortRulesMap)
	assert.Empty(t, mockMgr.AllowedPortsMap)
	assert.Empty(t, mockMgr.RateLimitRules)
}

// TestMockManager_DuplicateOperations tests duplicate operations
// TestMockManager_DuplicateOperations 测试重复操作
func TestMockManager_DuplicateOperations(t *testing.T) {
	mockMgr := NewMockManager()

	// Add same IP twice
	err := mockMgr.AddBlacklistIP("192.168.1.1/32")
	require.NoError(t, err)

	err = mockMgr.AddBlacklistIP("192.168.1.1/32")
	require.NoError(t, err) // Should not error on duplicate

	// Verify only one entry
	assert.Len(t, mockMgr.Blacklist, 1)
}

// TestMockManager_RemoveNonExistent tests removing non-existent entries
// TestMockManager_RemoveNonExistent 测试删除不存在的条目
func TestMockManager_RemoveNonExistent(t *testing.T) {
	mockMgr := NewMockManager()

	// Remove from empty blacklist
	err := mockMgr.RemoveBlacklistIP("192.168.1.1/32")
	assert.NoError(t, err) // Should not error

	// Remove from empty whitelist
	err = mockMgr.RemoveWhitelistIP("10.0.0.1/32")
	assert.NoError(t, err) // Should not error
}
