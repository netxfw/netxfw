package sdk_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestXDP_IPParsing tests IP parsing functionality
// TestXDP_IPParsing 测试 IP 解析功能
func TestXDP_IPParsing(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		isIPv4  bool
		wantErr bool
	}{
		{"Valid IPv4", "192.168.1.1", true, false},
		{"Valid IPv4 CIDR", "192.168.1.0/24", true, true}, // CIDR is not a valid single IP
		{"Valid IPv6", "2001:db8::1", false, false},
		{"Valid IPv6 CIDR", "2001:db8::/32", false, true}, // CIDR is not a valid single IP
		{"Invalid IP", "invalid", false, true},
		{"Empty string", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := netip.ParseAddr(tt.ip)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.isIPv4 {
					assert.True(t, ip.Is4())
				} else {
					assert.True(t, ip.Is6())
				}
			}
		})
	}
}

// TestXDP_CIDRValidation tests CIDR validation
// TestXDP_CIDRValidation 测试 CIDR 验证
func TestXDP_CIDRValidation(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"Valid IPv4 CIDR /24", "192.168.1.0/24", false},
		{"Valid IPv4 CIDR /32", "192.168.1.1/32", false},
		{"Valid IPv4 CIDR /16", "10.0.0.0/16", false},
		{"Valid IPv4 CIDR /8", "10.0.0.0/8", false},
		{"Valid IPv4 CIDR /0", "0.0.0.0/0", false},
		{"Valid IPv6 CIDR /32", "2001:db8::/32", false},
		{"Valid IPv6 CIDR /64", "2001:db8::/64", false},
		{"Valid IPv6 CIDR /128", "2001:db8::1/128", false},
		{"Invalid CIDR", "invalid", true},
		{"Missing prefix", "192.168.1.0", true},
		{"Invalid prefix", "192.168.1.0/33", true}, // Go rejects invalid prefix
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := net.ParseCIDR(tt.cidr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestXDP_IPNetworkContains tests IP network containment
// TestXDP_IPNetworkContains 测试 IP 网络包含
func TestXDP_IPNetworkContains(t *testing.T) {
	tests := []struct {
		name     string
		network  string
		ip       string
		contains bool
	}{
		{"IPv4 in network", "192.168.1.0/24", "192.168.1.100", true},
		{"IPv4 not in network", "192.168.1.0/24", "192.168.2.1", false},
		{"IPv4 exact match", "192.168.1.1/32", "192.168.1.1", true},
		{"IPv4 not exact match", "192.168.1.1/32", "192.168.1.2", false},
		{"IPv4 any", "0.0.0.0/0", "8.8.8.8", true},
		{"IPv6 in network", "2001:db8::/32", "2001:db8::1", true},
		{"IPv6 not in network", "2001:db8::/32", "2001:db9::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.network)
			require.NoError(t, err)

			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip)

			assert.Equal(t, tt.contains, ipNet.Contains(ip))
		})
	}
}

// TestXDP_MaskSize tests IP mask size calculation
// TestXDP_MaskSize 测试 IP 掩码大小计算
func TestXDP_MaskSize(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		wantOnes int
		wantBits int
	}{
		{"IPv4 /24", "192.168.1.0/24", 24, 32},
		{"IPv4 /32", "192.168.1.1/32", 32, 32},
		{"IPv4 /16", "10.0.0.0/16", 16, 32},
		{"IPv4 /8", "10.0.0.0/8", 8, 32},
		{"IPv4 /0", "0.0.0.0/0", 0, 32},
		{"IPv6 /32", "2001:db8::/32", 32, 128},
		{"IPv6 /64", "2001:db8::/64", 64, 128},
		{"IPv6 /128", "2001:db8::1/128", 128, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			require.NoError(t, err)

			ones, bits := ipNet.Mask.Size()
			assert.Equal(t, tt.wantOnes, ones)
			assert.Equal(t, tt.wantBits, bits)
		})
	}
}

// TestXDP_TimeConversion tests time conversion utilities
// TestXDP_TimeConversion 测试时间转换工具
func TestXDP_TimeConversion(t *testing.T) {
	// Test current time
	// 测试当前时间
	now := time.Now()
	assert.False(t, now.IsZero())

	// Test future time
	// 测试未来时间
	future := now.Add(1 * time.Hour)
	assert.True(t, future.After(now))

	// Test past time
	// 测试过去时间
	past := now.Add(-1 * time.Hour)
	assert.True(t, past.Before(now))

	// Test duration parsing
	// 测试持续时间解析
	duration, err := time.ParseDuration("1h")
	require.NoError(t, err)
	assert.Equal(t, time.Hour, duration)
}

// TestXDP_MockManager tests MockManager functionality
// TestXDP_MockManager 测试 MockManager 功能
func TestXDP_MockManager(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	require.NotNil(t, mockMgr)

	// Test blacklist operations
	// 测试黑名单操作
	err := mockMgr.AddBlacklistIP("192.168.1.1")
	require.NoError(t, err)

	contains, err := mockMgr.IsIPInBlacklist("192.168.1.1")
	require.NoError(t, err)
	assert.True(t, contains)

	// Test whitelist operations
	// 测试白名单操作
	err = mockMgr.AddWhitelistIP("192.168.2.1/32", 0)
	require.NoError(t, err)

	contains, err = mockMgr.IsIPInWhitelist("192.168.2.1/32")
	require.NoError(t, err)
	assert.True(t, contains)

	// Test allowed ports
	// 测试允许端口
	err = mockMgr.AllowPort(80)
	require.NoError(t, err)

	ports, err := mockMgr.ListAllowedPorts()
	require.NoError(t, err)
	assert.Contains(t, ports, uint16(80))

	// Test rate limit
	// 测试速率限制
	err = mockMgr.AddRateLimitRule("192.168.3.1/32", 1000, 100)
	require.NoError(t, err)

	rules, count, err := mockMgr.ListRateLimitRules(100, "")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, rules, 1)
}

// TestXDP_IPPortRule tests IP port rule functionality
// TestXDP_IPPortRule 测试 IP 端口规则功能
func TestXDP_IPPortRule(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add IP port rule
	// 添加 IP 端口规则
	err := mockMgr.AddIPPortRule("192.168.1.1/32", 80, 1) // Allow
	require.NoError(t, err)

	// List rules
	// 列出规则
	rules, count, err := mockMgr.ListIPPortRules(false, 100, "")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, rules, 1)

	// Remove rule
	// 删除规则
	err = mockMgr.RemoveIPPortRule("192.168.1.1/32", 80)
	require.NoError(t, err)

	// Verify removal
	// 验证删除
	rules, count, err = mockMgr.ListIPPortRules(false, 100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, rules)
}

// TestXDP_ConcurrentOperations tests concurrent operations
// TestXDP_ConcurrentOperations 测试并发操作
func TestXDP_ConcurrentOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Run concurrent operations
	// 运行并发操作
	done := make(chan bool)

	// Writer goroutine
	// 写入 goroutine
	go func() {
		for i := 0; i < 100; i++ {
			_ = mockMgr.AddBlacklistIP("192.168.1.1")
		}
		done <- true
	}()

	// Reader goroutine
	// 读取 goroutine
	go func() {
		for i := 0; i < 100; i++ {
			_, _ = mockMgr.IsIPInBlacklist("192.168.1.1")
		}
		done <- true
	}()

	// Wait for both goroutines
	// 等待两个 goroutine
	<-done
	<-done
}

// TestXDP_ClearOperations tests clear operations
// TestXDP_ClearOperations 测试清除操作
func TestXDP_ClearOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add some entries
	// 添加一些条目
	_ = mockMgr.AddBlacklistIP("192.168.1.1")
	_ = mockMgr.AddWhitelistIP("192.168.2.1/32", 0)
	_ = mockMgr.AllowPort(80)
	_ = mockMgr.AddRateLimitRule("192.168.3.1/32", 1000, 100)

	// Clear all
	// 清除所有
	err := mockMgr.ClearBlacklist()
	require.NoError(t, err)

	err = mockMgr.ClearWhitelist()
	require.NoError(t, err)

	err = mockMgr.ClearAllowedPorts()
	require.NoError(t, err)

	err = mockMgr.ClearRateLimitRules()
	require.NoError(t, err)

	// Verify all cleared
	// 验证所有已清除
	ips, count, err := mockMgr.ListBlacklistIPs(100, "")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, ips)
}
