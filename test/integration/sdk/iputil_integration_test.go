package sdk_test

import (
	"testing"

	"github.com/netxfw/netxfw/internal/utils/iputil"
	"github.com/stretchr/testify/assert"
)

// TestIPUtil_IPParsing tests IP parsing functionality
// TestIPUtil_IPParsing 测试 IP 解析功能
func TestIPUtil_IPParsing(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectIP  string
		expectErr bool
	}{
		{"Valid IPv4", "192.168.1.1", "192.168.1.1", false},
		{"Valid IPv4 with CIDR", "192.168.1.0/24", "192.168.1.0/24", false},
		{"Valid IPv6", "2001:db8::1", "2001:db8::1", false},
		{"Valid IPv6 with CIDR", "2001:db8::/32", "2001:db8::/32", false},
		{"Invalid IP", "invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipNet, err := iputil.ParseCIDR(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ipNet)
			}
		})
	}
}

// TestIPUtil_IPPortParsing tests IP:Port parsing functionality
// TestIPUtil_IPPortParsing 测试 IP:端口解析功能
func TestIPUtil_IPPortParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expectIP   string
		expectPort uint16
		expectErr  bool
	}{
		{"IPv4 with port", "192.168.1.1:8080", "192.168.1.1", 8080, false},
		{"IPv6 with port", "[2001:db8::1]:443", "2001:db8::1", 443, false},
		{"IPv4 without port", "192.168.1.1", "192.168.1.1", 0, false},
		{"Invalid format", "invalid:port", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, port, err := iputil.ParseIPPort(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectIP, ip)
				assert.Equal(t, tt.expectPort, port)
			}
		})
	}
}

// TestIPUtil_CIDRNormalization tests CIDR normalization
// TestIPUtil_CIDRNormalization 测试 CIDR 标准化
func TestIPUtil_CIDRNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"IPv4 single", "192.168.1.1", "192.168.1.1/32"},
		{"IPv4 CIDR", "192.168.1.0/24", "192.168.1.0/24"},
		{"IPv6 single", "2001:db8::1", "2001:db8::1/128"},
		{"IPv6 CIDR", "2001:db8::/32", "2001:db8::/32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := iputil.NormalizeCIDR(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIPUtil_IPValidation tests IP validation
// TestIPUtil_IPValidation 测试 IP 验证
func TestIPUtil_IPValidation(t *testing.T) {
	// Test valid IPs
	// 测试有效 IP
	assert.True(t, iputil.IsValidIP("192.168.1.1"))
	assert.True(t, iputil.IsValidIP("10.0.0.1"))
	assert.True(t, iputil.IsValidIP("2001:db8::1"))

	// Test invalid IPs
	// 测试无效 IP
	assert.False(t, iputil.IsValidIP("invalid"))
	assert.False(t, iputil.IsValidIP("256.256.256.256"))
}

// TestIPUtil_CIDRValidation tests CIDR validation
// TestIPUtil_CIDRValidation 测试 CIDR 验证
func TestIPUtil_CIDRValidation(t *testing.T) {
	// Test valid CIDRs (including single IPs which are converted to /32 or /128)
	// 测试有效 CIDR（包括转换为 /32 或 /128 的单个 IP）
	assert.True(t, iputil.IsValidCIDR("192.168.1.0/24"))
	assert.True(t, iputil.IsValidCIDR("10.0.0.0/8"))
	assert.True(t, iputil.IsValidCIDR("2001:db8::/32"))
	// Single IPs are also valid as they get converted to CIDR
	// 单个 IP 也是有效的，因为它们会被转换为 CIDR
	assert.True(t, iputil.IsValidCIDR("192.168.1.1"))

	// Test invalid CIDRs
	// 测试无效 CIDR
	assert.False(t, iputil.IsValidCIDR("invalid"))
}

// TestIPUtil_IsIPv6 tests IPv6 detection
// TestIPUtil_IsIPv6 测试 IPv6 检测
func TestIPUtil_IsIPv6(t *testing.T) {
	// Test IPv6 addresses
	// 测试 IPv6 地址
	assert.True(t, iputil.IsIPv6("2001:db8::1"))
	assert.True(t, iputil.IsIPv6("::1"))
	assert.True(t, iputil.IsIPv6("fe80::1"))

	// Test IPv4 addresses
	// 测试 IPv4 地址
	assert.False(t, iputil.IsIPv6("192.168.1.1"))
	assert.False(t, iputil.IsIPv6("10.0.0.1"))
	assert.False(t, iputil.IsIPv6("invalid"))
}
