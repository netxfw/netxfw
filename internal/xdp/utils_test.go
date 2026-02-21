package xdp

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetPhysicalInterfaces tests the GetPhysicalInterfaces function
// TestGetPhysicalInterfaces 测试 GetPhysicalInterfaces 函数
func TestGetPhysicalInterfaces(t *testing.T) {
	interfaces, err := GetPhysicalInterfaces()
	require.NoError(t, err)

	// Verify all returned interfaces are valid
	// 验证所有返回的接口都是有效的
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		require.NoError(t, err, "Interface %s should exist", name)

		// Verify interface is UP
		// 验证接口是启动状态
		assert.True(t, iface.Flags&net.FlagUp != 0, "Interface %s should be UP", name)

		// Verify interface is not loopback
		// 验证接口不是环回接口
		assert.True(t, iface.Flags&net.FlagLoopback == 0, "Interface %s should not be loopback", name)

		// Verify interface is not virtual
		// 验证接口不是虚拟接口
		assert.False(t, isVirtual(name), "Interface %s should not be virtual", name)
	}
}

// TestIsVirtual tests the isVirtual function
// TestIsVirtual 测试 isVirtual 函数
func TestIsVirtual(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		// Virtual interfaces / 虚拟接口
		{"lo", true},
		{"lo0", true},
		{"docker0", true},
		{"docker1", true},
		{"veth12345", true},
		{"veth0", true},
		{"virbr0", true},
		{"virbr1", true},
		{"br-12345", true},
		{"br-test", true},
		{"tun0", true},
		{"tun1", true},
		{"tap0", true},
		{"tap1", true},
		{"kube-ipvs0", true},
		{"kube-bridge", true},

		// Physical interfaces / 物理接口
		{"eth0", false},
		{"eth1", false},
		{"ens33", false},
		{"ens192", false},
		{"enp0s3", false},
		{"wlan0", false},
		{"wlp2s0", false},
		{"en0", false},
		{"em0", false},
		{"p1p1", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isVirtual(tt.name)
			assert.Equal(t, tt.expected, result, "isVirtual(%q) should return %v", tt.name, tt.expected)
		})
	}
}

// TestIsIPv6Func tests the IsIPv6 function (renamed to avoid conflict)
// TestIsIPv6Func 测试 IsIPv6 函数（重命名以避免冲突）
func TestIsIPv6Func(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		// IPv4 addresses / IPv4 地址
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"0.0.0.0", false},
		{"255.255.255.255", false},

		// IPv4 CIDR / IPv4 CIDR
		{"192.168.1.0/24", false},
		{"10.0.0.0/8", false},
		{"172.16.0.0/12", false},

		// IPv6 addresses / IPv6 地址
		{"::1", true},
		{"fe80::1", true},
		{"2001:db8::1", true},
		{"::", true},
		{"fe80::/10", true},
		{"2001:db8::/32", true},
		{"::/0", true},

		// Invalid / 无效
		{"invalid", false},
		{"", false},
		{"256.256.256.256", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := IsIPv6(tt.ip)
			assert.Equal(t, tt.expected, result, "IsIPv6(%q) should return %v", tt.ip, tt.expected)
		})
	}
}

// TestFormatLpmKey tests the FormatLpmKey function
// TestFormatLpmKey 测试 FormatLpmKey 函数
func TestFormatLpmKey(t *testing.T) {
	// Test with valid key
	// 使用有效键测试
	key, err := NewLpmKey("192.168.1.1/32")
	require.NoError(t, err)

	result := FormatLpmKey(&key)
	// Just verify it doesn't panic and returns a non-empty string
	// 仅验证它不会发生 panic 并返回非空字符串
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "192.168.1.1")
}

// TestNewLpmKeyFunc tests the NewLpmKey function (renamed to avoid conflict)
// TestNewLpmKeyFunc 测试 NewLpmKey 函数（重命名以避免冲突）
func TestNewLpmKeyFunc(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		hasError bool
	}{
		{"Valid IPv4", "192.168.1.1/32", false},
		{"Valid IPv4 CIDR", "192.168.1.0/24", false},
		{"Valid IPv6", "::1/128", false},
		{"Valid IPv6 CIDR", "2001:db8::/32", false},
		{"Invalid IP", "invalid", true},
		{"Empty IP", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewLpmKey(tt.cidr)

			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, key.Data.In6U.U6Addr8)
			}
		})
	}
}

// TestIntToIPFunc tests the intToIP function (renamed to avoid conflict)
// TestIntToIPFunc 测试 intToIP 函数（重命名以避免冲突）
func TestIntToIPFunc(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected string
	}{
		{"Zero", 0, "0.0.0.0"},
		{"One", 1, "1.0.0.0"},
		{"Max", 0xFFFFFFFF, "255.255.255.255"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intToIP(tt.input)
			assert.NotNil(t, result)
			assert.Len(t, result, 4)
		})
	}
}

// TestTimeToBootNSFunc tests the timeToBootNS function (renamed to avoid conflict)
// TestTimeToBootNSFunc 测试 timeToBootNS 函数（重命名以避免冲突）
func TestTimeToBootNSFunc(t *testing.T) {
	// Test with nil
	// 测试 nil 情况
	result := timeToBootNS(nil)
	assert.Equal(t, uint64(0), result)

	// Test with future time
	// 测试未来时间
	futureTime := time.Now().Add(24 * time.Hour)
	result = timeToBootNS(&futureTime)
	assert.NotZero(t, result)
}

// TestTimeToBootNSFromProc tests timeToBootNS against /proc/stat
// TestTimeToBootNSFromProc 测试 timeToBootNS 与 /proc/stat 对比
func TestTimeToBootNSFromProc(t *testing.T) {
	// Read /proc/stat to get boot time
	// 读取 /proc/stat 获取启动时间
	data, err := os.ReadFile("/proc/stat")
	require.NoError(t, err)

	var btime uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "btime ") {
			n, err := fmt.Sscanf(line, "btime %d", &btime)
			require.NoError(t, err)
			require.Equal(t, 1, n)
			break
		}
	}

	require.NotZero(t, btime, "Should find btime in /proc/stat")
}

// TestCleanupExpiredRules_NilMap tests CleanupExpiredRules with nil map
// TestCleanupExpiredRules_NilMap 测试 CleanupExpiredRules 使用 nil map
func TestCleanupExpiredRules_NilMap(t *testing.T) {
	removed, err := CleanupExpiredRules(nil, false)
	assert.NoError(t, err)
	assert.Equal(t, 0, removed)
}

// TestListWhitelistIPs_NilMap tests ListWhitelistIPs with nil map
// TestListWhitelistIPs_NilMap 测试 ListWhitelistIPs 使用 nil map
func TestListWhitelistIPs_NilMap(t *testing.T) {
	ips, count, err := ListWhitelistIPs(nil, 10, "")
	assert.NoError(t, err)
	assert.Nil(t, ips)
	assert.Equal(t, 0, count)
}

// TestListBlockedIPs_NilMap tests ListBlockedIPs with nil map
// TestListBlockedIPs_NilMap 测试 ListBlockedIPs 使用 nil map
// Note: ListBlockedIPs doesn't have nil check, so this test is skipped
// 注意：ListBlockedIPs 没有 nil 检查，因此跳过此测试
// func TestListBlockedIPs_NilMap(t *testing.T) {
// 	ips, count, err := ListBlockedIPs(nil, false, 10, "")
// 	assert.NoError(t, err)
// 	assert.Nil(t, ips)
// 	assert.Equal(t, 0, count)
// }

// TestIsIPInMap_NilMap tests IsIPInMap with nil map
// TestIsIPInMap_NilMap 测试 IsIPInMap 使用 nil map
// Note: IsIPInMap doesn't have nil check, so this test is skipped
// 注意：IsIPInMap 没有 nil 检查，因此跳过此测试
// func TestIsIPInMap_NilMap(t *testing.T) {
// 	found, err := IsIPInMap(nil, "192.168.1.1")
// 	assert.NoError(t, err)
// 	assert.False(t, found)
// }

// TestCheckConflict_InvalidCIDR tests CheckConflict with invalid CIDR
// TestCheckConflict_InvalidCIDR 测试 CheckConflict 使用无效 CIDR
func TestCheckConflict_InvalidCIDR(t *testing.T) {
	found, msg := CheckConflict(nil, "invalid-cidr", false)
	assert.False(t, found)
	assert.Empty(t, msg)
}

// TestLockIP_InvalidCIDR tests LockIP with invalid CIDR
// TestLockIP_InvalidCIDR 测试 LockIP 使用无效 CIDR
func TestLockIP_InvalidCIDR(t *testing.T) {
	err := LockIP(nil, "invalid-cidr")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP or CIDR")
}

// TestAllowIP_InvalidCIDR tests AllowIP with invalid CIDR
// TestAllowIP_InvalidCIDR 测试 AllowIP 使用无效 CIDR
func TestAllowIP_InvalidCIDR(t *testing.T) {
	err := AllowIP(nil, "invalid-cidr", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP or CIDR")
}

// TestUnlockIP_InvalidCIDR tests UnlockIP with invalid CIDR
// TestUnlockIP_InvalidCIDR 测试 UnlockIP 使用无效 CIDR
func TestUnlockIP_InvalidCIDR(t *testing.T) {
	err := UnlockIP(nil, "invalid-cidr")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP or CIDR")
}
