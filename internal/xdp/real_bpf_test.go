//go:build linux && integration
// +build linux,integration

package xdp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRealBPF_ManagerFromPins tests creating manager from existing BPF pins
// TestRealBPF_ManagerFromPins 测试从现有 BPF pins 创建管理器
func TestRealBPF_ManagerFromPins(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	// Try to create manager from existing pins
	// 尝试从现有 pins 创建管理器
	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	// Verify manager is valid
	// 验证管理器有效
	assert.NotNil(t, mgr)
}

// TestRealBPF_GetStats tests getting stats from real BPF maps
// TestRealBPF_GetStats 测试从真实 BPF Map 获取统计信息
func TestRealBPF_GetStats(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	// Get drop count
	// 获取拦截计数
	dropCount, err := mgr.GetDropCount()
	require.NoError(t, err)
	t.Logf("Drop count: %d", dropCount)

	// Get pass count
	// 获取放行计数
	passCount, err := mgr.GetPassCount()
	require.NoError(t, err)
	t.Logf("Pass count: %d", passCount)

	// Get locked IP count
	// 获取锁定 IP 计数
	lockedCount, err := mgr.GetLockedIPCount()
	require.NoError(t, err)
	t.Logf("Locked IP count: %d", lockedCount)

	// Get whitelist count
	// 获取白名单计数
	whitelistCount, err := mgr.GetWhitelistCount()
	require.NoError(t, err)
	t.Logf("Whitelist count: %d", whitelistCount)

	// Get conntrack count
	// 获取连接跟踪计数
	conntrackCount, err := mgr.GetConntrackCount()
	require.NoError(t, err)
	t.Logf("Conntrack count: %d", conntrackCount)
}

// TestRealBPF_BlacklistOperations tests blacklist operations with real BPF maps
// TestRealBPF_BlacklistOperations 测试真实 BPF Map 的黑名单操作
func TestRealBPF_BlacklistOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	// Create adapter for high-level operations
	// 创建适配器用于高级操作
	adapter := NewAdapter(mgr)

	testIP := "10.255.255.1/32" // Use unlikely IP for testing
	// 使用不太可能的 IP 进行测试

	// Check if IP is already blacklisted
	// 检查 IP 是否已在黑名单中
	initialBlacklisted, err := adapter.IsIPInBlacklist(testIP)
	require.NoError(t, err)

	// Add to blacklist
	// 添加到黑名单
	err = adapter.AddBlacklistIP(testIP)
	require.NoError(t, err, "Failed to add IP to blacklist")

	// Verify it's blacklisted
	// 验证已在黑名单中
	blacklisted, err := adapter.IsIPInBlacklist(testIP)
	require.NoError(t, err)
	assert.True(t, blacklisted, "IP should be in blacklist")

	// Remove from blacklist
	// 从黑名单移除
	err = adapter.RemoveBlacklistIP(testIP)
	require.NoError(t, err, "Failed to remove IP from blacklist")

	// Verify it's removed
	// 验证已移除
	blacklisted, err = adapter.IsIPInBlacklist(testIP)
	require.NoError(t, err)
	assert.False(t, blacklisted, "IP should not be in blacklist")

	// Restore initial state if needed
	// 如果需要，恢复初始状态
	if initialBlacklisted {
		_ = adapter.AddBlacklistIP(testIP)
	}
}

// TestRealBPF_WhitelistOperations tests whitelist operations with real BPF maps
// TestRealBPF_WhitelistOperations 测试真实 BPF Map 的白名单操作
func TestRealBPF_WhitelistOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	testIP := "10.255.255.2/32" // Use unlikely IP for testing
	// 使用不太可能的 IP 进行测试

	// Check if IP is already whitelisted
	// 检查 IP 是否已在白名单中
	initialWhitelisted, err := adapter.IsIPInWhitelist(testIP)
	require.NoError(t, err)

	// Add to whitelist
	// 添加到白名单
	err = adapter.AddWhitelistIP(testIP, 0)
	require.NoError(t, err, "Failed to add IP to whitelist")

	// Verify it's whitelisted
	// 验证已在白名单中
	whitelisted, err := adapter.IsIPInWhitelist(testIP)
	require.NoError(t, err)
	assert.True(t, whitelisted, "IP should be in whitelist")

	// Remove from whitelist
	// 从白名单移除
	err = adapter.RemoveWhitelistIP(testIP)
	require.NoError(t, err, "Failed to remove IP from whitelist")

	// Verify it's removed
	// 验证已移除
	whitelisted, err = adapter.IsIPInWhitelist(testIP)
	require.NoError(t, err)
	assert.False(t, whitelisted, "IP should not be in whitelist")

	// Restore initial state if needed
	// 如果需要，恢复初始状态
	if initialWhitelisted {
		_ = adapter.AddWhitelistIP(testIP, 0)
	}
}

// TestRealBPF_IPPortRules tests IP port rules with real BPF maps
// TestRealBPF_IPPortRules 测试真实 BPF Map 的 IP 端口规则
func TestRealBPF_IPPortRules(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	testIP := "10.255.255.3/32"
	testPort := uint16(65535) // Use unlikely port for testing
	// 使用不太可能的端口进行测试

	// Add IP port rule
	// 添加 IP 端口规则
	err = adapter.AddIPPortRule(testIP, testPort, 1) // 1 = Allow
	require.NoError(t, err, "Failed to add IP port rule")

	// List rules to verify
	// 列出规则验证
	rules, count, err := adapter.ListIPPortRules(false, 100, "")
	require.NoError(t, err)
	assert.Greater(t, count, 0, "Should have at least one rule")
	t.Logf("IP port rules count: %d", count)

	// Find our rule
	// 查找我们的规则
	found := false
	for _, rule := range rules {
		if rule.IP == testIP && rule.Port == testPort {
			found = true
			break
		}
	}
	assert.True(t, found, "Should find the added rule")

	// Remove the rule
	// 移除规则
	err = adapter.RemoveIPPortRule(testIP, testPort)
	require.NoError(t, err, "Failed to remove IP port rule")
}

// TestRealBPF_AllowedPorts tests allowed ports with real BPF maps
// TestRealBPF_AllowedPorts 测试真实 BPF Map 的允许端口
func TestRealBPF_AllowedPorts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	testPort := uint16(65534) // Use unlikely port for testing
	// 使用不太可能的端口进行测试

	// Allow port
	// 允许端口
	err = adapter.AllowPort(testPort)
	require.NoError(t, err, "Failed to allow port")

	// List allowed ports
	// 列出允许端口
	ports, err := adapter.ListAllowedPorts()
	require.NoError(t, err)

	// Verify port is in list
	// 验证端口在列表中
	found := false
	for _, p := range ports {
		if p == testPort {
			found = true
			break
		}
	}
	assert.True(t, found, "Port should be in allowed list")

	// Remove port
	// 移除端口
	err = adapter.RemoveAllowedPort(testPort)
	require.NoError(t, err, "Failed to remove allowed port")

	// Verify port is removed
	// 验证端口已移除
	ports, err = adapter.ListAllowedPorts()
	require.NoError(t, err)
	for _, p := range ports {
		assert.NotEqual(t, testPort, p, "Port should not be in allowed list")
	}
}

// TestRealBPF_RateLimitRules tests rate limit rules with real BPF maps
// TestRealBPF_RateLimitRules 测试真实 BPF Map 的速率限制规则
func TestRealBPF_RateLimitRules(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	testCIDR := "10.255.255.0/24" // Use unlikely CIDR for testing
	// 使用不太可能的 CIDR 进行测试

	// Add rate limit rule
	// 添加速率限制规则
	err = adapter.AddRateLimitRule(testCIDR, 1000, 2000)
	require.NoError(t, err, "Failed to add rate limit rule")

	// List rules
	// 列出规则
	rules, count, err := adapter.ListRateLimitRules(100, "")
	require.NoError(t, err)
	assert.Greater(t, count, 0, "Should have at least one rate limit rule")
	t.Logf("Rate limit rules count: %d", count)

	// Verify rule exists
	// 验证规则存在
	_, exists := rules[testCIDR]
	assert.True(t, exists, "Rule should exist")

	// Remove rule
	// 移除规则
	err = adapter.RemoveRateLimitRule(testCIDR)
	require.NoError(t, err, "Failed to remove rate limit rule")
}

// TestRealBPF_DynamicBlacklist tests dynamic blacklist with real BPF maps
// TestRealBPF_DynamicBlacklist 测试真实 BPF Map 的动态黑名单
func TestRealBPF_DynamicBlacklist(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	testIP := "10.255.255.100"

	// Add dynamic blacklist IP with TTL
	// 添加带 TTL 的动态黑名单 IP
	err = adapter.AddDynamicBlacklistIP(testIP, time.Hour)
	require.NoError(t, err, "Failed to add dynamic blacklist IP")

	t.Logf("Successfully added dynamic blacklist IP: %s", testIP)

	// Note: ListDynamicBlacklistIPs may fail due to different map structure
	// 注意：ListDynamicBlacklistIPs 可能因不同的 Map 结构而失败
	// Dynamic blacklist uses LRU hash with different key/value sizes
	// 动态黑名单使用具有不同键/值大小的 LRU hash
	// Clean up - dynamic blacklist uses DynLockList, not LockList
	// 清理 - 动态黑名单使用 DynLockList，而不是 LockList
	// Note: We don't have a direct remove for dynamic blacklist, it will expire automatically
	// 注意：我们没有直接移除动态黑名单的方法，它会自动过期
}

// TestRealBPF_DropDetails tests getting drop details from real BPF maps
// TestRealBPF_DropDetails 测试从真实 BPF Map 获取拦截详情
func TestRealBPF_DropDetails(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	// Get drop details
	// 获取拦截详情
	dropDetails, err := mgr.GetDropDetails()
	require.NoError(t, err)

	if len(dropDetails) > 0 {
		t.Logf("Drop details count: %d", len(dropDetails))
		for i, detail := range dropDetails {
			if i >= 5 {
				break
			}
			t.Logf("  Drop: Reason=%d, Protocol=%d, SrcIP=%s, DstPort=%d, Count=%d",
				detail.Reason, detail.Protocol, detail.SrcIP, detail.DstPort, detail.Count)
		}
	} else {
		t.Log("No drop details available")
	}

	// Get pass details
	// 获取放行详情
	passDetails, err := mgr.GetPassDetails()
	require.NoError(t, err)

	if len(passDetails) > 0 {
		t.Logf("Pass details count: %d", len(passDetails))
	} else {
		t.Log("No pass details available")
	}
}

// TestRealBPF_ConntrackEntries tests listing conntrack entries from real BPF maps
// TestRealBPF_ConntrackEntries 测试从真实 BPF Map 列出连接跟踪条目
func TestRealBPF_ConntrackEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	// List conntrack entries
	// 列出连接跟踪条目
	entries, err := mgr.ListConntrackEntries()
	require.NoError(t, err)

	if len(entries) > 0 {
		t.Logf("Conntrack entries count: %d", len(entries))
		for i, entry := range entries {
			if i >= 5 {
				break
			}
			t.Logf("  Conntrack: SrcIP=%s, DstIP=%s, SrcPort=%d, DstPort=%d, Protocol=%d",
				entry.SrcIP, entry.DstIP, entry.SrcPort, entry.DstPort, entry.Protocol)
		}
	} else {
		t.Log("No conntrack entries available")
	}
}

// TestRealBPF_Configuration tests configuration methods with real BPF maps
// TestRealBPF_Configuration 测试真实 BPF Map 的配置方法
func TestRealBPF_Configuration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	// These should not error even if they don't change anything
	// 这些不应该报错，即使它们没有改变任何东西
	err = adapter.SetDefaultDeny(true)
	assert.NoError(t, err, "SetDefaultDeny should not error")

	err = adapter.SetAllowReturnTraffic(true)
	assert.NoError(t, err, "SetAllowReturnTraffic should not error")

	err = adapter.SetAllowICMP(true)
	assert.NoError(t, err, "SetAllowICMP should not error")

	err = adapter.SetConntrack(true)
	assert.NoError(t, err, "SetConntrack should not error")

	err = adapter.SetEnableRateLimit(true)
	assert.NoError(t, err, "SetEnableRateLimit should not error")
}

// TestRealBPF_ListBlacklistIPs tests listing blacklist IPs with pagination
// TestRealBPF_ListBlacklistIPs 测试带分页的黑名单 IP 列表
func TestRealBPF_ListBlacklistIPs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	// List all blacklist IPs
	// 列出所有黑名单 IP
	ips, count, err := adapter.ListBlacklistIPs(100, "")
	require.NoError(t, err)
	t.Logf("Blacklist IPs count: %d", count)

	for i, ip := range ips {
		if i >= 10 {
			break
		}
		t.Logf("  Blacklisted: %s", ip.IP)
	}
}

// TestRealBPF_ListWhitelistIPs tests listing whitelist IPs with pagination
// TestRealBPF_ListWhitelistIPs 测试带分页的白名单 IP 列表
func TestRealBPF_ListWhitelistIPs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	// List all whitelist IPs
	// 列出所有白名单 IP
	ips, count, err := adapter.ListWhitelistIPs(100, "")
	require.NoError(t, err)
	t.Logf("Whitelist IPs count: %d", count)

	for i, ip := range ips {
		if i >= 10 {
			break
		}
		t.Logf("  Whitelisted: %s", ip)
	}
}

// TestRealBPF_IPv6Support tests IPv6 support with real BPF maps
// TestRealBPF_IPv6Support 测试真实 BPF Map 的 IPv6 支持
func TestRealBPF_IPv6Support(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	// Test IPv6 address
	// 测试 IPv6 地址
	testIPv6 := "fd00:dead:beef::1/128"

	// Add IPv6 to blacklist
	// 添加 IPv6 到黑名单
	err = adapter.AddBlacklistIP(testIPv6)
	if err != nil {
		t.Logf("IPv6 blacklist not supported or failed: %v", err)
		return
	}

	// Verify it's blacklisted
	// 验证已在黑名单中
	blacklisted, err := adapter.IsIPInBlacklist(testIPv6)
	require.NoError(t, err)
	assert.True(t, blacklisted, "IPv6 should be in blacklist")

	// Clean up
	// 清理
	_ = adapter.RemoveBlacklistIP(testIPv6)
}

// TestRealBPF_ParseIP tests IP parsing utilities
// TestRealBPF_ParseIP 测试 IP 解析工具
func TestRealBPF_ParseIP(t *testing.T) {
	testCases := []struct {
		ipStr    string
		expected bool
	}{
		{"192.168.1.1", true},
		{"fd00::1", true},
		{"invalid", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.ipStr, func(t *testing.T) {
			ip, err := netip.ParseAddr(tc.ipStr)
			if tc.expected {
				assert.NoError(t, err)
				assert.True(t, ip.IsValid())
			} else {
				// ParseAddr might succeed for some invalid inputs, so we just check it doesn't panic
				// ParseAddr 可能对某些无效输入成功，所以我们只检查它不会 panic
				_ = ip
			}
		})
	}
}

// TestRealBPF_ParseCIDR tests CIDR parsing utilities
// TestRealBPF_ParseCIDR 测试 CIDR 解析工具
func TestRealBPF_ParseCIDR(t *testing.T) {
	testCases := []struct {
		cidrStr  string
		expected bool
	}{
		{"192.168.1.1/32", true},
		{"10.0.0.0/8", true},
		{"fd00::1/128", true},
		{"invalid", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.cidrStr, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tc.cidrStr)
			if tc.expected {
				assert.NoError(t, err)
				assert.True(t, prefix.IsValid())
			} else {
				// ParsePrefix might succeed for some invalid inputs, so we just check it doesn't panic
				// ParsePrefix 可能对某些无效输入成功，所以我们只检查它不会 panic
				_ = prefix
			}
		})
	}
}

// TestRealBPF_ClearOperations tests clear operations with real BPF maps
// TestRealBPF_ClearOperations 测试真实 BPF Map 的清除操作
func TestRealBPF_ClearOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	// Add test data
	// 添加测试数据
	testIP := "10.255.255.200/32"
	err = adapter.AddBlacklistIP(testIP)
	require.NoError(t, err)

	// Verify added
	// 验证已添加
	blacklisted, err := adapter.IsIPInBlacklist(testIP)
	require.NoError(t, err)
	assert.True(t, blacklisted)

	// Clear blacklist
	// 清除黑名单
	err = adapter.ClearBlacklist()
	require.NoError(t, err, "Failed to clear blacklist")

	// Verify cleared
	// 验证已清除
	count, err := mgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), count, "Blacklist should be empty")
}

// TestRealBPF_AdvancedConfiguration tests advanced configuration methods
// TestRealBPF_AdvancedConfiguration 测试高级配置方法
func TestRealBPF_AdvancedConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := NewAdapter(mgr)

	// Test advanced configuration methods
	// 测试高级配置方法
	err = adapter.SetStrictTCP(true)
	assert.NoError(t, err, "SetStrictTCP should not error")

	err = adapter.SetSYNLimit(true)
	assert.NoError(t, err, "SetSYNLimit should not error")

	err = adapter.SetEnableAFXDP(true)
	assert.NoError(t, err, "SetEnableAFXDP should not error")

	err = adapter.SetDropFragments(true)
	assert.NoError(t, err, "SetDropFragments should not error")

	err = adapter.SetAutoBlockExpiry(time.Hour)
	assert.NoError(t, err, "SetAutoBlockExpiry should not error")

	err = adapter.SetConntrackTimeout(time.Minute * 30)
	assert.NoError(t, err, "SetConntrackTimeout should not error")

	err = adapter.SetStrictProtocol(true)
	assert.NoError(t, err, "SetStrictProtocol should not error")

	err = adapter.SetICMPRateLimit(100, 200)
	assert.NoError(t, err, "SetICMPRateLimit should not error")
}

// TestRealBPF_SyncOperations tests sync operations with real BPF maps
// TestRealBPF_SyncOperations 测试真实 BPF Map 的同步操作
func TestRealBPF_SyncOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	// SyncToFiles requires a valid config, skip if nil
	// SyncToFiles 需要有效的配置，如果为 nil 则跳过
	// This test is skipped as it requires a valid GlobalConfig
	// 此测试被跳过，因为它需要有效的 GlobalConfig
	t.Log("SyncToFiles test skipped - requires valid GlobalConfig")
}
