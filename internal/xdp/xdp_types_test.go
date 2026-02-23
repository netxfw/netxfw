package xdp

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
)

// TestBlockedIP tests BlockedIP struct
// TestBlockedIP 测试 BlockedIP 结构体
func TestBlockedIP(t *testing.T) {
	blockedIP := BlockedIP{
		IP:        "192.168.1.1",
		ExpiresAt: uint64(time.Now().Add(time.Hour).Unix()),
		Counter:   100,
	}

	assert.Equal(t, "192.168.1.1", blockedIP.IP)
	assert.True(t, blockedIP.ExpiresAt > 0)
	assert.Equal(t, uint64(100), blockedIP.Counter)
}

// TestIPPortRule tests IPPortRule struct
// TestIPPortRule 测试 IPPortRule 结构体
func TestIPPortRule(t *testing.T) {
	rule := IPPortRule{
		IP:     "192.168.1.1",
		Port:   80,
		Action: 1,
	}

	assert.Equal(t, "192.168.1.1", rule.IP)
	assert.Equal(t, uint16(80), rule.Port)
	assert.Equal(t, uint8(1), rule.Action)
}

// TestRateLimitConf tests RateLimitConf struct
// TestRateLimitConf 测试 RateLimitConf 结构体
func TestRateLimitConf(t *testing.T) {
	conf := RateLimitConf{
		Rate:  1000,
		Burst: 100,
	}

	assert.Equal(t, uint64(1000), conf.Rate)
	assert.Equal(t, uint64(100), conf.Burst)
}

// TestManagerInterface tests that MockManager implements ManagerInterface
// TestManagerInterface 测试 MockManager 实现 ManagerInterface
func TestManagerInterface(t *testing.T) {
	// This test verifies that MockManager implements all required methods
	// 此测试验证 MockManager 实现了所有必需的方法
	var _ ManagerInterface = NewMockManager()
}

// TestMockManager_ConfigMethods tests configuration methods
// TestMockManager_ConfigMethods 测试配置方法
func TestMockManager_ConfigMethods(t *testing.T) {
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
}

// TestMockManager_BlacklistMethods tests blacklist methods
// TestMockManager_BlacklistMethods 测试黑名单方法
func TestMockManager_BlacklistMethods(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddBlacklistIP
	// 测试 AddBlacklistIP
	err := mockMgr.AddBlacklistIP("192.168.1.1")
	assert.NoError(t, err)

	// Test IsIPInBlacklist
	// 测试 IsIPInBlacklist
	contains, err := mockMgr.IsIPInBlacklist("192.168.1.1")
	assert.NoError(t, err)
	assert.True(t, contains)

	// Test ListBlacklistIPs
	// 测试 ListBlacklistIPs
	ips, count, err := mockMgr.ListBlacklistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, ips, 1)

	// Test RemoveBlacklistIP
	// 测试 RemoveBlacklistIP
	err = mockMgr.RemoveBlacklistIP("192.168.1.1")
	assert.NoError(t, err)

	contains, err = mockMgr.IsIPInBlacklist("192.168.1.1")
	assert.NoError(t, err)
	assert.False(t, contains)

	// Test ClearBlacklist
	// 测试 ClearBlacklist
	err = mockMgr.AddBlacklistIP("192.168.1.2")
	assert.NoError(t, err)
	err = mockMgr.AddBlacklistIP("192.168.1.3")
	assert.NoError(t, err)

	err = mockMgr.ClearBlacklist()
	assert.NoError(t, err)

	ips, count, err = mockMgr.ListBlacklistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, ips)
}

// TestMockManager_WhitelistMethods tests whitelist methods
// TestMockManager_WhitelistMethods 测试白名单方法
func TestMockManager_WhitelistMethods(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddWhitelistIP
	// 测试 AddWhitelistIP
	err := mockMgr.AddWhitelistIP("192.168.1.1/32", 0)
	assert.NoError(t, err)

	// Test IsIPInWhitelist
	// 测试 IsIPInWhitelist
	contains, err := mockMgr.IsIPInWhitelist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)

	// Test ListWhitelistIPs
	// 测试 ListWhitelistIPs
	ips, count, err := mockMgr.ListWhitelistIPs(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, ips, 1)

	// Test RemoveWhitelistIP
	// 测试 RemoveWhitelistIP
	err = mockMgr.RemoveWhitelistIP("192.168.1.1/32")
	assert.NoError(t, err)

	contains, err = mockMgr.IsIPInWhitelist("192.168.1.1/32")
	assert.NoError(t, err)
	assert.False(t, contains)

	// Test ClearWhitelist
	// 测试 ClearWhitelist
	err = mockMgr.AddWhitelistIP("192.168.1.2/32", 0)
	assert.NoError(t, err)
	err = mockMgr.ClearWhitelist()
	assert.NoError(t, err)
	assert.Equal(t, 0, len(mockMgr.WhitelistMap))
}

// TestMockManager_IPPortRulesMethods tests IP port rules methods
// TestMockManager_IPPortRulesMethods 测试 IP 端口规则方法
func TestMockManager_IPPortRulesMethods(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddIPPortRule
	// 测试 AddIPPortRule
	err := mockMgr.AddIPPortRule("192.168.1.1/32", 80, 1)
	assert.NoError(t, err)

	// Test ListIPPortRules
	// 测试 ListIPPortRules
	rules, count, err := mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, rules, 1)

	// Test RemoveIPPortRule
	// 测试 RemoveIPPortRule
	err = mockMgr.RemoveIPPortRule("192.168.1.1/32", 80)
	assert.NoError(t, err)

	// Test ClearIPPortRules
	// 测试 ClearIPPortRules
	err = mockMgr.AddIPPortRule("192.168.1.2/32", 443, 1)
	assert.NoError(t, err)
	err = mockMgr.ClearIPPortRules()
	assert.NoError(t, err)
	assert.Equal(t, 0, len(mockMgr.IPPortRulesMap))
}

// TestMockManager_AllowedPortsMethods tests allowed ports methods
// TestMockManager_AllowedPortsMethods 测试允许端口方法
func TestMockManager_AllowedPortsMethods(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AllowPort (interface method name)
	// 测试 AllowPort（接口方法名）
	err := mockMgr.AllowPort(80)
	assert.NoError(t, err)
	assert.True(t, mockMgr.AllowedPortsMap[80])

	// Test ListAllowedPorts
	// 测试 ListAllowedPorts
	ports, err := mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	assert.Len(t, ports, 1)

	// Test RemoveAllowedPort
	// 测试 RemoveAllowedPort
	err = mockMgr.RemoveAllowedPort(80)
	assert.NoError(t, err)
	assert.False(t, mockMgr.AllowedPortsMap[80])

	// Test ClearAllowedPorts
	// 测试 ClearAllowedPorts
	err = mockMgr.AllowPort(443)
	assert.NoError(t, err)
	err = mockMgr.ClearAllowedPorts()
	assert.NoError(t, err)
	assert.Equal(t, 0, len(mockMgr.AllowedPortsMap))
}

// TestMockManager_RateLimitMethods tests rate limit methods
// TestMockManager_RateLimitMethods 测试速率限制方法
func TestMockManager_RateLimitMethods(t *testing.T) {
	mockMgr := NewMockManager()

	// Test AddRateLimitRule
	// 测试 AddRateLimitRule
	err := mockMgr.AddRateLimitRule("192.168.1.1/32", 1000, 100)
	assert.NoError(t, err)

	// Test ListRateLimitRules
	// 测试 ListRateLimitRules
	rules, count, err := mockMgr.ListRateLimitRules(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, rules, 1)

	// Test RemoveRateLimitRule
	// 测试 RemoveRateLimitRule
	err = mockMgr.RemoveRateLimitRule("192.168.1.1/32")
	assert.NoError(t, err)

	// Test ClearRateLimitRules
	// 测试 ClearRateLimitRules
	err = mockMgr.AddRateLimitRule("192.168.1.2/32", 2000, 200)
	assert.NoError(t, err)
	err = mockMgr.ClearRateLimitRules()
	assert.NoError(t, err)
	assert.Equal(t, 0, len(mockMgr.RateLimitRules))
}

// TestMockManager_SyncMethods tests sync methods
// TestMockManager_SyncMethods 测试同步方法
func TestMockManager_SyncMethods(t *testing.T) {
	mockMgr := NewMockManager()

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{"192.168.1.0/24"},
		},
	}

	// Test SyncFromFiles
	// 测试 SyncFromFiles
	err := mockMgr.SyncFromFiles(cfg, false)
	assert.NoError(t, err)

	// Test VerifyAndRepair
	// 测试 VerifyAndRepair
	err = mockMgr.VerifyAndRepair(cfg)
	assert.NoError(t, err)

	// Test SyncToFiles
	// 测试 SyncToFiles
	err = mockMgr.SyncToFiles(cfg)
	assert.NoError(t, err)
}

// TestMockManager_OtherConfigMethods tests other configuration methods
// TestMockManager_OtherConfigMethods 测试其他配置方法
func TestMockManager_OtherConfigMethods(t *testing.T) {
	mockMgr := NewMockManager()

	// Test SetAutoBlock
	// 测试 SetAutoBlock
	err := mockMgr.SetAutoBlock(true)
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
	err = mockMgr.SetConntrackTimeout(time.Hour)
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
	err = mockMgr.SetICMPRateLimit(1000, 100)
	assert.NoError(t, err)
}

// TestMockManager_EdgeCases tests edge cases
// TestMockManager_EdgeCases 测试边界情况
func TestMockManager_EdgeCases(t *testing.T) {
	mockMgr := NewMockManager()

	// Test removing non-existent entries
	// 测试删除不存在的条目
	err := mockMgr.RemoveBlacklistIP("non-existent")
	assert.NoError(t, err)

	err = mockMgr.RemoveWhitelistIP("non-existent")
	assert.NoError(t, err)

	err = mockMgr.RemoveIPPortRule("non-existent", 80)
	assert.NoError(t, err)

	err = mockMgr.RemoveAllowedPort(80)
	assert.NoError(t, err)

	err = mockMgr.RemoveRateLimitRule("non-existent")
	assert.NoError(t, err)

	// Test clearing empty maps
	// 测试清空空的 Map
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
}

// TestMockManager_ConcurrentAccess tests concurrent access
// TestMockManager_ConcurrentAccess 测试并发访问
func TestMockManager_ConcurrentAccess(t *testing.T) {
	mockMgr := NewMockManager()

	// Run multiple goroutines to test concurrent access
	// 运行多个 goroutine 测试并发访问
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

// TestMockManager_ZeroValues tests zero values
// TestMockManager_ZeroValues 测试零值
func TestMockManager_ZeroValues(t *testing.T) {
	mockMgr := NewMockManager()

	// Test with empty strings
	// 测试空字符串
	err := mockMgr.AddBlacklistIP("")
	assert.NoError(t, err)

	err = mockMgr.AddWhitelistIP("", 0)
	assert.NoError(t, err)

	// Test with zero rate
	// 测试零速率
	err = mockMgr.AddRateLimitRule("192.168.1.1/32", 0, 0)
	assert.NoError(t, err)
}

// TestConntrackEntry tests ConntrackEntry struct
// TestConntrackEntry 测试 ConntrackEntry 结构体
func TestConntrackEntry(t *testing.T) {
	entry := ConntrackEntry{
		SrcIP:    "192.168.1.1",
		DstIP:    "10.0.0.1",
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
		LastSeen: time.Now(),
	}

	assert.Equal(t, "192.168.1.1", entry.SrcIP)
	assert.Equal(t, "10.0.0.1", entry.DstIP)
	assert.Equal(t, uint16(12345), entry.SrcPort)
	assert.Equal(t, uint16(80), entry.DstPort)
	assert.Equal(t, uint8(6), entry.Protocol)
}

// TestDropDetailEntry tests DropDetailEntry struct
// TestDropDetailEntry 测试 DropDetailEntry 结构体
func TestDropDetailEntry(t *testing.T) {
	entry := DropDetailEntry{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "10.0.0.1",
		SrcPort:   12345,
		DstPort:   80,
		Protocol:  6,
		Reason:    1,
		Count:     100,
		Payload:   []byte("test"),
	}

	assert.Equal(t, "192.168.1.1", entry.SrcIP)
	assert.Equal(t, "10.0.0.1", entry.DstIP)
	assert.Equal(t, uint16(12345), entry.SrcPort)
	assert.Equal(t, uint16(80), entry.DstPort)
	assert.Equal(t, uint8(6), entry.Protocol)
	assert.Equal(t, uint32(1), entry.Reason)
	assert.Equal(t, uint64(100), entry.Count)
}
