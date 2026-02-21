package sdk_test

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestStats_GetCounters tests GetCounters method
// TestStats_GetCounters 测试 GetCounters 方法
func TestStats_GetCounters(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	pass, drop, err := s.Stats.GetCounters()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, pass, uint64(0))
	assert.GreaterOrEqual(t, drop, uint64(0))
}

// TestStats_GetDropDetails tests GetDropDetails method
// TestStats_GetDropDetails 测试 GetDropDetails 方法
func TestStats_GetDropDetails(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	details, err := s.Stats.GetDropDetails()
	assert.NoError(t, err)
	_ = details // May be nil for mock
}

// TestStats_GetPassDetails tests GetPassDetails method
// TestStats_GetPassDetails 测试 GetPassDetails 方法
func TestStats_GetPassDetails(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	details, err := s.Stats.GetPassDetails()
	assert.NoError(t, err)
	_ = details // May be nil for mock
}

// TestStats_GetLockedIPCount tests GetLockedIPCount method
// TestStats_GetLockedIPCount 测试 GetLockedIPCount 方法
func TestStats_GetLockedIPCount(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	count, err := s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)

	err = s.Blacklist.Add("192.168.1.1/32")
	assert.NoError(t, err)

	count, err = s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)
}

// TestSecurity_SetDefaultDeny tests SetDefaultDeny method
// TestSecurity_SetDefaultDeny 测试 SetDefaultDeny 方法
func TestSecurity_SetDefaultDeny(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetDefaultDeny(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DefaultDeny)

	err = s.Security.SetDefaultDeny(false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.DefaultDeny)
}

// TestSecurity_SetEnableAFXDP tests SetEnableAFXDP method
// TestSecurity_SetEnableAFXDP 测试 SetEnableAFXDP 方法
func TestSecurity_SetEnableAFXDP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetEnableAFXDP(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableAFXDP)

	err = s.Security.SetEnableAFXDP(false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.EnableAFXDP)
}

// TestSecurity_AllMethods tests all Security methods
// TestSecurity_AllMethods 测试所有 Security 方法
func TestSecurity_AllMethods(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	assert.NoError(t, s.Security.SetDropFragments(true))
	assert.NoError(t, s.Security.SetStrictTCP(true))
	assert.NoError(t, s.Security.SetSYNLimit(true))
	assert.NoError(t, s.Security.SetConntrack(true))
	assert.NoError(t, s.Security.SetConntrackTimeout(30*time.Minute))
	assert.NoError(t, s.Security.SetBogonFilter(true))
	assert.NoError(t, s.Security.SetAutoBlock(true))
	assert.NoError(t, s.Security.SetAutoBlockExpiry(1*time.Hour))
}

// TestConntrack_List tests List method
// TestConntrack_List 测试 List 方法
func TestConntrack_List(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	entries, err := s.Conntrack.List()
	assert.NoError(t, err)
	_ = entries // May be nil for mock
}

// TestConntrack_Count tests Count method
// TestConntrack_Count 测试 Count 方法
func TestConntrack_Count(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	count, err := s.Conntrack.Count()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)
}

// TestBlacklist_AllMethods tests all Blacklist methods
// TestBlacklist_AllMethods 测试所有 Blacklist 方法
func TestBlacklist_AllMethods(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Add
	// 添加
	err := s.Blacklist.Add("192.168.1.1/32")
	assert.NoError(t, err)

	// Contains
	// 包含
	contains, err := s.Blacklist.Contains("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)

	// AddWithDuration
	// 添加带持续时间
	err = s.Blacklist.AddWithDuration("192.168.1.2/32", 1*time.Hour)
	assert.NoError(t, err)

	// List
	// 列表
	_, total, err := s.Blacklist.List(100, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 2)

	// Remove
	// 移除
	err = s.Blacklist.Remove("192.168.1.1/32")
	assert.NoError(t, err)

	// Clear
	// 清除
	err = s.Blacklist.Clear()
	assert.NoError(t, err)
}

// TestWhitelist_AllMethods tests all Whitelist methods
// TestWhitelist_AllMethods 测试所有 Whitelist 方法
func TestWhitelist_AllMethods(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Add
	// 添加
	err := s.Whitelist.Add("10.0.0.1/32", 0)
	assert.NoError(t, err)

	// AddWithPort
	// 添加带端口
	err = s.Whitelist.AddWithPort("10.0.0.2/32", 8080)
	assert.NoError(t, err)

	// Contains
	// 包含
	contains, err := s.Whitelist.Contains("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)

	// List
	// 列表
	_, total, err := s.Whitelist.List(100, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 2)

	// Remove
	// 移除
	err = s.Whitelist.Remove("10.0.0.1/32")
	assert.NoError(t, err)

	// Clear
	// 清除
	err = s.Whitelist.Clear()
	assert.NoError(t, err)
}

// TestRule_AllMethods tests all Rule methods
// TestRule_AllMethods 测试所有 Rule 方法
func TestRule_AllMethods(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Add
	// 添加
	err := s.Rule.Add("192.168.1.1/32", 80, 1)
	assert.NoError(t, err)

	// AddIPPortRule
	// 添加 IP 端口规则
	err = s.Rule.AddIPPortRule("192.168.1.2/32", 443, 2)
	assert.NoError(t, err)

	// List
	// 列表
	_, total, err := s.Rule.List(false, 100, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 2)

	// ListIPPortRules
	// 列出 IP 端口规则
	_, total, err = s.Rule.ListIPPortRules(100, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 2)

	// Remove
	// 移除
	err = s.Rule.Remove("192.168.1.1/32", 80)
	assert.NoError(t, err)

	// RemoveIPPortRule
	// 移除 IP 端口规则
	err = s.Rule.RemoveIPPortRule("192.168.1.2/32", 443)
	assert.NoError(t, err)

	// Clear
	// 清除
	err = s.Rule.Clear()
	assert.NoError(t, err)
}

// TestRule_AllowPort tests AllowPort methods
// TestRule_AllowPort 测试 AllowPort 方法
func TestRule_AllowPort(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Rule.AllowPort(80)
	assert.NoError(t, err)

	err = s.Rule.AllowPort(443)
	assert.NoError(t, err)

	err = s.Rule.RemoveAllowedPort(80)
	assert.NoError(t, err)
}

// TestRule_RateLimit tests RateLimit methods
// TestRule_RateLimit 测试 RateLimit 方法
func TestRule_RateLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Rule.AddRateLimitRule("10.0.0.0/8", 1000, 2000)
	assert.NoError(t, err)

	err = s.Rule.AddRateLimitRule("192.168.0.0/16", 500, 1000)
	assert.NoError(t, err)

	_, total, err := s.Rule.ListRateLimitRules(100, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 2)

	err = s.Rule.RemoveRateLimitRule("10.0.0.0/8")
	assert.NoError(t, err)
}

// TestSDK_NewSDK tests NewSDK function
// TestSDK_NewSDK 测试 NewSDK 函数
func TestSDK_NewSDK(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	assert.NotNil(t, s)
	assert.NotNil(t, s.Blacklist)
	assert.NotNil(t, s.Whitelist)
	assert.NotNil(t, s.Rule)
	assert.NotNil(t, s.Stats)
	assert.NotNil(t, s.Security)
	assert.NotNil(t, s.Conntrack)
	assert.NotNil(t, s.EventBus)
	assert.NotNil(t, s.Sync)
}

// TestBlacklist_IPv6 tests blacklist with IPv6
// TestBlacklist_IPv6 测试 IPv6 黑名单
func TestBlacklist_IPv6(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Blacklist.Add("2001:db8::1/128")
	assert.NoError(t, err)

	contains, err := s.Blacklist.Contains("2001:db8::1/128")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestWhitelist_IPv6 tests whitelist with IPv6
// TestWhitelist_IPv6 测试 IPv6 白名单
func TestWhitelist_IPv6(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Whitelist.Add("2001:db8::1/128", 0)
	assert.NoError(t, err)

	contains, err := s.Whitelist.Contains("2001:db8::1/128")
	assert.NoError(t, err)
	assert.True(t, contains)
}

// TestRule_IPv6 tests rules with IPv6
// TestRule_IPv6 测试 IPv6 规则
func TestRule_IPv6(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Rule.Add("2001:db8::1/128", 80, 1)
	assert.NoError(t, err)

	rules, total, err := s.Rule.List(true, 100, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 1)
	assert.NotNil(t, rules)
}

// TestBlacklist_CIDR tests blacklist with CIDR notation
// TestBlacklist_CIDR 测试 CIDR 表示法的黑名单
func TestBlacklist_CIDR(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Blacklist.Add("192.168.0.0/16")
	assert.NoError(t, err)

	err = s.Blacklist.Add("10.0.0.0/8")
	assert.NoError(t, err)
}

// TestWhitelist_CIDR tests whitelist with CIDR notation
// TestWhitelist_CIDR 测试 CIDR 表示法的白名单
func TestWhitelist_CIDR(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Whitelist.Add("192.168.0.0/16", 0)
	assert.NoError(t, err)

	err = s.Whitelist.Add("10.0.0.0/8", 0)
	assert.NoError(t, err)
}

// TestBlacklist_Search tests blacklist search functionality
// TestBlacklist_Search 测试黑名单搜索功能
func TestBlacklist_Search(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	s.Blacklist.Add("192.168.1.1/32")
	s.Blacklist.Add("192.168.1.2/32")
	s.Blacklist.Add("10.0.0.1/32")

	ips, total, err := s.Blacklist.List(100, "192.168")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 2)
	assert.NotNil(t, ips)
}

// TestWhitelist_Search tests whitelist search functionality
// TestWhitelist_Search 测试白名单搜索功能
func TestWhitelist_Search(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	s.Whitelist.Add("192.168.1.1/32", 0)
	s.Whitelist.Add("192.168.1.2/32", 0)
	s.Whitelist.Add("10.0.0.1/32", 0)

	ips, total, err := s.Whitelist.List(100, "192.168")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 2)
	assert.NotNil(t, ips)
}

// TestBlockedIP tests BlockedIP struct
// TestBlockedIP 测试 BlockedIP 结构体
func TestBlockedIP(t *testing.T) {
	blocked := sdk.BlockedIP{
		IP:        "192.168.1.1",
		ExpiresAt: 1234567890,
		Counter:   100,
	}

	assert.Equal(t, "192.168.1.1", blocked.IP)
	assert.Equal(t, uint64(1234567890), blocked.ExpiresAt)
	assert.Equal(t, uint64(100), blocked.Counter)
}

// TestIPPortRule tests IPPortRule struct
// TestIPPortRule 测试 IPPortRule 结构体
func TestIPPortRule(t *testing.T) {
	rule := sdk.IPPortRule{
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
	conf := sdk.RateLimitConf{
		Rate:  1000,
		Burst: 2000,
	}

	assert.Equal(t, uint64(1000), conf.Rate)
	assert.Equal(t, uint64(2000), conf.Burst)
}

// TestConntrackEntry tests ConntrackEntry struct
// TestConntrackEntry 测试 ConntrackEntry 结构体
func TestConntrackEntry(t *testing.T) {
	entry := sdk.ConntrackEntry{
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
	entry := sdk.DropDetailEntry{
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
	assert.Equal(t, uint32(1), entry.Reason)
	assert.Equal(t, uint64(100), entry.Count)
}

// TestDropLogEntry tests DropLogEntry struct
// TestDropLogEntry 测试 DropLogEntry 结构体
func TestDropLogEntry(t *testing.T) {
	entry := sdk.DropLogEntry{
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
	assert.Equal(t, uint32(1), entry.Reason)
}
