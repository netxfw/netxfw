package sdk

import (
	"sync"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
)

// TestSDK_NewSDK tests NewSDK function
// TestSDK_NewSDK 测试 NewSDK 函数
func TestSDK_NewSDK(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	assert.NotNil(t, s)
	assert.NotNil(t, s.Blacklist)
	assert.NotNil(t, s.Whitelist)
	assert.NotNil(t, s.Rule)
	assert.NotNil(t, s.Stats)
	assert.NotNil(t, s.Security)
	assert.NotNil(t, s.Conntrack)
	assert.NotNil(t, s.EventBus)
	assert.NotNil(t, s.Sync)
	assert.NotNil(t, s.Store)
}

// TestSDK_GetManager tests GetManager function
// TestSDK_GetManager 测试 GetManager 函数
func TestSDK_GetManager(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	mgr := s.GetManager()
	assert.Equal(t, mockMgr, mgr)
}

// TestKVStore tests KVStore operations
// TestKVStore 测试 KVStore 操作
func TestKVStore(t *testing.T) {
	store := &kvStoreImpl{}

	// Test Set and Get
	// 测试 Set 和 Get
	store.Set("key1", "value1")
	val, ok := store.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	// Test non-existent key
	// 测试不存在的键
	val, ok = store.Get("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, val)

	// Test Delete
	// 测试 Delete
	store.Delete("key1")
	val, ok = store.Get("key1")
	assert.False(t, ok)
}

// TestKVStore_Concurrent tests concurrent KVStore operations
// TestKVStore_Concurrent 测试并发 KVStore 操作
func TestKVStore_Concurrent(t *testing.T) {
	store := &kvStoreImpl{}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.Set(string(rune(i)), i)
		}(i)
	}
	wg.Wait()
}

// TestBlacklistAPI tests BlacklistAPI operations
// TestBlacklistAPI 测试 BlacklistAPI 操作
func TestBlacklistAPI(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	// Test Add
	// 测试 Add
	err := s.Blacklist.Add("192.168.1.1/32")
	assert.NoError(t, err)

	// Test Contains
	// 测试 Contains
	contains, err := s.Blacklist.Contains("192.168.1.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)

	// Test Remove
	// 测试 Remove
	err = s.Blacklist.Remove("192.168.1.1/32")
	assert.NoError(t, err)

	contains, err = s.Blacklist.Contains("192.168.1.1/32")
	assert.NoError(t, err)
	assert.False(t, contains)
}

// TestBlacklistAPI_AddWithDuration tests AddWithDuration
// TestBlacklistAPI_AddWithDuration 测试 AddWithDuration
func TestBlacklistAPI_AddWithDuration(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	err := s.Blacklist.AddWithDuration("192.168.1.1/32", 5*time.Minute)
	assert.NoError(t, err)
}

// TestBlacklistAPI_AddWithFile tests AddWithFile
// TestBlacklistAPI_AddWithFile 测试 AddWithFile
func TestBlacklistAPI_AddWithFile(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	err := s.Blacklist.AddWithFile("192.168.1.1/32", "/tmp/test.txt")
	assert.NoError(t, err)
}

// TestBlacklistAPI_Clear tests Clear
// TestBlacklistAPI_Clear 测试 Clear
func TestBlacklistAPI_Clear(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	s.Blacklist.Add("192.168.1.1/32")
	s.Blacklist.Add("192.168.1.2/32")

	err := s.Blacklist.Clear()
	assert.NoError(t, err)
}

// TestBlacklistAPI_List tests List
// TestBlacklistAPI_List 测试 List
func TestBlacklistAPI_List(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	s.Blacklist.Add("192.168.1.1/32")
	s.Blacklist.Add("192.168.1.2/32")

	ips, total, err := s.Blacklist.List(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, ips, 2)
}

// TestWhitelistAPI tests WhitelistAPI operations
// TestWhitelistAPI 测试 WhitelistAPI 操作
func TestWhitelistAPI(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	// Test Add (with port 0)
	// 测试 Add（端口为 0）
	err := s.Whitelist.Add("10.0.0.1/32", 0)
	assert.NoError(t, err)

	// Test Contains
	// 测试 Contains
	contains, err := s.Whitelist.Contains("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, contains)

	// Test Remove
	// 测试 Remove
	err = s.Whitelist.Remove("10.0.0.1/32")
	assert.NoError(t, err)

	contains, err = s.Whitelist.Contains("10.0.0.1/32")
	assert.NoError(t, err)
	assert.False(t, contains)
}

// TestWhitelistAPI_WithPort tests whitelist with port
// TestWhitelistAPI_WithPort 测试带端口的白名单
func TestWhitelistAPI_WithPort(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	err := s.Whitelist.AddWithPort("10.0.0.1/32", 443)
	assert.NoError(t, err)
}

// TestWhitelistAPI_List tests whitelist list
// TestWhitelistAPI_List 测试白名单列表
func TestWhitelistAPI_List(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	s.Whitelist.Add("10.0.0.1/32", 0)
	s.Whitelist.Add("10.0.0.2/32", 0)

	ips, total, err := s.Whitelist.List(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, ips, 2)
}

// TestStatsAPI tests StatsAPI operations
// TestStatsAPI 测试 StatsAPI 操作
func TestStatsAPI(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	pass, drop, err := s.Stats.GetCounters()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), pass)
	assert.Equal(t, uint64(0), drop)
}

// TestStatsAPI_GetLockedIPCount tests GetLockedIPCount
// TestStatsAPI_GetLockedIPCount 测试 GetLockedIPCount
func TestStatsAPI_GetLockedIPCount(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	s.Blacklist.Add("192.168.1.1/32")

	count, err := s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestRuleAPI tests RuleAPI operations
// TestRuleAPI 测试 RuleAPI 操作
func TestRuleAPI(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	// Test AddRateLimitRule
	// 测试 AddRateLimitRule
	err := s.Rule.AddRateLimitRule("192.168.1.0/24", 1000, 2000)
	assert.NoError(t, err)

	// Test RemoveRateLimitRule
	// 测试 RemoveRateLimitRule
	err = s.Rule.RemoveRateLimitRule("192.168.1.0/24")
	assert.NoError(t, err)
}

// TestRuleAPI_IPPortRules tests IP Port Rules
// TestRuleAPI_IPPortRules 测试 IP 端口规则
func TestRuleAPI_IPPortRules(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	err := s.Rule.Add("192.168.1.1/32", 80, 1)
	assert.NoError(t, err)

	err = s.Rule.Remove("192.168.1.1/32", 80)
	assert.NoError(t, err)

	err = s.Rule.Clear()
	assert.NoError(t, err)
}

// TestRuleAPI_AllowPort tests AllowPort
// TestRuleAPI_AllowPort 测试 AllowPort
func TestRuleAPI_AllowPort(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	err := s.Rule.AllowPort(443)
	assert.NoError(t, err)

	err = s.Rule.RemoveAllowedPort(443)
	assert.NoError(t, err)
}

// TestSecurityAPI tests SecurityAPI operations
// TestSecurityAPI 测试 SecurityAPI 操作
func TestSecurityAPI(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	// Test SetDefaultDeny
	// 测试 SetDefaultDeny
	err := s.Security.SetDefaultDeny(true)
	assert.NoError(t, err)

	// Test SetEnableAFXDP
	// 测试 SetEnableAFXDP
	err = s.Security.SetEnableAFXDP(true)
	assert.NoError(t, err)

	// Test SetAutoBlock
	// 测试 SetAutoBlock
	err = s.Security.SetAutoBlock(true)
	assert.NoError(t, err)

	// Test SetAutoBlockExpiry
	// 测试 SetAutoBlockExpiry
	err = s.Security.SetAutoBlockExpiry(30 * time.Minute)
	assert.NoError(t, err)

	// Test SetConntrack
	// 测试 SetConntrack
	err = s.Security.SetConntrack(true)
	assert.NoError(t, err)

	// Test SetConntrackTimeout
	// 测试 SetConntrackTimeout
	err = s.Security.SetConntrackTimeout(2 * time.Hour)
	assert.NoError(t, err)
}

// TestConntrackAPI tests ConntrackAPI operations
// TestConntrackAPI 测试 ConntrackAPI 操作
func TestConntrackAPI(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)

	// Test List
	// 测试 List
	entries, err := s.Conntrack.List()
	assert.NoError(t, err)
	assert.Empty(t, entries)

	// Test Count
	// 测试 Count
	count, err := s.Conntrack.Count()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestSyncAPI tests SyncAPI operations
// TestSyncAPI 测试 SyncAPI 操作
func TestSyncAPI(t *testing.T) {
	mockMgr := NewMockManager()
	s := NewSDK(mockMgr)
	cfg := &types.GlobalConfig{}

	// Test ToConfig
	// 测试 ToConfig
	err := s.Sync.ToConfig(cfg)
	assert.NoError(t, err)

	// Test ToMap
	// 测试 ToMap
	err = s.Sync.ToMap(cfg, false)
	assert.NoError(t, err)

	// Test VerifyAndRepair
	// 测试 VerifyAndRepair
	err = s.Sync.VerifyAndRepair(cfg)
	assert.NoError(t, err)
}
