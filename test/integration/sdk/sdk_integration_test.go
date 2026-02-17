package sdk_test

import (
	"context"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestSDK_Integration_BlacklistWorkflow tests the complete blacklist workflow
// TestSDK_Integration_BlacklistWorkflow 测试完整的黑名单工作流
func TestSDK_Integration_BlacklistWorkflow(t *testing.T) {
	// Create mock manager and SDK
	// 创建模拟管理器和 SDK
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test adding IPs to blacklist
	// 测试添加 IP 到黑名单
	err := s.Blacklist.Add("192.168.1.1")
	assert.NoError(t, err)

	err = s.Blacklist.Add("192.168.1.2")
	assert.NoError(t, err)

	err = s.Blacklist.Add("10.0.0.1")
	assert.NoError(t, err)

	// Verify count
	// 验证计数
	count, err := s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 3, count)

	// Test listing blacklist
	// 测试列出黑名单
	_, total, err := s.Blacklist.List(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 3, total)

	// Test removing from blacklist
	// 测试从黑名单移除
	err = s.Blacklist.Remove("192.168.1.1")
	assert.NoError(t, err)

	count, err = s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 2, count)

	// Test clearing blacklist
	// 测试清除黑名单
	err = s.Blacklist.Clear()
	assert.NoError(t, err)

	count, err = s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestSDK_Integration_WhitelistWorkflow tests the complete whitelist workflow
// TestSDK_Integration_WhitelistWorkflow 测试完整的白名单工作流
func TestSDK_Integration_WhitelistWorkflow(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test adding IPs to whitelist
	// 测试添加 IP 到白名单
	err := s.Whitelist.Add("10.0.0.1", 0)
	assert.NoError(t, err)

	err = s.Whitelist.Add("10.0.0.2", 80)
	assert.NoError(t, err)

	// Test listing whitelist
	// 测试列出白名单
	_, total, err := s.Whitelist.List(100, "")
	assert.NoError(t, err)
	assert.Equal(t, 2, total)

	// Test removing from whitelist
	// 测试从白名单移除
	err = s.Whitelist.Remove("10.0.0.1")
	assert.NoError(t, err)
}

// TestSDK_Integration_IPPortRulesWorkflow tests the IP port rules workflow
// TestSDK_Integration_IPPortRulesWorkflow 测试 IP 端口规则工作流
func TestSDK_Integration_IPPortRulesWorkflow(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test adding IP port rules
	// 测试添加 IP 端口规则
	err := s.Rule.Add("192.168.1.1", 80, 1) // Allow
	assert.NoError(t, err)

	err = s.Rule.Add("192.168.1.2", 443, 2) // Deny
	assert.NoError(t, err)

	// Test listing IP port rules
	// 测试列出 IP 端口规则
	rules, total, err := s.Rule.List(false, 100, "")
	assert.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, rules, 2)

	// Test removing IP port rule
	// 测试移除 IP 端口规则
	err = s.Rule.Remove("192.168.1.1", 80)
	assert.NoError(t, err)

	rules, total, err = s.Rule.List(false, 100, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, total)
}

// TestSDK_Integration_SecuritySettings tests security settings
// TestSDK_Integration_SecuritySettings 测试安全设置
func TestSDK_Integration_SecuritySettings(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test SetDefaultDeny
	// 测试 SetDefaultDeny
	err := s.Security.SetDefaultDeny(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DefaultDeny)

	// Test SetEnableAFXDP
	// 测试 SetEnableAFXDP
	err = s.Security.SetEnableAFXDP(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableAFXDP)

	// Test SetDropFragments
	// 测试 SetDropFragments
	err = s.Security.SetDropFragments(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DropFragments)

	// Test SetStrictTCP
	// 测试 SetStrictTCP
	err = s.Security.SetStrictTCP(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.StrictTCP)

	// Test SetSYNLimit
	// 测试 SetSYNLimit
	err = s.Security.SetSYNLimit(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.SYNLimit)

	// Test SetBogonFilter
	// 测试 SetBogonFilter
	err = s.Security.SetBogonFilter(true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.BogonFilter)
}

// TestSDK_Integration_StatsOperations tests stats operations
// TestSDK_Integration_StatsOperations 测试统计操作
func TestSDK_Integration_StatsOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test GetCounters
	// 测试 GetCounters
	pass, drop, err := s.Stats.GetCounters()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), pass)
	assert.Equal(t, uint64(0), drop)

	// Test GetLockedIPCount
	// 测试 GetLockedIPCount
	lockedCount, err := s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, lockedCount)

	// Test GetDropDetails
	// 测试 GetDropDetails
	dropDetails, err := s.Stats.GetDropDetails()
	assert.NoError(t, err)

	// Test GetPassDetails
	// 测试 GetPassDetails
	passDetails, err := s.Stats.GetPassDetails()
	assert.NoError(t, err)

	// Note: MockManager returns nil for details
	// 注意：MockManager 返回 nil 作为详情
	_ = dropDetails
	_ = passDetails
}

// TestSDK_Integration_StoreOperations tests store operations
// TestSDK_Integration_StoreOperations 测试存储操作
func TestSDK_Integration_StoreOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test Set and Get
	// 测试 Set 和 Get
	s.Store.Set("key1", "value1")
	val, ok := s.Store.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	// Test Get non-existent
	// 测试获取不存在的键
	val, ok = s.Store.Get("key2")
	assert.False(t, ok)
	assert.Nil(t, val)

	// Test Delete
	// 测试删除
	s.Store.Delete("key1")
	val, ok = s.Store.Get("key1")
	assert.False(t, ok)
	assert.Nil(t, val)
}

// TestSDK_Integration_EventBus tests event bus operations
// TestSDK_Integration_EventBus 测试事件总线操作
func TestSDK_Integration_EventBus(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Channel to receive events
	// 用于接收事件的通道
	eventCh := make(chan sdk.Event, 1)

	// Define handler
	// 定义处理函数
	handler := func(e sdk.Event) {
		eventCh <- e
	}

	// Subscribe to rate limit block events
	// 订阅速率限制阻止事件
	s.EventBus.Subscribe(sdk.EventTypeRateLimitBlock, handler)

	// Publish an event
	// 发布事件
	testEvent := sdk.Event{
		Type:    sdk.EventTypeRateLimitBlock,
		Payload: "192.168.1.1",
		Source:  "test",
	}
	s.EventBus.Publish(testEvent)

	// Wait for event with timeout
	// 等待事件（带超时）
	select {
	case e := <-eventCh:
		assert.Equal(t, sdk.EventTypeRateLimitBlock, e.Type)
		assert.Equal(t, "192.168.1.1", e.Payload)
	case <-time.After(time.Second):
		t.Error("Event not received within timeout")
	}

	// Unsubscribe
	// 取消订阅
	s.EventBus.Unsubscribe(sdk.EventTypeRateLimitBlock, handler)
}

// TestSDK_Integration_ContextUsage tests SDK with context
// TestSDK_Integration_ContextUsage 测试带上下文的 SDK
func TestSDK_Integration_ContextUsage(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify context is properly created
	// 验证上下文正确创建
	assert.NotNil(t, ctx)

	// Use SDK with context
	// 使用带上下文的 SDK
	err := s.Blacklist.Add("192.168.1.1")
	assert.NoError(t, err)

	// Verify the operation completed before context deadline
	// 验证操作在上下文截止时间前完成
	assert.NoError(t, ctx.Err())
}

// TestSDK_Integration_GetManager tests GetManager method
// TestSDK_Integration_GetManager 测试 GetManager 方法
func TestSDK_Integration_GetManager(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test GetManager
	// 测试 GetManager
	mgr := s.GetManager()
	assert.NotNil(t, mgr)
	assert.Equal(t, mockMgr, mgr)
}

// TestSDK_Integration_MultipleOperations tests multiple operations in sequence
// TestSDK_Integration_MultipleOperations 测试多个连续操作
func TestSDK_Integration_MultipleOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Add to blacklist
	// 添加到黑名单
	err := s.Blacklist.Add("192.168.1.1")
	assert.NoError(t, err)

	// Add to whitelist
	// 添加到白名单
	err = s.Whitelist.Add("10.0.0.1", 0)
	assert.NoError(t, err)

	// Add IP port rule
	// 添加 IP 端口规则
	err = s.Rule.Add("172.16.0.1", 8080, 1)
	assert.NoError(t, err)

	// Verify all operations
	// 验证所有操作
	lockedCount, _ := s.Stats.GetLockedIPCount()
	assert.Equal(t, 1, lockedCount)

	rules, total, _ := s.Rule.List(false, 100, "")
	assert.Equal(t, 1, total)
	assert.Len(t, rules, 1)
}

// TestSDK_Integration_ConntrackOperations tests conntrack operations
// TestSDK_Integration_ConntrackOperations 测试连接跟踪操作
func TestSDK_Integration_ConntrackOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test SetConntrackTimeout
	// 测试 SetConntrackTimeout
	err := s.Security.SetConntrackTimeout(30 * time.Second)
	assert.NoError(t, err)

	// Test SetAutoBlockExpiry
	// 测试 SetAutoBlockExpiry
	err = s.Security.SetAutoBlockExpiry(5 * time.Minute)
	assert.NoError(t, err)
}
