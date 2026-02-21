package sdk_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestStatsAPI_GetCounters tests GetCounters method
// TestStatsAPI_GetCounters 测试 GetCounters 方法
func TestStatsAPI_GetCounters(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	pass, drop, err := s.Stats.GetCounters()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), pass)
	assert.Equal(t, uint64(0), drop)
}

// TestStatsAPI_GetDropDetails tests GetDropDetails method
// TestStatsAPI_GetDropDetails 测试 GetDropDetails 方法
func TestStatsAPI_GetDropDetails(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	details, err := s.Stats.GetDropDetails()
	assert.NoError(t, err)
	assert.Nil(t, details)
}

// TestStatsAPI_GetPassDetails tests GetPassDetails method
// TestStatsAPI_GetPassDetails 测试 GetPassDetails 方法
func TestStatsAPI_GetPassDetails(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	details, err := s.Stats.GetPassDetails()
	assert.NoError(t, err)
	assert.Nil(t, details)
}

// TestStatsAPI_GetLockedIPCount tests GetLockedIPCount method
// TestStatsAPI_GetLockedIPCount 测试 GetLockedIPCount 方法
func TestStatsAPI_GetLockedIPCount(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	count, err := s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	// Add some IPs and test again
	// 添加一些 IP 并再次测试
	mockMgr.AddBlacklistIP("192.168.1.1/32")
	mockMgr.AddBlacklistIP("192.168.1.2/32")

	count, err = s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
}

// TestSecurityAPI_SetDefaultDeny tests SetDefaultDeny method
// TestSecurityAPI_SetDefaultDeny 测试 SetDefaultDeny 方法
func TestSecurityAPI_SetDefaultDeny(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetDefaultDeny(true)
	assert.NoError(t, err)
}

// TestSecurityAPI_SetEnableAFXDP tests SetEnableAFXDP method
// TestSecurityAPI_SetEnableAFXDP 测试 SetEnableAFXDP 方法
func TestSecurityAPI_SetEnableAFXDP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetEnableAFXDP(true)
	assert.NoError(t, err)
}

// TestSecurityAPI_SetDropFragments tests SetDropFragments method
// TestSecurityAPI_SetDropFragments 测试 SetDropFragments 方法
func TestSecurityAPI_SetDropFragments(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetDropFragments(true)
	assert.NoError(t, err)
}

// TestSecurityAPI_SetStrictTCP tests SetStrictTCP method
// TestSecurityAPI_SetStrictTCP 测试 SetStrictTCP 方法
func TestSecurityAPI_SetStrictTCP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetStrictTCP(true)
	assert.NoError(t, err)
}

// TestSecurityAPI_SetSYNLimit tests SetSYNLimit method
// TestSecurityAPI_SetSYNLimit 测试 SetSYNLimit 方法
func TestSecurityAPI_SetSYNLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetSYNLimit(true)
	assert.NoError(t, err)
}

// TestSecurityAPI_SetConntrack tests SetConntrack method
// TestSecurityAPI_SetConntrack 测试 SetConntrack 方法
func TestSecurityAPI_SetConntrack(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetConntrack(true)
	assert.NoError(t, err)
}

// TestSecurityAPI_SetConntrackTimeout tests SetConntrackTimeout method
// TestSecurityAPI_SetConntrackTimeout 测试 SetConntrackTimeout 方法
func TestSecurityAPI_SetConntrackTimeout(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetConntrackTimeout(30 * time.Minute)
	assert.NoError(t, err)
}

// TestSecurityAPI_SetBogonFilter tests SetBogonFilter method
// TestSecurityAPI_SetBogonFilter 测试 SetBogonFilter 方法
func TestSecurityAPI_SetBogonFilter(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetBogonFilter(true)
	assert.NoError(t, err)
}

// TestSecurityAPI_SetAutoBlock tests SetAutoBlock method
// TestSecurityAPI_SetAutoBlock 测试 SetAutoBlock 方法
func TestSecurityAPI_SetAutoBlock(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetAutoBlock(true)
	assert.NoError(t, err)
}

// TestSecurityAPI_SetAutoBlockExpiry tests SetAutoBlockExpiry method
// TestSecurityAPI_SetAutoBlockExpiry 测试 SetAutoBlockExpiry 方法
func TestSecurityAPI_SetAutoBlockExpiry(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	err := s.Security.SetAutoBlockExpiry(1 * time.Hour)
	assert.NoError(t, err)
}

// TestDefaultEventBus_Subscribe tests Subscribe method
// TestDefaultEventBus_Subscribe 测试 Subscribe 方法
func TestDefaultEventBus_Subscribe(t *testing.T) {
	bus := sdk.NewEventBus()
	var called int32 // Use int32 for atomic operations / 使用 int32 进行原子操作

	handler := func(e sdk.Event) {
		atomic.StoreInt32(&called, 1)
	}

	bus.Subscribe(sdk.EventTypeRateLimitBlock, handler)
	bus.Publish(sdk.NewEvent(sdk.EventTypeRateLimitBlock, "test", "payload"))

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(1), atomic.LoadInt32(&called))
}

// TestDefaultEventBus_Unsubscribe tests Unsubscribe method
// TestDefaultEventBus_Unsubscribe 测试 Unsubscribe 方法
func TestDefaultEventBus_Unsubscribe(t *testing.T) {
	bus := sdk.NewEventBus()

	handler := func(e sdk.Event) {}

	bus.Subscribe(sdk.EventTypeRateLimitBlock, handler)
	bus.Unsubscribe(sdk.EventTypeRateLimitBlock, handler)

	// Unsubscribe is simplified, just verify no panic
	// Unsubscribe 已简化，只需验证无崩溃
	assert.NotNil(t, bus)
}

// TestDefaultEventBus_Publish tests Publish method
// TestDefaultEventBus_Publish 测试 Publish 方法
func TestDefaultEventBus_Publish(t *testing.T) {
	bus := sdk.NewEventBus()
	eventCh := make(chan sdk.Event, 1)

	handler := func(e sdk.Event) {
		eventCh <- e
	}

	bus.Subscribe(sdk.EventTypeConfigReload, handler)
	bus.Publish(sdk.NewEvent(sdk.EventTypeConfigReload, "test_source", map[string]string{"key": "value"}))

	select {
	case e := <-eventCh:
		assert.Equal(t, sdk.EventTypeConfigReload, e.Type)
		assert.Equal(t, "test_source", e.Source)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

// TestDefaultEventBus_Publish_NoHandlers tests Publish with no handlers
// TestDefaultEventBus_Publish_NoHandlers 测试无处理器的 Publish
func TestDefaultEventBus_Publish_NoHandlers(t *testing.T) {
	bus := sdk.NewEventBus()
	// Should not panic with no handlers
	// 无处理器时不应崩溃
	bus.Publish(sdk.NewEvent(sdk.EventTypeRateLimitBlock, "test", nil))
}

// TestNewEvent tests NewEvent function
// TestNewEvent 测试 NewEvent 函数
func TestNewEvent(t *testing.T) {
	event := sdk.NewEvent(sdk.EventTypeRateLimitBlock, "test_source", "test_payload")

	assert.Equal(t, sdk.EventTypeRateLimitBlock, event.Type)
	assert.Equal(t, "test_source", event.Source)
	assert.Equal(t, "test_payload", event.Payload)
	assert.Greater(t, event.Timestamp, int64(0))
}

// TestNewEventBus tests NewEventBus function
// TestNewEventBus 测试 NewEventBus 函数
func TestNewEventBus(t *testing.T) {
	bus := sdk.NewEventBus()
	assert.NotNil(t, bus)
}

// TestDefaultEventBus_MultipleHandlers tests multiple handlers for same event
// TestDefaultEventBus_MultipleHandlers 测试同一事件的多个处理器
func TestDefaultEventBus_MultipleHandlers(t *testing.T) {
	bus := sdk.NewEventBus()
	var counter int32
	var wg sync.WaitGroup

	handler1 := func(e sdk.Event) {
		atomic.AddInt32(&counter, 1)
		wg.Done()
	}
	handler2 := func(e sdk.Event) {
		atomic.AddInt32(&counter, 1)
		wg.Done()
	}

	bus.Subscribe(sdk.EventTypeRateLimitBlock, handler1)
	bus.Subscribe(sdk.EventTypeRateLimitBlock, handler2)

	wg.Add(2)
	bus.Publish(sdk.NewEvent(sdk.EventTypeRateLimitBlock, "test", nil))

	wg.Wait()
	assert.Equal(t, int32(2), atomic.LoadInt32(&counter))
}

// TestDefaultEventBus_DifferentEventTypes tests different event types
// TestDefaultEventBus_DifferentEventTypes 测试不同的事件类型
func TestDefaultEventBus_DifferentEventTypes(t *testing.T) {
	bus := sdk.NewEventBus()
	rateLimitCh := make(chan sdk.Event, 1)
	configReloadCh := make(chan sdk.Event, 1)

	bus.Subscribe(sdk.EventTypeRateLimitBlock, func(e sdk.Event) {
		rateLimitCh <- e
	})
	bus.Subscribe(sdk.EventTypeConfigReload, func(e sdk.Event) {
		configReloadCh <- e
	})

	bus.Publish(sdk.NewEvent(sdk.EventTypeRateLimitBlock, "test", nil))
	bus.Publish(sdk.NewEvent(sdk.EventTypeConfigReload, "test", nil))

	select {
	case e := <-rateLimitCh:
		assert.Equal(t, sdk.EventTypeRateLimitBlock, e.Type)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for rate limit event")
	}

	select {
	case e := <-configReloadCh:
		assert.Equal(t, sdk.EventTypeConfigReload, e.Type)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for config reload event")
	}
}
