package sdk_test

import (
	"testing"

	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestKVStore tests the key-value store functionality
// TestKVStore 测试键值存储功能
func TestKVStore(t *testing.T) {
	// Create SDK with nil manager to get a fresh store
	// 使用 nil manager 创建 SDK 以获取新的存储
	sdkInstance := sdk.NewSDK(nil)
	s := sdkInstance.Store

	// Test Set and Get
	// 测试 Set 和 Get
	s.Set("key1", "value1")
	val, ok := s.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	// Test Get non-existent
	// 测试获取不存在的键
	val, ok = s.Get("key2")
	assert.False(t, ok)
	assert.Nil(t, val)

	// Test Delete
	// 测试删除
	s.Delete("key1")
	val, ok = s.Get("key1")
	assert.False(t, ok)
	assert.Nil(t, val)

	// Test Complex Type
	// 测试复杂类型
	type Complex struct {
		ID   int
		Name string
	}
	c := Complex{ID: 1, Name: "Test"}
	s.Set("complex", c)
	val, ok = s.Get("complex")
	assert.True(t, ok)
	assert.Equal(t, c, val)
}

// TestNewSDK_StoreInitialized tests that SDK store is initialized
// TestNewSDK_StoreInitialized 测试 SDK 存储已初始化
func TestNewSDK_StoreInitialized(t *testing.T) {
	sdkInstance := sdk.NewSDK(nil)
	assert.NotNil(t, sdkInstance.Store)

	sdkInstance.Store.Set("test", 123)
	val, ok := sdkInstance.Store.Get("test")
	assert.True(t, ok)
	assert.Equal(t, 123, val)
}
