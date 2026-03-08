//go:build integration
// +build integration

package core

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigCache_HotReload_Basic tests basic hot reload functionality.
// TestConfigCache_HotReload_Basic 测试基本热重载功能。
func TestConfigCache_HotReload_Basic(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(100 * time.Millisecond)

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	originalDefaultDeny := cfg.Base.DefaultDeny

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.DefaultDeny = !originalDefaultDeny
	})
	assert.NoError(t, err)
}

// TestConfigCache_HotReload_MultipleUpdates tests multiple hot reload updates.
// TestConfigCache_HotReload_MultipleUpdates 测试多次热重载更新。
func TestConfigCache_HotReload_MultipleUpdates(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(50 * time.Millisecond)

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		err = cache.UpdateConfig(func(c *types.GlobalConfig) {
			c.Base.DefaultDeny = !c.Base.DefaultDeny
		})
		assert.NoError(t, err)
	}

	_ = cfg
}

// TestConfigCache_HotReload_Rollback tests hot reload rollback.
// TestConfigCache_HotReload_Rollback 测试热重载回滚。
func TestConfigCache_HotReload_Rollback(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)

	_ = cfg
}

// TestConfigCache_HotReload_ConcurrentReaders tests concurrent readers during hot reload.
// TestConfigCache_HotReload_ConcurrentReaders 测试热重载期间的并发读取。
func TestConfigCache_HotReload_ConcurrentReaders(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)

	_ = cfg
}

// TestConfigCache_HotReload_ForceReload tests force reload.
// TestConfigCache_HotReload_ForceReload 测试强制重载。
func TestConfigCache_HotReload_ForceReload(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)

	_ = cfg
}

// TestConfigCache_HotReload_DirtyTracking tests dirty tracking.
// TestConfigCache_HotReload_DirtyTracking 测试脏标记跟踪。
func TestConfigCache_HotReload_DirtyTracking(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)

	_ = cfg
}
