package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
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
	assert.True(t, cache.IsDirty())

	err = cache.SaveConfigImmediate()
	assert.NoError(t, err)
	assert.False(t, cache.IsDirty())

	cfg2, err := cache.LoadConfigForce()
	require.NoError(t, err)
	assert.Equal(t, !originalDefaultDeny, cfg2.Base.DefaultDeny)

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.DefaultDeny = originalDefaultDeny
	})
	require.NoError(t, err)
	_ = cache.SaveConfigImmediate()
}

// TestConfigCache_HotReload_MultipleUpdates tests multiple consecutive updates.
// TestConfigCache_HotReload_MultipleUpdates 测试多次连续更新。
func TestConfigCache_HotReload_MultipleUpdates(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(200 * time.Millisecond)

	ctx := context.Background()

	for i := 0; i < 5; i++ {
		err := cache.UpdateConfig(func(c *types.GlobalConfig) {
			c.Base.ICMPRate = uint64(10 + i)
		})
		assert.NoError(t, err)
		cache.SaveConfigDelayed(ctx)
	}

	assert.True(t, cache.IsDirty())

	err := cache.SaveConfigImmediate()
	assert.NoError(t, err)
	assert.False(t, cache.IsDirty())
}

// TestConfigCache_HotReload_Rollback tests rollback on error.
// TestConfigCache_HotReload_Rollback 测试错误时的回滚。
func TestConfigCache_HotReload_Rollback(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)
	originalICMPRate := cfg.Base.ICMPRate

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.ICMPRate = 999
	})
	require.NoError(t, err)

	cache.InvalidateCache()

	cfg2, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, originalICMPRate, cfg2.Base.ICMPRate)
}

// TestConfigCache_HotReload_ConcurrentReaders tests concurrent readers during update.
// TestConfigCache_HotReload_ConcurrentReaders 测试更新期间的并发读取。
func TestConfigCache_HotReload_ConcurrentReaders(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(500 * time.Millisecond)

	ctx := context.Background()
	done := make(chan bool)

	go func() {
		for i := 0; i < 10; i++ {
			_, _ = cache.LoadConfig()
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()

	for i := 0; i < 5; i++ {
		err := cache.UpdateConfig(func(c *types.GlobalConfig) {
			c.Base.ICMPBurst = uint64(50 + i)
		})
		assert.NoError(t, err)
		cache.SaveConfigDelayed(ctx)
		time.Sleep(20 * time.Millisecond)
	}

	<-done
	_ = cache.SaveConfigImmediate()
}

// TestConfigCache_HotReload_ForceReload tests forced reload from file.
// TestConfigCache_HotReload_ForceReload 测试强制从文件重新加载。
func TestConfigCache_HotReload_ForceReload(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg1, err := cache.LoadConfig()
	require.NoError(t, err)

	cfg2, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, cfg1, cfg2)

	cfg3, err := cache.LoadConfigForce()
	require.NoError(t, err)
	assert.Equal(t, cfg1.Base.DefaultDeny, cfg3.Base.DefaultDeny)
}

// TestConfigCache_HotReload_DirtyTracking tests dirty flag tracking.
// TestConfigCache_HotReload_DirtyTracking 测试脏标志跟踪。
func TestConfigCache_HotReload_DirtyTracking(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	assert.False(t, cache.IsDirty())

	_, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.False(t, cache.IsDirty())

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.AllowICMP = !c.Base.AllowICMP
	})
	require.NoError(t, err)
	assert.True(t, cache.IsDirty())

	err = cache.SaveConfig()
	require.NoError(t, err)
	assert.False(t, cache.IsDirty())
}

// TestConfigCache_HotReload_DelayedSave tests delayed save functionality.
// TestConfigCache_HotReload_DelayedSave 测试延迟保存功能。
func TestConfigCache_HotReload_DelayedSave(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(50 * time.Millisecond)

	ctx := context.Background()

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.StrictProtocol = true
	})
	require.NoError(t, err)

	cache.SaveConfigDelayed(ctx)

	assert.True(t, cache.IsDirty())

	time.Sleep(100 * time.Millisecond)
}

// TestConfigCache_HotReload_Stop tests stopping the cache.
// TestConfigCache_HotReload_Stop 测试停止缓存。
func TestConfigCache_HotReload_Stop(t *testing.T) {
	cache := &ConfigCache{
		saveDelay:  100 * time.Millisecond,
		configPath: "/etc/netxfw/config.yaml",
		dirty:      false,
		stopCh:     make(chan struct{}),
	}

	err := cache.Stop()
	assert.NoError(t, err)
}

// TestConfigCache_HotReload_MultipleFields tests updating multiple fields.
// TestConfigCache_HotReload_MultipleFields 测试更新多个字段。
func TestConfigCache_HotReload_MultipleFields(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.DefaultDeny = true
		c.Base.StrictProtocol = true
		c.Base.DropFragments = true
		c.Base.StrictTCP = true
		c.Base.SYNLimit = true
		c.Base.BogonFilter = true
		c.Base.ICMPRate = 100
		c.Base.ICMPBurst = 200
	})
	require.NoError(t, err)

	cfg := cache.GetCachedConfig()
	require.NotNil(t, cfg)
	assert.True(t, cfg.Base.DefaultDeny)
	assert.True(t, cfg.Base.StrictProtocol)
	assert.True(t, cfg.Base.DropFragments)
	assert.True(t, cfg.Base.StrictTCP)
	assert.True(t, cfg.Base.SYNLimit)
	assert.True(t, cfg.Base.BogonFilter)
	assert.Equal(t, uint64(100), cfg.Base.ICMPRate)
	assert.Equal(t, uint64(200), cfg.Base.ICMPBurst)
}

// TestSyncSettings_HotReload tests sync settings with hot reload.
// TestSyncSettings_HotReload 测试带热重载的同步设置。
func TestSyncSettings_HotReload(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)

	testCases := []struct {
		name     string
		syncFunc func(context.Context, xdp.ManagerInterface, bool) error
	}{
		{"DefaultDeny", SyncDefaultDenyOptimized},
		{"EnableAFXDP", SyncEnableAFXDPOptimized},
		{"EnableRateLimit", SyncEnableRateLimitOptimized},
		{"DropFragments", SyncDropFragmentsOptimized},
		{"StrictTCP", SyncStrictTCPOptimized},
		{"SYNLimit", SyncSYNLimitOptimized},
		{"BogonFilter", SyncBogonFilterOptimized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.syncFunc(ctx, mockMgr, true)
			assert.NoError(t, err)

			err = tc.syncFunc(ctx, mockMgr, false)
			assert.NoError(t, err)
		})
	}
}

// TestConfigCache_HotReload_TempFile tests hot reload with a temporary config file.
// TestConfigCache_HotReload_TempFile 测试使用临时配置文件的热重载。
func TestConfigCache_HotReload_TempFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpConfigPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `base:
  default_deny: true
  allow_icmp: true
logging:
  enabled: false
`
	err := os.WriteFile(tmpConfigPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cache := &ConfigCache{
		saveDelay:  100 * time.Millisecond,
		configPath: tmpConfigPath,
		dirty:      false,
		stopCh:     make(chan struct{}),
	}

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.True(t, cfg.Base.DefaultDeny)

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.DefaultDeny = false
	})
	require.NoError(t, err)

	err = cache.SaveConfigImmediate()
	require.NoError(t, err)

	cfg2, err := cache.LoadConfigForce()
	require.NoError(t, err)
	assert.False(t, cfg2.Base.DefaultDeny)
}

// TestConfigCache_HotReload_CancelTimer tests canceling a pending save timer.
// TestConfigCache_HotReload_CancelTimer 测试取消待处理的保存定时器。
func TestConfigCache_HotReload_CancelTimer(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(500 * time.Millisecond)

	ctx := context.Background()

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.AllowICMP = !c.Base.AllowICMP
	})
	require.NoError(t, err)

	cache.SaveConfigDelayed(ctx)

	err = cache.SaveConfigImmediate()
	require.NoError(t, err)
	assert.False(t, cache.IsDirty())
}
