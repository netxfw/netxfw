package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestConfigCache_GetConfigCache tests GetConfigCache singleton
// TestConfigCache_GetConfigCache 测试 GetConfigCache 单例
func TestConfigCache_GetConfigCache(t *testing.T) {
	cache1 := GetConfigCache()
	cache2 := GetConfigCache()

	assert.Equal(t, cache1, cache2, "ConfigCache should be a singleton")
}

// TestConfigCache_SaveDelay tests the save delay setting
// TestConfigCache_SaveDelay 测试保存延迟设置
func TestConfigCache_SaveDelay(t *testing.T) {
	cache := GetConfigCache()
	cache.SetSaveDelay(100 * time.Millisecond)

	assert.Equal(t, 100*time.Millisecond, cache.saveDelay)
}

// TestConfigCache_IsDirty tests the dirty flag
// TestConfigCache_IsDirty 测试脏标志
func TestConfigCache_IsDirty(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	assert.False(t, cache.IsDirty())

	err := cache.UpdateConfig(func(cfg *types.GlobalConfig) {
	})
	assert.NoError(t, err)
	assert.True(t, cache.IsDirty())
}

// TestConfigCache_InvalidateCache tests cache invalidation
// TestConfigCache_InvalidateCache 测试缓存失效
func TestConfigCache_InvalidateCache(t *testing.T) {
	cache := GetConfigCache()

	cache.InvalidateCache()

	assert.Nil(t, cache.GetCachedConfig())
	assert.False(t, cache.IsDirty())
}

// TestSyncBoolSettingWithConfig tests optimized sync function
// TestSyncBoolSettingWithConfig 测试优化的同步函数
func TestSyncBoolSettingWithConfig(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := syncBoolSettingWithConfig(ctx, mockMgr, true,
		mockMgr.SetDefaultDeny,
		func(cfg *types.GlobalConfig, v bool) { cfg.Base.DefaultDeny = v },
		"test setting", "Test setting set to: %v")
	assert.NoError(t, err)
}

// TestSyncDefaultDeny tests optimized SyncDefaultDeny
// TestSyncDefaultDeny 测试优化的 SyncDefaultDeny
func TestSyncDefaultDeny(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncDefaultDeny(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DefaultDeny)

	err = SyncDefaultDeny(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.DefaultDeny)
}

// TestSyncEnableAFXDP tests optimized SyncEnableAFXDP
// TestSyncEnableAFXDP 测试优化的 SyncEnableAFXDP
func TestSyncEnableAFXDP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableAFXDP(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableAFXDP)
}

// TestSyncEnableRateLimit tests optimized SyncEnableRateLimit
// TestSyncEnableRateLimit 测试优化的 SyncEnableRateLimit
func TestSyncEnableRateLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableRateLimit(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableRateLimit)
}

// TestSyncDropFragments tests optimized SyncDropFragments
// TestSyncDropFragments 测试优化的 SyncDropFragments
func TestSyncDropFragments(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncDropFragments(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DropFragments)
}

// TestSyncStrictTCP tests optimized SyncStrictTCP
// TestSyncStrictTCP 测试优化的 SyncStrictTCP
func TestSyncStrictTCP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncStrictTCP(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.StrictTCP)
}

// TestSyncSYNLimit tests optimized SyncSYNLimit
// TestSyncSYNLimit 测试优化的 SyncSYNLimit
func TestSyncSYNLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncSYNLimit(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.SYNLimit)
}

// TestSyncBogonFilter tests optimized SyncBogonFilter
// TestSyncBogonFilter 测试优化的 SyncBogonFilter
func TestSyncBogonFilter(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncBogonFilter(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.BogonFilter)
}

// Table-driven tests for optimized sync functions
// 优化同步函数的表驱动测试

// TestTableDriven_SyncBoolSettings tests all optimized boolean sync functions
// TestTableDriven_SyncBoolSettings 测试所有优化的布尔同步函数
func TestTableDriven_SyncBoolSettings(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	testCases := []struct {
		name     string
		syncFunc func(context.Context, xdp.ManagerInterface, bool) error
		enable   bool
	}{
		{"SyncDefaultDeny_Enable", SyncDefaultDeny, true},
		{"SyncDefaultDeny_Disable", SyncDefaultDeny, false},
		{"SyncEnableAFXDP_Enable", SyncEnableAFXDP, true},
		{"SyncEnableAFXDP_Disable", SyncEnableAFXDP, false},
		{"SyncEnableRateLimit_Enable", SyncEnableRateLimit, true},
		{"SyncEnableRateLimit_Disable", SyncEnableRateLimit, false},
		{"SyncDropFragments_Enable", SyncDropFragments, true},
		{"SyncDropFragments_Disable", SyncDropFragments, false},
		{"SyncStrictTCP_Enable", SyncStrictTCP, true},
		{"SyncStrictTCP_Disable", SyncStrictTCP, false},
		{"SyncSYNLimit_Enable", SyncSYNLimit, true},
		{"SyncSYNLimit_Disable", SyncSYNLimit, false},
		{"SyncBogonFilter_Enable", SyncBogonFilter, true},
		{"SyncBogonFilter_Disable", SyncBogonFilter, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.syncFunc(ctx, mockMgr, tc.enable)
			assert.NoError(t, err)
		})
	}
}

// TestConfigCache_ConcurrentAccess tests concurrent access to config cache
// TestConfigCache_ConcurrentAccess 测试配置缓存的并发访问
func TestConfigCache_ConcurrentAccess(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)

	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx := context.Background()

			err := cache.UpdateConfig(func(cfg *types.GlobalConfig) {
			})
			assert.NoError(t, err)

			cache.SaveConfigDelayed(ctx)
		}(i)
	}

	wg.Wait()
}

// TestConfigCache_SaveConfigImmediate tests immediate save
// TestConfigCache_SaveConfigImmediate 测试立即保存
func TestConfigCache_SaveConfigImmediate(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	err := cache.UpdateConfig(func(cfg *types.GlobalConfig) {
	})
	assert.NoError(t, err)
	assert.True(t, cache.IsDirty())

	err = cache.SaveConfigImmediate()
	assert.NoError(t, err)
	assert.False(t, cache.IsDirty())
}

// BenchmarkSyncDefaultDeny_Original benchmarks original SyncDefaultDeny
// BenchmarkSyncDefaultDeny_Original 基准测试原始 SyncDefaultDeny
func BenchmarkSyncDefaultDeny_Original(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncDefaultDeny(ctx, mockMgr, true)
	}
}

// BenchmarkSyncDefaultDeny_ benchmarks optimized SyncDefaultDeny
// BenchmarkSyncDefaultDeny_ 基准测试优化的 SyncDefaultDeny
func BenchmarkSyncDefaultDeny_(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncDefaultDeny(ctx, mockMgr, true)
	}
}

// BenchmarkSyncBoolSetting_Original benchmarks original sync function
// BenchmarkSyncBoolSetting_Original 基准测试原始同步函数
func BenchmarkSyncBoolSetting_Original(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = syncBoolSettingWithConfig(ctx, mockMgr, true,
			mockMgr.SetDefaultDeny,
			func(cfg *types.GlobalConfig, v bool) { cfg.Base.DefaultDeny = v },
			"test", "Test: %v")
	}
}

// BenchmarkSyncBoolSetting_ benchmarks optimized sync function
// BenchmarkSyncBoolSetting_ 基准测试优化的同步函数
func BenchmarkSyncBoolSetting_(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = syncBoolSettingWithConfig(ctx, mockMgr, true,
			mockMgr.SetDefaultDeny,
			func(cfg *types.GlobalConfig, v bool) { cfg.Base.DefaultDeny = v },
			"test", "Test: %v")
	}
}

// BenchmarkConfigCache_LoadConfig benchmarks config loading with cache
// BenchmarkConfigCache_LoadConfig 基准测试带缓存的配置加载
func BenchmarkConfigCache_LoadConfig(b *testing.B) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.LoadConfig()
	}
}

// BenchmarkConfigCache_UpdateConfig benchmarks config update with cache
// BenchmarkConfigCache_UpdateConfig 基准测试带缓存的配置更新
func BenchmarkConfigCache_UpdateConfig(b *testing.B) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.UpdateConfig(func(cfg *types.GlobalConfig) {
		})
	}
}

// BenchmarkConfigCache_SaveConfigDelayed benchmarks delayed save
// BenchmarkConfigCache_SaveConfigDelayed 基准测试延迟保存
func BenchmarkConfigCache_SaveConfigDelayed(b *testing.B) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.SaveConfigDelayed(ctx)
	}
}

// BenchmarkParallel_SyncDefaultDeny_ benchmarks parallel optimized sync
// BenchmarkParallel_SyncDefaultDeny_ 基准测试并行优化同步
func BenchmarkParallel_SyncDefaultDeny_(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = SyncDefaultDeny(ctx, mockMgr, true)
		}
	})
}
