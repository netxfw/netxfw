package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
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

// TestSyncBoolSettingWithConfigOptimized tests optimized sync function
// TestSyncBoolSettingWithConfigOptimized 测试优化的同步函数
func TestSyncBoolSettingWithConfigOptimized(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := syncBoolSettingWithConfigOptimized(ctx, mockMgr, true,
		mockMgr.SetDefaultDeny,
		func(cfg *types.GlobalConfig, v bool) { cfg.Base.DefaultDeny = v },
		"test setting", "Test setting set to: %v")
	assert.NoError(t, err)
}

// TestSyncDefaultDenyOptimized tests optimized SyncDefaultDeny
// TestSyncDefaultDenyOptimized 测试优化的 SyncDefaultDeny
func TestSyncDefaultDenyOptimized(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncDefaultDenyOptimized(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DefaultDeny)

	err = SyncDefaultDenyOptimized(ctx, mockMgr, false)
	assert.NoError(t, err)
	assert.False(t, mockMgr.DefaultDeny)
}

// TestSyncEnableAFXDPOptimized tests optimized SyncEnableAFXDP
// TestSyncEnableAFXDPOptimized 测试优化的 SyncEnableAFXDP
func TestSyncEnableAFXDPOptimized(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableAFXDPOptimized(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableAFXDP)
}

// TestSyncEnableRateLimitOptimized tests optimized SyncEnableRateLimit
// TestSyncEnableRateLimitOptimized 测试优化的 SyncEnableRateLimit
func TestSyncEnableRateLimitOptimized(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncEnableRateLimitOptimized(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.EnableRateLimit)
}

// TestSyncDropFragmentsOptimized tests optimized SyncDropFragments
// TestSyncDropFragmentsOptimized 测试优化的 SyncDropFragments
func TestSyncDropFragmentsOptimized(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncDropFragmentsOptimized(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.DropFragments)
}

// TestSyncStrictTCPOptimized tests optimized SyncStrictTCP
// TestSyncStrictTCPOptimized 测试优化的 SyncStrictTCP
func TestSyncStrictTCPOptimized(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncStrictTCPOptimized(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.StrictTCP)
}

// TestSyncSYNLimitOptimized tests optimized SyncSYNLimit
// TestSyncSYNLimitOptimized 测试优化的 SyncSYNLimit
func TestSyncSYNLimitOptimized(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncSYNLimitOptimized(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.SYNLimit)
}

// TestSyncBogonFilterOptimized tests optimized SyncBogonFilter
// TestSyncBogonFilterOptimized 测试优化的 SyncBogonFilter
func TestSyncBogonFilterOptimized(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncBogonFilterOptimized(ctx, mockMgr, true)
	assert.NoError(t, err)
	assert.True(t, mockMgr.BogonFilter)
}

// Table-driven tests for optimized sync functions
// 优化同步函数的表驱动测试

// TestTableDriven_SyncBoolSettingsOptimized tests all optimized boolean sync functions
// TestTableDriven_SyncBoolSettingsOptimized 测试所有优化的布尔同步函数
func TestTableDriven_SyncBoolSettingsOptimized(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	testCases := []struct {
		name     string
		syncFunc func(context.Context, xdp.ManagerInterface, bool) error
		enable   bool
	}{
		{"SyncDefaultDenyOptimized_Enable", SyncDefaultDenyOptimized, true},
		{"SyncDefaultDenyOptimized_Disable", SyncDefaultDenyOptimized, false},
		{"SyncEnableAFXDPOptimized_Enable", SyncEnableAFXDPOptimized, true},
		{"SyncEnableAFXDPOptimized_Disable", SyncEnableAFXDPOptimized, false},
		{"SyncEnableRateLimitOptimized_Enable", SyncEnableRateLimitOptimized, true},
		{"SyncEnableRateLimitOptimized_Disable", SyncEnableRateLimitOptimized, false},
		{"SyncDropFragmentsOptimized_Enable", SyncDropFragmentsOptimized, true},
		{"SyncDropFragmentsOptimized_Disable", SyncDropFragmentsOptimized, false},
		{"SyncStrictTCPOptimized_Enable", SyncStrictTCPOptimized, true},
		{"SyncStrictTCPOptimized_Disable", SyncStrictTCPOptimized, false},
		{"SyncSYNLimitOptimized_Enable", SyncSYNLimitOptimized, true},
		{"SyncSYNLimitOptimized_Disable", SyncSYNLimitOptimized, false},
		{"SyncBogonFilterOptimized_Enable", SyncBogonFilterOptimized, true},
		{"SyncBogonFilterOptimized_Disable", SyncBogonFilterOptimized, false},
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

// BenchmarkSyncDefaultDeny_Optimized benchmarks optimized SyncDefaultDeny
// BenchmarkSyncDefaultDeny_Optimized 基准测试优化的 SyncDefaultDeny
func BenchmarkSyncDefaultDeny_Optimized(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncDefaultDenyOptimized(ctx, mockMgr, true)
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

// BenchmarkSyncBoolSetting_Optimized benchmarks optimized sync function
// BenchmarkSyncBoolSetting_Optimized 基准测试优化的同步函数
func BenchmarkSyncBoolSetting_Optimized(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = syncBoolSettingWithConfigOptimized(ctx, mockMgr, true,
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

// BenchmarkParallel_SyncDefaultDeny_Optimized benchmarks parallel optimized sync
// BenchmarkParallel_SyncDefaultDeny_Optimized 基准测试并行优化同步
func BenchmarkParallel_SyncDefaultDeny_Optimized(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = SyncDefaultDenyOptimized(ctx, mockMgr, true)
		}
	})
}
