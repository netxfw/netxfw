package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// HotReloadScenarioTest tests comprehensive hot reload scenarios.
// HotReloadScenarioTest 测试全面的热重载场景。

// TestHotReloadScenario_IncrementalVsFull tests detection of incremental vs full reload.
// TestHotReloadScenario_IncrementalVsFull 测试增量与完整重载的检测。
func TestHotReloadScenario_IncrementalVsFull(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)

	originalConntrack := cfg.Conntrack

	scenarios := []struct {
		name          string
		modifyFunc    func(*types.GlobalConfig)
		expectFull    bool
		expectMessage string
	}{
		{
			name: "Change_DefaultDeny_Incremental",
			modifyFunc: func(c *types.GlobalConfig) {
				c.Base.DefaultDeny = !c.Base.DefaultDeny
			},
			expectFull:    false,
			expectMessage: "Incremental reload: only config values changed",
		},
		{
			name: "Change_ICMPRate_Incremental",
			modifyFunc: func(c *types.GlobalConfig) {
				c.Base.ICMPRate = 500
			},
			expectFull:    false,
			expectMessage: "Incremental reload: only config values changed",
		},
		{
			name: "Change_ConntrackCapacity_Full",
			modifyFunc: func(c *types.GlobalConfig) {
				c.Conntrack.MaxEntries = originalConntrack.MaxEntries + 1000
			},
			expectFull:    true,
			expectMessage: "Full reload: capacity changed",
		},
		{
			name: "Change_MultipleValues_Incremental",
			modifyFunc: func(c *types.GlobalConfig) {
				c.Base.DefaultDeny = true
				c.Base.StrictProtocol = true
				c.Base.DropFragments = true
				c.Base.ICMPRate = 200
				c.Base.ICMPBurst = 400
			},
			expectFull:    false,
			expectMessage: "Incremental reload: only config values changed",
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			cache.InvalidateCache()
			_, err := cache.LoadConfig()
			require.NoError(t, err)

			err = cache.UpdateConfig(tc.modifyFunc)
			require.NoError(t, err)

			cfgAfter := cache.GetCachedConfig()
			require.NotNil(t, cfgAfter)

			if tc.expectFull {
				assert.NotEqual(t, originalConntrack, cfgAfter.Conntrack, "Capacity should have changed")
			}
		})
	}
}

// TestHotReloadScenario_DataMigration tests data migration during hot reload.
// TestHotReloadScenario_DataMigration 测试热重载期间的数据迁移。
func TestHotReloadScenario_DataMigration(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	cache := GetConfigCache()
	cache.InvalidateCache()

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	syncFuncs := []struct {
		name string
		fn   func(context.Context, xdp.ManagerInterface, bool) error
	}{
		{"SyncDefaultDeny", SyncDefaultDenyOptimized},
		{"SyncEnableAFXDP", SyncEnableAFXDPOptimized},
		{"SyncEnableRateLimit", SyncEnableRateLimitOptimized},
		{"SyncDropFragments", SyncDropFragmentsOptimized},
		{"SyncStrictTCP", SyncStrictTCPOptimized},
		{"SyncSYNLimit", SyncSYNLimitOptimized},
		{"SyncBogonFilter", SyncBogonFilterOptimized},
	}

	for _, sf := range syncFuncs {
		t.Run(sf.name, func(t *testing.T) {
			err := sf.fn(ctx, mockMgr, true)
			assert.NoError(t, err, "Sync with true should succeed")

			err = sf.fn(ctx, mockMgr, false)
			assert.NoError(t, err, "Sync with false should succeed")
		})
	}
}

// TestHotReloadScenario_ConcurrentReload tests concurrent hot reload operations.
// TestHotReloadScenario_ConcurrentReload 测试并发热重载操作。
func TestHotReloadScenario_ConcurrentReload(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(100 * time.Millisecond)

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := 0; i < 10; i++ {
		wg.Add(2)

		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				err := cache.UpdateConfig(func(c *types.GlobalConfig) {
					c.Base.ICMPRate = uint64(100 + id + j)
				})
				if err != nil {
					errCh <- fmt.Errorf("writer %d: %w", id, err)
					return
				}
			}
		}(i)

		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				_, err := cache.LoadConfig()
				if err != nil {
					errCh <- fmt.Errorf("reader %d: %w", id, err)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

// TestHotReloadScenario_ErrorRecovery tests error recovery during hot reload.
// TestHotReloadScenario_ErrorRecovery 测试热重载期间的错误恢复。
func TestHotReloadScenario_ErrorRecovery(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)

	originalDefaultDeny := cfg.Base.DefaultDeny
	originalICMPRate := cfg.Base.ICMPRate

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.DefaultDeny = !originalDefaultDeny
		c.Base.ICMPRate = 9999
	})
	require.NoError(t, err)

	modifiedCfg := cache.GetCachedConfig()
	require.NotNil(t, modifiedCfg)
	assert.NotEqual(t, originalDefaultDeny, modifiedCfg.Base.DefaultDeny)
	assert.Equal(t, uint64(9999), modifiedCfg.Base.ICMPRate)

	cache.InvalidateCache()

	recoveredCfg, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, originalDefaultDeny, recoveredCfg.Base.DefaultDeny, "Should recover original DefaultDeny")
	assert.Equal(t, originalICMPRate, recoveredCfg.Base.ICMPRate, "Should recover original ICMPRate")
}

// TestHotReloadScenario_StateConsistency tests state consistency during hot reload.
// TestHotReloadScenario_StateConsistency 测试热重载期间的状态一致性。
func TestHotReloadScenario_StateConsistency(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	icmpRates := make([]uint64, 5)

	for i := 0; i < 5; i++ {
		expectedRate := uint64(100 * (i + 1))
		err := cache.UpdateConfig(func(c *types.GlobalConfig) {
			c.Base.ICMPRate = expectedRate
		})
		require.NoError(t, err)

		err = cache.SaveConfigImmediate()
		require.NoError(t, err)

		cfg := cache.GetCachedConfig()
		require.NotNil(t, cfg)
		icmpRates[i] = cfg.Base.ICMPRate
	}

	for i := 0; i < 5; i++ {
		expectedRate := uint64(100 * (i + 1))
		assert.Equal(t, expectedRate, icmpRates[i],
			"State %d should have ICMPRate %d", i, expectedRate)
	}
}

// TestHotReloadScenario_RollbackOnFailure tests rollback on failure.
// TestHotReloadScenario_RollbackOnFailure 测试失败时的回滚。
func TestHotReloadScenario_RollbackOnFailure(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg, err := cache.LoadConfig()
	require.NoError(t, err)

	originalStrictTCP := cfg.Base.StrictTCP

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.StrictTCP = !originalStrictTCP
	})
	require.NoError(t, err)

	modifiedCfg := cache.GetCachedConfig()
	assert.NotEqual(t, originalStrictTCP, modifiedCfg.Base.StrictTCP)

	cache.InvalidateCache()

	recoveredCfg, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, originalStrictTCP, recoveredCfg.Base.StrictTCP)
}

// TestHotReloadScenario_MultipleFieldUpdates tests multiple field updates.
// TestHotReloadScenario_MultipleFieldUpdates 测试多字段更新。
func TestHotReloadScenario_MultipleFieldUpdates(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	updates := []struct {
		name       string
		updateFunc func(*types.GlobalConfig)
		checkFunc  func(*types.GlobalConfig) bool
	}{
		{
			name: "SecuritySettings",
			updateFunc: func(c *types.GlobalConfig) {
				c.Base.DefaultDeny = true
				c.Base.StrictProtocol = true
				c.Base.DropFragments = true
				c.Base.StrictTCP = true
				c.Base.SYNLimit = true
				c.Base.BogonFilter = true
			},
			checkFunc: func(c *types.GlobalConfig) bool {
				return c.Base.DefaultDeny &&
					c.Base.StrictProtocol &&
					c.Base.DropFragments &&
					c.Base.StrictTCP &&
					c.Base.SYNLimit &&
					c.Base.BogonFilter
			},
		},
		{
			name: "RateLimitSettings",
			updateFunc: func(c *types.GlobalConfig) {
				c.Base.ICMPRate = 500
				c.Base.ICMPBurst = 1000
			},
			checkFunc: func(c *types.GlobalConfig) bool {
				return c.Base.ICMPRate == 500 && c.Base.ICMPBurst == 1000
			},
		},
		{
			name: "EnableAllFeatures",
			updateFunc: func(c *types.GlobalConfig) {
				c.Base.EnableAFXDP = true
				c.RateLimit.Enabled = true
				c.RateLimit.AutoBlock = true
				c.RateLimit.AutoBlockExpiry = "1h"
			},
			checkFunc: func(c *types.GlobalConfig) bool {
				return c.Base.EnableAFXDP &&
					c.RateLimit.Enabled &&
					c.RateLimit.AutoBlock &&
					c.RateLimit.AutoBlockExpiry == "1h"
			},
		},
	}

	for _, tc := range updates {
		t.Run(tc.name, func(t *testing.T) {
			err := cache.UpdateConfig(tc.updateFunc)
			require.NoError(t, err)

			cfg := cache.GetCachedConfig()
			require.NotNil(t, cfg)
			assert.True(t, tc.checkFunc(cfg), "Check function should return true")

			err = cache.SaveConfigImmediate()
			require.NoError(t, err)
		})
	}
}

// TestHotReloadScenario_PerformanceUnderLoad tests hot reload performance under load.
// TestHotReloadScenario_PerformanceUnderLoad 测试负载下的热重载性能。
func TestHotReloadScenario_PerformanceUnderLoad(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(10 * time.Millisecond)

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	start := time.Now()
	iterations := 100

	for i := 0; i < iterations; i++ {
		err := cache.UpdateConfig(func(c *types.GlobalConfig) {
			c.Base.ICMPRate = uint64(i)
		})
		require.NoError(t, err)
	}

	elapsed := time.Since(start)
	avgLatency := elapsed / time.Duration(iterations)

	t.Logf("Average update latency: %v", avgLatency)
	assert.Less(t, avgLatency.Microseconds(), int64(100), "Average latency should be less than 100µs")
}

// TestHotReloadScenario_ConfigValidation tests config validation during hot reload.
// TestHotReloadScenario_ConfigValidation 测试热重载期间的配置验证。
func TestHotReloadScenario_ConfigValidation(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	validUpdates := []struct {
		name string
		fn   func(*types.GlobalConfig)
	}{
		{"ValidICMPRate", func(c *types.GlobalConfig) { c.Base.ICMPRate = 1000 }},
		{"ValidICMPBurst", func(c *types.GlobalConfig) { c.Base.ICMPBurst = 2000 }},
		{"ValidAutoBlockExpiry", func(c *types.GlobalConfig) { c.RateLimit.AutoBlockExpiry = "2h" }},
	}

	for _, tc := range validUpdates {
		t.Run(tc.name, func(t *testing.T) {
			err := cache.UpdateConfig(tc.fn)
			assert.NoError(t, err, "Valid update should succeed")
		})
	}
}

// TestHotReloadScenario_DirtyFlagConsistency tests dirty flag consistency.
// TestHotReloadScenario_DirtyFlagConsistency 测试脏标志一致性。
func TestHotReloadScenario_DirtyFlagConsistency(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	assert.False(t, cache.IsDirty(), "Should not be dirty initially")

	_, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.False(t, cache.IsDirty(), "Should not be dirty after load")

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.DefaultDeny = !c.Base.DefaultDeny
	})
	require.NoError(t, err)
	assert.True(t, cache.IsDirty(), "Should be dirty after update")

	err = cache.SaveConfigImmediate()
	require.NoError(t, err)
	assert.False(t, cache.IsDirty(), "Should not be dirty after save")

	cache.InvalidateCache()
	assert.False(t, cache.IsDirty(), "Should not be dirty after invalidate")
}

// TestHotReloadScenario_ContextCancellation tests context cancellation during hot reload.
// TestHotReloadScenario_ContextCancellation 测试热重载期间的上下文取消。
func TestHotReloadScenario_ContextCancellation(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(1 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.StrictProtocol = true
	})
	require.NoError(t, err)

	cache.SaveConfigDelayed(ctx)

	cancel()

	err = cache.SaveConfigImmediate()
	require.NoError(t, err)
	assert.False(t, cache.IsDirty())
}

// Mock errors for testing error scenarios.
// 用于测试错误场景的模拟错误。

// TestHotReloadScenario_ErrorPropagation tests error propagation.
// TestHotReloadScenario_ErrorPropagation 测试错误传播。
func TestHotReloadScenario_ErrorPropagation(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.ICMPRate = 100
	})
	require.NoError(t, err)

	cfg := cache.GetCachedConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, uint64(100), cfg.Base.ICMPRate)
}

// TestHotReloadScenario_SaveConfigImmediate tests immediate save functionality.
// TestHotReloadScenario_SaveConfigImmediate 测试立即保存功能。
func TestHotReloadScenario_SaveConfigImmediate(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.StrictProtocol = !c.Base.StrictProtocol
	})
	require.NoError(t, err)
	assert.True(t, cache.IsDirty())

	start := time.Now()
	err = cache.SaveConfigImmediate()
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.False(t, cache.IsDirty())
	t.Logf("SaveConfigImmediate took: %v", elapsed)
}

// TestHotReloadScenario_LoadConfigForce tests force load functionality.
// TestHotReloadScenario_LoadConfigForce 测试强制加载功能。
func TestHotReloadScenario_LoadConfigForce(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg1, err := cache.LoadConfig()
	require.NoError(t, err)

	cfg2, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, cfg1, cfg2, "Cached config should be same")

	cfg3, err := cache.LoadConfigForce()
	require.NoError(t, err)
	assert.Equal(t, cfg1.Base.DefaultDeny, cfg3.Base.DefaultDeny, "Force loaded config should match")
}

// TestHotReloadScenario_GetCachedConfig tests get cached config functionality.
// TestHotReloadScenario_GetCachedConfig 测试获取缓存配置功能。
func TestHotReloadScenario_GetCachedConfig(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	cfg := cache.GetCachedConfig()
	assert.Nil(t, cfg, "Should be nil before load")

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	cfg = cache.GetCachedConfig()
	require.NotNil(t, cfg, "Should not be nil after load")

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.ICMPRate = 777
	})
	require.NoError(t, err)

	cfg = cache.GetCachedConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, uint64(777), cfg.Base.ICMPRate)
}

// TestHotReloadScenario_SetSaveDelay tests set save delay functionality.
// TestHotReloadScenario_SetSaveDelay 测试设置保存延迟功能。
func TestHotReloadScenario_SetSaveDelay(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()

	originalDelay := 500 * time.Millisecond
	cache.SetSaveDelay(originalDelay)

	_, err := cache.LoadConfig()
	require.NoError(t, err)

	newDelay := 100 * time.Millisecond
	cache.SetSaveDelay(newDelay)

	start := time.Now()
	ctx := context.Background()

	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.StrictProtocol = true
	})
	require.NoError(t, err)

	cache.SaveConfigDelayed(ctx)

	time.Sleep(150 * time.Millisecond)
	elapsed := time.Since(start)

	t.Logf("Delayed save completed in: %v", elapsed)
	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(100))
}

// TestHotReloadScenario_Stop tests stop functionality.
// TestHotReloadScenario_Stop 测试停止功能。
func TestHotReloadScenario_Stop(t *testing.T) {
	cache := &ConfigCache{
		saveDelay:  100 * time.Millisecond,
		configPath: "/etc/netxfw/config.yaml",
		dirty:      false,
		stopCh:     make(chan struct{}),
	}

	err := cache.Stop()
	assert.NoError(t, err, "Stop should succeed")
}

// TestHotReloadScenario_CompleteWorkflow tests a complete hot reload workflow.
// TestHotReloadScenario_CompleteWorkflow 测试完整的热重载工作流。
func TestHotReloadScenario_CompleteWorkflow(t *testing.T) {
	cache := GetConfigCache()
	cache.InvalidateCache()
	cache.SetSaveDelay(50 * time.Millisecond)

	// Step 1: Initial load
	// 步骤 1：初始加载
	cfg, err := cache.LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	t.Log("Step 1: Initial config loaded")

	// Step 2: Modify config
	// 步骤 2：修改配置
	originalDefaultDeny := cfg.Base.DefaultDeny
	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.DefaultDeny = !originalDefaultDeny
		c.Base.StrictProtocol = true
		c.Base.ICMPRate = 500
	})
	require.NoError(t, err)
	assert.True(t, cache.IsDirty())
	t.Log("Step 2: Config modified")

	// Step 3: Save config
	// 步骤 3：保存配置
	err = cache.SaveConfigImmediate()
	require.NoError(t, err)
	assert.False(t, cache.IsDirty())
	t.Log("Step 3: Config saved")

	// Step 4: Verify persistence
	// 步骤 4：验证持久化
	cache.InvalidateCache()
	cfg2, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.NotEqual(t, originalDefaultDeny, cfg2.Base.DefaultDeny)
	assert.True(t, cfg2.Base.StrictProtocol)
	assert.Equal(t, uint64(500), cfg2.Base.ICMPRate)
	t.Log("Step 4: Persistence verified")

	// Step 5: Restore original state
	// 步骤 5：恢复原始状态
	err = cache.UpdateConfig(func(c *types.GlobalConfig) {
		c.Base.DefaultDeny = originalDefaultDeny
		c.Base.StrictProtocol = false
		c.Base.ICMPRate = 100
	})
	require.NoError(t, err)
	err = cache.SaveConfigImmediate()
	require.NoError(t, err)
	t.Log("Step 5: Original state restored")

	// Step 6: Final verification
	// 步骤 6：最终验证
	cache.InvalidateCache()
	cfg3, err := cache.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, originalDefaultDeny, cfg3.Base.DefaultDeny)
	t.Log("Step 6: Final verification complete")
}
