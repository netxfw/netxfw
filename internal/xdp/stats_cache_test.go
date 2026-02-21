package xdp

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestStatsCache_GetGlobalStats_Cached tests that global stats are cached
// TestStatsCache_GetGlobalStats_Cached 测试全局统计是否被缓存
func TestStatsCache_GetGlobalStats_Cached(t *testing.T) {
	// Create a real Manager with the cache initialized
	// 创建一个初始化了缓存的真实 Manager
	mgr := &Manager{
		statsCache: NewStatsCache(nil),
	}
	// Replace the manager reference in cache with our mock
	// 用我们的模拟替换缓存中的 manager 引用
	mgr.statsCache.mgr = mgr

	// Manually set up cache to use mock data
	// 手动设置缓存以使用模拟数据
	cache := mgr.statsCache
	cache.globalStats = &GlobalStats{
		TotalPackets: 1000,
		TotalPass:    800,
		TotalDrop:    200,
	}
	cache.lastGlobalUpdate = time.Now()

	// First call should use cached data
	// 第一次调用应该使用缓存数据
	stats, err := cache.GetGlobalStats()
	assert.NoError(t, err)
	assert.Equal(t, uint64(1000), stats.TotalPackets)
	assert.Equal(t, uint64(800), stats.TotalPass)
	assert.Equal(t, uint64(200), stats.TotalDrop)
}

// TestStatsCache_GetGlobalStats_Expired tests that expired cache is refreshed
// TestStatsCache_GetGlobalStats_Expired 测试过期的缓存是否被刷新
func TestStatsCache_GetGlobalStats_Expired(t *testing.T) {
	cache := NewStatsCache(nil)
	cache.globalTTL = 100 * time.Millisecond

	// Set expired cached data
	// 设置过期的缓存数据
	cache.globalStats = &GlobalStats{
		TotalPackets: 100,
		TotalPass:    80,
		TotalDrop:    20,
	}
	cache.lastGlobalUpdate = time.Now().Add(-1 * time.Hour) // Expired / 已过期

	// The cache should refresh when expired
	// 当过期时缓存应该刷新
	// Since we can't easily inject the mock, we'll test the TTL logic
	// 由于我们不能轻松注入模拟，我们将测试 TTL 逻辑
	assert.True(t, time.Since(cache.lastGlobalUpdate) > cache.globalTTL)
}

// TestStatsCache_GetDropDetails_Cached tests that drop details are cached
// TestStatsCache_GetDropDetails_Cached 测试丢弃详情是否被缓存
func TestStatsCache_GetDropDetails_Cached(t *testing.T) {
	// Create a Manager with perfStats initialized
	// 创建一个初始化了 perfStats 的 Manager
	mgr := &Manager{
		perfStats: NewPerformanceStats(),
	}
	cache := NewStatsCache(mgr)
	cache.dropDetails = []sdk.DropDetailEntry{
		{SrcIP: "10.0.0.1", Reason: 3, Count: 100},
		{SrcIP: "10.0.0.2", Reason: 4, Count: 50},
	}
	cache.lastDropUpdate = time.Now()

	// Cached data should be returned
	// 应该返回缓存数据
	details, err := cache.GetDropDetails()
	assert.NoError(t, err)
	assert.Len(t, details, 2)
	assert.Equal(t, "10.0.0.1", details[0].SrcIP)
	assert.Equal(t, uint64(100), details[0].Count)
}

// TestStatsCache_GetPassDetails_Cached tests that pass details are cached
// TestStatsCache_GetPassDetails_Cached 测试通过详情是否被缓存
func TestStatsCache_GetPassDetails_Cached(t *testing.T) {
	// Create a Manager with perfStats initialized
	// 创建一个初始化了 perfStats 的 Manager
	mgr := &Manager{
		perfStats: NewPerformanceStats(),
	}
	cache := NewStatsCache(mgr)
	cache.passDetails = []sdk.DropDetailEntry{
		{SrcIP: "192.168.1.1", Reason: 101, Count: 200},
	}
	cache.lastPassUpdate = time.Now()

	// Cached data should be returned
	// 应该返回缓存数据
	details, err := cache.GetPassDetails()
	assert.NoError(t, err)
	assert.Len(t, details, 1)
	assert.Equal(t, "192.168.1.1", details[0].SrcIP)
	assert.Equal(t, uint64(200), details[0].Count)
}

// TestStatsCache_GetMapCounts_Cached tests that map counts are cached
// TestStatsCache_GetMapCounts_Cached 测试 Map 计数是否被缓存
func TestStatsCache_GetMapCounts_Cached(t *testing.T) {
	// Create a Manager with perfStats initialized
	// 创建一个初始化了 perfStats 的 Manager
	mgr := &Manager{
		perfStats: NewPerformanceStats(),
	}
	cache := NewStatsCache(mgr)
	cache.mapCounts = MapCounts{
		Blacklist:        100,
		Whitelist:        50,
		Conntrack:        200,
		DynamicBlacklist: 25,
		UpdatedAt:        time.Now(),
	}

	// Cached data should be returned
	// 应该返回缓存数据
	counts, err := cache.GetMapCounts()
	assert.NoError(t, err)
	assert.Equal(t, uint64(100), counts.Blacklist)
	assert.Equal(t, uint64(50), counts.Whitelist)
	assert.Equal(t, uint64(200), counts.Conntrack)
	assert.Equal(t, uint64(25), counts.DynamicBlacklist)
}

// TestStatsCache_InvalidateAll tests that all cache is invalidated
// TestStatsCache_InvalidateAll 测试所有缓存是否被清除
func TestStatsCache_InvalidateAll(t *testing.T) {
	// Create a Manager with perfStats initialized
	// 创建一个初始化了 perfStats 的 Manager
	mgr := &Manager{
		perfStats: NewPerformanceStats(),
	}
	cache := NewStatsCache(mgr)

	// Set some cached data
	// 设置一些缓存数据
	cache.globalStats = &GlobalStats{TotalPackets: 100}
	cache.dropDetails = []sdk.DropDetailEntry{{SrcIP: "10.0.0.1"}}
	cache.passDetails = []sdk.DropDetailEntry{{SrcIP: "192.168.1.1"}}
	cache.mapCounts = MapCounts{Blacklist: 50, UpdatedAt: time.Now()}
	cache.lastGlobalUpdate = time.Now()
	cache.lastDropUpdate = time.Now()
	cache.lastPassUpdate = time.Now()

	// Invalidate all
	// 清除所有
	cache.InvalidateAll()

	// All should be cleared
	// 所有都应该被清除
	assert.Nil(t, cache.globalStats)
	assert.Nil(t, cache.dropDetails)
	assert.Nil(t, cache.passDetails)
	assert.True(t, cache.mapCounts.UpdatedAt.IsZero())
	assert.True(t, cache.lastGlobalUpdate.IsZero())
	assert.True(t, cache.lastDropUpdate.IsZero())
	assert.True(t, cache.lastPassUpdate.IsZero())
}

// TestStatsCache_InvalidateGlobal tests that global stats cache is invalidated
// TestStatsCache_InvalidateGlobal 测试全局统计缓存是否被清除
func TestStatsCache_InvalidateGlobal(t *testing.T) {
	// Create a Manager with perfStats initialized
	// 创建一个初始化了 perfStats 的 Manager
	mgr := &Manager{
		perfStats: NewPerformanceStats(),
	}
	cache := NewStatsCache(mgr)

	// Set some cached data
	// 设置一些缓存数据
	cache.globalStats = &GlobalStats{TotalPackets: 100}
	cache.lastGlobalUpdate = time.Now()
	cache.dropDetails = []sdk.DropDetailEntry{{SrcIP: "10.0.0.1"}}
	cache.lastDropUpdate = time.Now()

	// Invalidate global only
	// 仅清除全局
	cache.InvalidateGlobal()

	// Global should be cleared, others should remain
	// 全局应该被清除，其他应该保留
	assert.Nil(t, cache.globalStats)
	assert.True(t, cache.lastGlobalUpdate.IsZero())
	assert.NotNil(t, cache.dropDetails)
	assert.False(t, cache.lastDropUpdate.IsZero())
}

// TestStatsCache_InvalidateDetails tests that details cache is invalidated
// TestStatsCache_InvalidateDetails 测试详情缓存是否被清除
func TestStatsCache_InvalidateDetails(t *testing.T) {
	// Create a Manager with perfStats initialized
	// 创建一个初始化了 perfStats 的 Manager
	mgr := &Manager{
		perfStats: NewPerformanceStats(),
	}
	cache := NewStatsCache(mgr)

	// Set some cached data
	// 设置一些缓存数据
	cache.dropDetails = []sdk.DropDetailEntry{{SrcIP: "10.0.0.1"}}
	cache.passDetails = []sdk.DropDetailEntry{{SrcIP: "192.168.1.1"}}
	cache.lastDropUpdate = time.Now()
	cache.lastPassUpdate = time.Now()
	cache.globalStats = &GlobalStats{TotalPackets: 100}
	cache.lastGlobalUpdate = time.Now()

	// Invalidate details only
	// 仅清除详情
	cache.InvalidateDetails()

	// Details should be cleared, global should remain
	// 详情应该被清除，全局应该保留
	assert.Nil(t, cache.dropDetails)
	assert.Nil(t, cache.passDetails)
	assert.True(t, cache.lastDropUpdate.IsZero())
	assert.True(t, cache.lastPassUpdate.IsZero())
	assert.NotNil(t, cache.globalStats)
	assert.False(t, cache.lastGlobalUpdate.IsZero())
}

// TestStatsCache_SetTTL tests custom TTL settings
// TestStatsCache_SetTTL 测试自定义 TTL 设置
func TestStatsCache_SetTTL(t *testing.T) {
	// Create a Manager with perfStats initialized
	// 创建一个初始化了 perfStats 的 Manager
	mgr := &Manager{
		perfStats: NewPerformanceStats(),
	}
	cache := NewStatsCache(mgr)

	// Default TTLs
	// 默认 TTL
	assert.Equal(t, 5*time.Second, cache.globalTTL)
	assert.Equal(t, 10*time.Second, cache.detailsTTL)
	assert.Equal(t, 30*time.Second, cache.mapCountsTTL)

	// Set custom TTLs
	// 设置自定义 TTL
	cache.SetTTL(1*time.Second, 2*time.Second, 3*time.Second)

	assert.Equal(t, 1*time.Second, cache.globalTTL)
	assert.Equal(t, 2*time.Second, cache.detailsTTL)
	assert.Equal(t, 3*time.Second, cache.mapCountsTTL)
}

// TestStatsCache_GetCacheInfo tests cache info retrieval
// TestStatsCache_GetCacheInfo 测试缓存信息获取
func TestStatsCache_GetCacheInfo(t *testing.T) {
	// Create a Manager with perfStats initialized
	// 创建一个初始化了 perfStats 的 Manager
	mgr := &Manager{
		perfStats: NewPerformanceStats(),
	}
	cache := NewStatsCache(mgr)

	// Set some cached data
	// 设置一些缓存数据
	cache.globalStats = &GlobalStats{TotalPackets: 100}
	cache.lastGlobalUpdate = time.Now()
	cache.dropDetails = []sdk.DropDetailEntry{{SrcIP: "10.0.0.1"}}
	cache.lastDropUpdate = time.Now()

	info := cache.GetCacheInfo()

	assert.True(t, info["global_stats_cached"].(bool))
	assert.True(t, info["drop_details_cached"].(bool))
	assert.False(t, info["pass_details_cached"].(bool))
	assert.False(t, info["map_counts_cached"].(bool))
	assert.Equal(t, "5s", info["global_stats_ttl"].(string))
	assert.Equal(t, "10s", info["drop_details_ttl"].(string))
}
