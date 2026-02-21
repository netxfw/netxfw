package xdp

import (
	"sync"
	"time"

	"github.com/netxfw/netxfw/pkg/sdk"
)

// StatsCache provides cached statistics with incremental updates.
// StatsCache 提供带增量更新的缓存统计信息。
type StatsCache struct {
	mu sync.RWMutex

	// Cached statistics / 缓存的统计信息
	globalStats *GlobalStats
	dropDetails []sdk.DropDetailEntry
	passDetails []sdk.DropDetailEntry
	mapCounts   MapCounts

	// Cache timestamps / 缓存时间戳
	lastGlobalUpdate time.Time
	lastDropUpdate   time.Time
	lastPassUpdate   time.Time
	//nolint:unused // Reserved for future map counts caching
	lastMapCountsUpdate time.Time

	// Cache TTL (time-to-live) / 缓存有效期
	globalTTL    time.Duration
	detailsTTL   time.Duration
	mapCountsTTL time.Duration

	// Manager reference / Manager 引用
	mgr *Manager
}

// MapCounts holds cached map entry counts.
// MapCounts 保存缓存的 Map 条目计数。
type MapCounts struct {
	Blacklist        uint64    `json:"blacklist"`         // Blacklist entries / 黑名单条目数
	Whitelist        uint64    `json:"whitelist"`         // Whitelist entries / 白名单条目数
	Conntrack        uint64    `json:"conntrack"`         // Conntrack entries / 连接跟踪条目数
	DynamicBlacklist uint64    `json:"dynamic_blacklist"` // Dynamic blacklist entries / 动态黑名单条目数
	UpdatedAt        time.Time `json:"updated_at"`        // Last update time / 最后更新时间
}

// NewStatsCache creates a new statistics cache.
// NewStatsCache 创建新的统计缓存。
func NewStatsCache(mgr *Manager) *StatsCache {
	return &StatsCache{
		mgr: mgr,
		// Default TTLs / 默认有效期
		globalTTL:    5 * time.Second,  // Global stats refresh every 5s / 全局统计每 5 秒刷新
		detailsTTL:   10 * time.Second, // Details refresh every 10s / 详细统计每 10 秒刷新
		mapCountsTTL: 30 * time.Second, // Map counts refresh every 30s / Map 计数每 30 秒刷新
	}
}

// SetTTL sets custom cache TTL values.
// SetTTL 设置自定义缓存有效期。
func (c *StatsCache) SetTTL(global, details, mapCounts time.Duration) {
	c.globalTTL = global
	c.detailsTTL = details
	c.mapCountsTTL = mapCounts
}

// cacheHelper provides common cache operations with double-checked locking.
// cacheHelper 提供带有双重检查锁定的通用缓存操作。
func (c *StatsCache) cacheHelper(
	cacheName string,
	isValid func() bool,
	recordHit func(),
	fetchData func() error,
) bool {
	// First check with read lock
	c.mu.RLock()
	if isValid() {
		defer c.mu.RUnlock()
		if c.mgr.perfStats != nil {
			c.mgr.perfStats.RecordCacheHit(cacheName)
		}
		recordHit()
		return true
	}
	c.mu.RUnlock()

	// Record cache miss
	if c.mgr.perfStats != nil {
		c.mgr.perfStats.RecordCacheMiss(cacheName)
	}

	// Acquire write lock for refresh
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check after acquiring write lock
	if isValid() {
		recordHit()
		return true
	}

	// Fetch fresh data
	return fetchData() == nil
}

// GetGlobalStats returns cached global statistics, refreshing if expired.
// GetGlobalStats 返回缓存的全局统计，如果过期则刷新。
func (c *StatsCache) GetGlobalStats() (*GlobalStats, error) {
	var result *GlobalStats
	var fetchErr error

	c.cacheHelper(
		"global_stats",
		func() bool { return c.globalStats != nil && time.Since(c.lastGlobalUpdate) < c.globalTTL },
		func() { result = c.globalStats },
		func() error {
			stats, err := c.mgr.GetGlobalStats()
			if err != nil {
				if c.globalStats != nil {
					result = c.globalStats
					return nil
				}
				fetchErr = err
				return err
			}
			c.globalStats = stats
			c.lastGlobalUpdate = time.Now()
			result = stats
			return nil
		},
	)

	return result, fetchErr
}

// GetDropDetails returns cached drop details, refreshing if expired.
// GetDropDetails 返回缓存的丢弃详情，如果过期则刷新。
func (c *StatsCache) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	var result []sdk.DropDetailEntry
	var fetchErr error

	c.cacheHelper(
		"drop_details",
		func() bool { return c.dropDetails != nil && time.Since(c.lastDropUpdate) < c.detailsTTL },
		func() { result = c.dropDetails },
		func() error {
			details, err := c.mgr.GetDropDetails()
			if err != nil {
				if c.dropDetails != nil {
					result = c.dropDetails
					return nil
				}
				fetchErr = err
				return err
			}
			c.dropDetails = details
			c.lastDropUpdate = time.Now()
			result = details
			return nil
		},
	)

	return result, fetchErr
}

// GetPassDetails returns cached pass details, refreshing if expired.
// GetPassDetails 返回缓存的通过详情，如果过期则刷新。
func (c *StatsCache) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	var result []sdk.DropDetailEntry
	var fetchErr error

	c.cacheHelper(
		"pass_details",
		func() bool { return c.passDetails != nil && time.Since(c.lastPassUpdate) < c.detailsTTL },
		func() { result = c.passDetails },
		func() error {
			details, err := c.mgr.GetPassDetails()
			if err != nil {
				if c.passDetails != nil {
					result = c.passDetails
					return nil
				}
				fetchErr = err
				return err
			}
			c.passDetails = details
			c.lastPassUpdate = time.Now()
			result = details
			return nil
		},
	)

	return result, fetchErr
}

// GetMapCounts returns cached map entry counts, refreshing if expired.
// GetMapCounts 返回缓存的 Map 条目计数，如果过期则刷新。
func (c *StatsCache) GetMapCounts() (MapCounts, error) {
	var result MapCounts

	c.cacheHelper(
		"map_counts",
		func() bool {
			return !c.mapCounts.UpdatedAt.IsZero() && time.Since(c.mapCounts.UpdatedAt) < c.mapCountsTTL
		},
		func() { result = c.mapCounts },
		func() error {
			blacklist, _ := c.mgr.GetLockedIPCount()
			whitelist, _ := c.mgr.GetWhitelistCount()
			conntrack, _ := c.mgr.GetConntrackCount()
			dynamicBlacklist, _ := c.mgr.GetDynLockListCount()

			c.mapCounts = MapCounts{
				Blacklist:        blacklist,
				Whitelist:        whitelist,
				Conntrack:        conntrack,
				DynamicBlacklist: dynamicBlacklist,
				UpdatedAt:        time.Now(),
			}
			result = c.mapCounts
			return nil
		},
	)

	return result, nil
}

// InvalidateAll clears all cached data.
// InvalidateAll 清除所有缓存数据。
func (c *StatsCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.globalStats = nil
	c.dropDetails = nil
	c.passDetails = nil
	c.mapCounts = MapCounts{}
	c.lastGlobalUpdate = time.Time{}
	c.lastDropUpdate = time.Time{}
	c.lastPassUpdate = time.Time{}
}

// InvalidateGlobal clears global stats cache.
// InvalidateGlobal 清除全局统计缓存。
func (c *StatsCache) InvalidateGlobal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.globalStats = nil
	c.lastGlobalUpdate = time.Time{}
}

// InvalidateDetails clears details cache.
// InvalidateDetails 清除详情缓存。
func (c *StatsCache) InvalidateDetails() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropDetails = nil
	c.passDetails = nil
	c.lastDropUpdate = time.Time{}
	c.lastPassUpdate = time.Time{}
}

// InvalidateMapCounts clears map counts cache.
// InvalidateMapCounts 清除 Map 计数缓存。
func (c *StatsCache) InvalidateMapCounts() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mapCounts = MapCounts{}
}

// GetCacheInfo returns cache status information.
// GetCacheInfo 返回缓存状态信息。
func (c *StatsCache) GetCacheInfo() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"global_stats_cached": c.globalStats != nil,
		"drop_details_cached": c.dropDetails != nil,
		"pass_details_cached": c.passDetails != nil,
		"map_counts_cached":   !c.mapCounts.UpdatedAt.IsZero(),
		"global_stats_ttl":    c.globalTTL.String(),
		"drop_details_ttl":    c.detailsTTL.String(),
		"map_counts_ttl":      c.mapCountsTTL.String(),
	}
}
