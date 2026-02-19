package xdp

import (
	"sync"
	"time"

	"github.com/livp123/netxfw/pkg/sdk"
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
	lastGlobalUpdate    time.Time
	lastDropUpdate      time.Time
	lastPassUpdate      time.Time
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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.globalTTL = global
	c.detailsTTL = details
	c.mapCountsTTL = mapCounts
}

// GetGlobalStats returns cached global statistics, refreshing if expired.
// GetGlobalStats 返回缓存的全局统计，如果过期则刷新。
func (c *StatsCache) GetGlobalStats() (*GlobalStats, error) {
	c.mu.RLock()
	// Return cached if still valid / 如果缓存有效则返回
	if c.globalStats != nil && time.Since(c.lastGlobalUpdate) < c.globalTTL {
		defer c.mu.RUnlock()
		// Record cache hit / 记录缓存命中
		if c.mgr.perfStats != nil {
			c.mgr.perfStats.RecordCacheHit("global_stats")
		}
		return c.globalStats, nil
	}
	c.mu.RUnlock()

	// Record cache miss / 记录缓存未命中
	if c.mgr.perfStats != nil {
		c.mgr.perfStats.RecordCacheMiss("global_stats")
	}

	// Need to refresh / 需要刷新
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check after acquiring write lock / 获取写锁后再次检查
	if c.globalStats != nil && time.Since(c.lastGlobalUpdate) < c.globalTTL {
		return c.globalStats, nil
	}

	// Fetch fresh data / 获取新数据
	stats, err := c.mgr.GetGlobalStats()
	if err != nil {
		// Return stale data if available / 如果有旧数据则返回
		if c.globalStats != nil {
			return c.globalStats, nil
		}
		return nil, err
	}

	c.globalStats = stats
	c.lastGlobalUpdate = time.Now()
	return stats, nil
}

// GetDropDetails returns cached drop details, refreshing if expired.
// GetDropDetails 返回缓存的丢弃详情，如果过期则刷新。
func (c *StatsCache) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	c.mu.RLock()
	// Return cached if still valid / 如果缓存有效则返回
	if c.dropDetails != nil && time.Since(c.lastDropUpdate) < c.detailsTTL {
		defer c.mu.RUnlock()
		// Record cache hit / 记录缓存命中
		if c.mgr.perfStats != nil {
			c.mgr.perfStats.RecordCacheHit("drop_details")
		}
		return c.dropDetails, nil
	}
	c.mu.RUnlock()

	// Record cache miss / 记录缓存未命中
	if c.mgr.perfStats != nil {
		c.mgr.perfStats.RecordCacheMiss("drop_details")
	}

	// Need to refresh / 需要刷新
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check after acquiring write lock / 获取写锁后再次检查
	if c.dropDetails != nil && time.Since(c.lastDropUpdate) < c.detailsTTL {
		return c.dropDetails, nil
	}

	// Fetch fresh data / 获取新数据
	details, err := c.mgr.GetDropDetails()
	if err != nil {
		// Return stale data if available / 如果有旧数据则返回
		if c.dropDetails != nil {
			return c.dropDetails, nil
		}
		return nil, err
	}

	c.dropDetails = details
	c.lastDropUpdate = time.Now()
	return details, nil
}

// GetPassDetails returns cached pass details, refreshing if expired.
// GetPassDetails 返回缓存的通过详情，如果过期则刷新。
func (c *StatsCache) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	c.mu.RLock()
	// Return cached if still valid / 如果缓存有效则返回
	if c.passDetails != nil && time.Since(c.lastPassUpdate) < c.detailsTTL {
		defer c.mu.RUnlock()
		// Record cache hit / 记录缓存命中
		if c.mgr.perfStats != nil {
			c.mgr.perfStats.RecordCacheHit("pass_details")
		}
		return c.passDetails, nil
	}
	c.mu.RUnlock()

	// Record cache miss / 记录缓存未命中
	if c.mgr.perfStats != nil {
		c.mgr.perfStats.RecordCacheMiss("pass_details")
	}

	// Need to refresh / 需要刷新
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check after acquiring write lock / 获取写锁后再次检查
	if c.passDetails != nil && time.Since(c.lastPassUpdate) < c.detailsTTL {
		return c.passDetails, nil
	}

	// Fetch fresh data / 获取新数据
	details, err := c.mgr.GetPassDetails()
	if err != nil {
		// Return stale data if available / 如果有旧数据则返回
		if c.passDetails != nil {
			return c.passDetails, nil
		}
		return nil, err
	}

	c.passDetails = details
	c.lastPassUpdate = time.Now()
	return details, nil
}

// GetMapCounts returns cached map entry counts, refreshing if expired.
// GetMapCounts 返回缓存的 Map 条目计数，如果过期则刷新。
func (c *StatsCache) GetMapCounts() (MapCounts, error) {
	c.mu.RLock()
	// Return cached if still valid / 如果缓存有效则返回
	if !c.mapCounts.UpdatedAt.IsZero() && time.Since(c.mapCounts.UpdatedAt) < c.mapCountsTTL {
		defer c.mu.RUnlock()
		// Record cache hit / 记录缓存命中
		if c.mgr.perfStats != nil {
			c.mgr.perfStats.RecordCacheHit("map_counts")
		}
		return c.mapCounts, nil
	}
	c.mu.RUnlock()

	// Record cache miss / 记录缓存未命中
	if c.mgr.perfStats != nil {
		c.mgr.perfStats.RecordCacheMiss("map_counts")
	}

	// Need to refresh / 需要刷新
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check after acquiring write lock / 获取写锁后再次检查
	if !c.mapCounts.UpdatedAt.IsZero() && time.Since(c.mapCounts.UpdatedAt) < c.mapCountsTTL {
		return c.mapCounts, nil
	}

	// Fetch fresh data / 获取新数据
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
	return c.mapCounts, nil
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

// GetCacheInfo returns information about cache state.
// GetCacheInfo 返回缓存状态信息。
func (c *StatsCache) GetCacheInfo() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]any{
		"global_stats_cached": c.globalStats != nil,
		"global_stats_age":    time.Since(c.lastGlobalUpdate).String(),
		"global_stats_ttl":    c.globalTTL.String(),
		"drop_details_cached": c.dropDetails != nil,
		"drop_details_age":    time.Since(c.lastDropUpdate).String(),
		"drop_details_ttl":    c.detailsTTL.String(),
		"pass_details_cached": c.passDetails != nil,
		"pass_details_age":    time.Since(c.lastPassUpdate).String(),
		"pass_details_ttl":    c.detailsTTL.String(),
		"map_counts_cached":   !c.mapCounts.UpdatedAt.IsZero(),
		"map_counts_age":      time.Since(c.mapCounts.UpdatedAt).String(),
		"map_counts_ttl":      c.mapCountsTTL.String(),
	}
}
