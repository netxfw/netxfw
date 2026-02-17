package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
)

// ConfigCache provides a cached configuration manager with delayed persistence.
// ConfigCache 提供带延迟持久化的配置缓存管理器。
type ConfigCache struct {
	mu sync.RWMutex

	// cachedConfig is the in-memory cached configuration
	// cachedConfig 是内存中缓存的配置
	cachedConfig *types.GlobalConfig

	// dirty indicates if the config has been modified but not saved
	// dirty 表示配置已修改但未保存
	dirty bool

	// lastLoadTime is the last time the config was loaded from file
	// lastLoadTime 是上次从文件加载配置的时间
	lastLoadTime time.Time

	// saveTimer is the timer for delayed save
	// saveTimer 是延迟保存的定时器
	saveTimer *time.Timer

	// saveDelay is the delay before saving to file
	// saveDelay 是保存到文件的延迟时间
	saveDelay time.Duration

	// configPath is the path to the config file
	// configPath 是配置文件的路径
	configPath string

	// stopCh is the channel to stop the background saver
	// stopCh 是停止后台保存器的通道
	stopCh chan struct{}
}

// configCacheInstance is the global config cache instance
// configCacheInstance 是全局配置缓存实例
var configCacheInstance *ConfigCache

// configCacheOnce ensures the cache is initialized only once
// configCacheOnce 确保缓存只初始化一次
var configCacheOnce sync.Once

// GetConfigCache returns the global config cache instance.
// GetConfigCache 返回全局配置缓存实例。
func GetConfigCache() *ConfigCache {
	configCacheOnce.Do(func() {
		configCacheInstance = &ConfigCache{
			saveDelay:  500 * time.Millisecond,
			configPath: config.GetConfigPath(),
			dirty:      false,
			stopCh:     make(chan struct{}),
		}
	})
	return configCacheInstance
}

// LoadConfig loads the configuration from cache or file.
// LoadConfig 从缓存或文件加载配置。
func (c *ConfigCache) LoadConfig() (*types.GlobalConfig, error) {
	c.mu.RLock()
	if c.cachedConfig != nil && !c.dirty {
		cached := c.cachedConfig
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedConfig != nil && !c.dirty {
		return c.cachedConfig, nil
	}

	cfg, err := types.LoadGlobalConfig(c.configPath)
	if err != nil {
		return nil, err
	}

	c.cachedConfig = cfg
	c.lastLoadTime = time.Now()
	c.dirty = false

	return cfg, nil
}

// LoadConfigForce forces a reload from file.
// LoadConfigForce 强制从文件重新加载。
func (c *ConfigCache) LoadConfigForce() (*types.GlobalConfig, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cfg, err := types.LoadGlobalConfig(c.configPath)
	if err != nil {
		return nil, err
	}

	c.cachedConfig = cfg
	c.lastLoadTime = time.Now()
	c.dirty = false

	return cfg, nil
}

// UpdateConfig updates the cached configuration and marks it dirty.
// UpdateConfig 更新缓存的配置并标记为脏。
func (c *ConfigCache) UpdateConfig(updater func(*types.GlobalConfig)) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedConfig == nil {
		cfg, err := types.LoadGlobalConfig(c.configPath)
		if err != nil {
			return err
		}
		c.cachedConfig = cfg
	}

	updater(c.cachedConfig)
	c.dirty = true

	return nil
}

// SaveConfig saves the configuration to file immediately.
// SaveConfig 立即将配置保存到文件。
func (c *ConfigCache) SaveConfig() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedConfig == nil {
		return nil
	}

	if !c.dirty {
		return nil
	}

	err := types.SaveGlobalConfig(c.configPath, c.cachedConfig)
	if err != nil {
		return err
	}

	c.dirty = false
	return nil
}

// SaveConfigDelayed schedules a delayed save to reduce I/O.
// SaveConfigDelayed 安排延迟保存以减少 I/O。
func (c *ConfigCache) SaveConfigDelayed(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.dirty = true

	if c.saveTimer != nil {
		c.saveTimer.Stop()
	}

	c.saveTimer = time.AfterFunc(c.saveDelay, func() {
		log := logger.Get(ctx)
		if err := c.SaveConfig(); err != nil {
			log.Warnf("⚠️  Failed to save config: %v", err)
		}
	})
}

// SaveConfigImmediate saves the config immediately and cancels any pending delayed save.
// SaveConfigImmediate 立即保存配置并取消任何待处理的延迟保存。
func (c *ConfigCache) SaveConfigImmediate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.saveTimer != nil {
		c.saveTimer.Stop()
		c.saveTimer = nil
	}

	if c.cachedConfig == nil || !c.dirty {
		return nil
	}

	err := types.SaveGlobalConfig(c.configPath, c.cachedConfig)
	if err != nil {
		return err
	}

	c.dirty = false
	return nil
}

// IsDirty returns whether the config has unsaved changes.
// IsDirty 返回配置是否有未保存的更改。
func (c *ConfigCache) IsDirty() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dirty
}

// GetCachedConfig returns the cached config without loading from file.
// GetCachedConfig 返回缓存的配置，不从文件加载。
func (c *ConfigCache) GetCachedConfig() *types.GlobalConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cachedConfig
}

// InvalidateCache clears the cache, forcing a reload on next access.
// InvalidateCache 清除缓存，强制下次访问时重新加载。
func (c *ConfigCache) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cachedConfig = nil
	c.dirty = false
	c.lastLoadTime = time.Time{}
}

// SetSaveDelay sets the delay for delayed saves.
// SetSaveDelay 设置延迟保存的延迟时间。
func (c *ConfigCache) SetSaveDelay(delay time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.saveDelay = delay
}

// Stop stops the config cache and saves any pending changes.
// Stop 停止配置缓存并保存任何待处理的更改。
func (c *ConfigCache) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.saveTimer != nil {
		c.saveTimer.Stop()
		c.saveTimer = nil
	}

	close(c.stopCh)

	if c.cachedConfig != nil && c.dirty {
		return types.SaveGlobalConfig(c.configPath, c.cachedConfig)
	}

	return nil
}

// syncBoolSettingWithConfigOptimized is an optimized version that uses the cache.
// syncBoolSettingWithConfigOptimized 是使用缓存的优化版本。
func syncBoolSettingWithConfigOptimized(ctx context.Context, xdpMgr XDPManager, enable bool,
	setter func(bool) error, configSetter configBoolSetter, settingName, logMsg string) error {

	log := logger.Get(ctx)
	if err := setter(enable); err != nil {
		return fmt.Errorf("failed to set %s: %v", settingName, err)
	}

	cache := GetConfigCache()

	types.ConfigMu.Lock()
	err := cache.UpdateConfig(func(cfg *types.GlobalConfig) {
		configSetter(cfg, enable)
	})
	types.ConfigMu.Unlock()

	if err != nil {
		log.Warnf("⚠️  Failed to update config cache: %v", err)
		return err
	}

	cache.SaveConfigDelayed(ctx)

	log.Infof(logMsg, enable)
	return nil
}

// SyncDefaultDenyOptimized sets the default deny policy with optimized config sync.
// SyncDefaultDenyOptimized 设置默认拒绝策略并使用优化的配置同步。
func SyncDefaultDenyOptimized(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	return syncBoolSettingWithConfigOptimized(ctx, xdpMgr, enable,
		xdpMgr.SetDefaultDeny,
		func(cfg *types.GlobalConfig, v bool) { cfg.Base.DefaultDeny = v },
		"default deny", "🛡️ Default deny policy set to: %v")
}

// SyncEnableAFXDPOptimized enables or disables AF_XDP with optimized config sync.
// SyncEnableAFXDPOptimized 启用或禁用 AF_XDP 并使用优化的配置同步。
func SyncEnableAFXDPOptimized(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	return syncBoolSettingWithConfigOptimized(ctx, xdpMgr, enable,
		xdpMgr.SetEnableAFXDP,
		func(cfg *types.GlobalConfig, v bool) { cfg.Base.EnableAFXDP = v },
		"enable AF_XDP", "🚀 AF_XDP redirection set to: %v")
}

// SyncEnableRateLimitOptimized enables or disables rate limiting with optimized config sync.
// SyncEnableRateLimitOptimized 启用或禁用速率限制并使用优化的配置同步。
func SyncEnableRateLimitOptimized(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	return syncBoolSettingWithConfigOptimized(ctx, xdpMgr, enable,
		xdpMgr.SetEnableRateLimit,
		func(cfg *types.GlobalConfig, v bool) { cfg.RateLimit.Enabled = v },
		"enable ratelimit", "🚀 Global rate limit set to: %v")
}

// SyncDropFragmentsOptimized enables or disables fragment dropping with optimized config sync.
// SyncDropFragmentsOptimized 启用或禁用分片丢弃并使用优化的配置同步。
func SyncDropFragmentsOptimized(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	return syncBoolSettingWithConfigOptimized(ctx, xdpMgr, enable,
		xdpMgr.SetDropFragments,
		func(cfg *types.GlobalConfig, v bool) { cfg.Base.DropFragments = v },
		"drop fragments", "🛡️ IP Fragment dropping set to: %v")
}

// SyncStrictTCPOptimized enables or disables strict TCP with optimized config sync.
// SyncStrictTCPOptimized 启用或禁用严格 TCP 并使用优化的配置同步。
func SyncStrictTCPOptimized(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	return syncBoolSettingWithConfigOptimized(ctx, xdpMgr, enable,
		xdpMgr.SetStrictTCP,
		func(cfg *types.GlobalConfig, v bool) { cfg.Base.StrictTCP = v },
		"strict tcp", "🛡️ Strict TCP validation set to: %v")
}

// SyncSYNLimitOptimized enables or disables SYN limit with optimized config sync.
// SyncSYNLimitOptimized 启用或禁用 SYN 限制并使用优化的配置同步。
func SyncSYNLimitOptimized(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	return syncBoolSettingWithConfigOptimized(ctx, xdpMgr, enable,
		xdpMgr.SetSYNLimit,
		func(cfg *types.GlobalConfig, v bool) { cfg.Base.SYNLimit = v },
		"syn limit", "🛡️ SYN Rate Limit set to: %v")
}

// SyncBogonFilterOptimized enables or disables bogon filter with optimized config sync.
// SyncBogonFilterOptimized 启用或禁用 bogon 过滤并使用优化的配置同步。
func SyncBogonFilterOptimized(ctx context.Context, xdpMgr XDPManager, enable bool) error {
	return syncBoolSettingWithConfigOptimized(ctx, xdpMgr, enable,
		xdpMgr.SetBogonFilter,
		func(cfg *types.GlobalConfig, v bool) { cfg.Base.BogonFilter = v },
		"bogon filter", "🛡️ Bogon Filter set to: %v")
}
