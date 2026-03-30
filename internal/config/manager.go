package config

import (
	"fmt"
	"sync"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// DefaultBackupKeep is the default number of backups to keep.
// DefaultBackupKeep 默认保留的备份数量。
const DefaultBackupKeep = 3

// ConfigManager handles all configuration-related operations in a centralized manner
// ConfigManager 以集中方式处理所有配置相关操作
type ConfigManager struct {
	configPath string
	mutex      sync.RWMutex
	config     *types.GlobalConfig
	backupKeep int // Number of backups to keep / 保留的备份数量
}

// resolvePath returns the current effective config path.
// resolvePath 返回当前有效配置路径。
func (cm *ConfigManager) resolvePath() string {
	if runtime.ConfigPath != "" {
		return runtime.ConfigPath
	}
	if cm.configPath != "" {
		return cm.configPath
	}
	return GetDefaultConfigPath()
}

// NewConfigManager creates a new configuration manager instance
// NewConfigManager 创建新的配置管理器实例
func NewConfigManager(configPath string) *ConfigManager {
	return &ConfigManager{
		configPath: configPath,
		backupKeep: DefaultBackupKeep,
	}
}

// SetBackupKeep sets the number of backups to keep.
// SetBackupKeep 设置保留的备份数量。
func (cm *ConfigManager) SetBackupKeep(keep int) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.backupKeep = keep
}

// ReloadConfig loads a fresh config snapshot from disk under the global config lock.
// ReloadConfig 在全局配置锁保护下从磁盘加载最新配置快照。
func (cm *ConfigManager) ReloadConfig() (*types.GlobalConfig, error) {
	path := cm.GetConfigPath()

	types.ConfigMu.RLock()
	cfg, err := types.LoadGlobalConfig(path)
	types.ConfigMu.RUnlock()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// MutateConfig applies fn to the in-memory config snapshot and persists it.
// MutateConfig 对内存配置快照执行 fn 并持久化到文件。
func (cm *ConfigManager) MutateConfig(fn func(*types.GlobalConfig) error) error {
	cfg := cm.GetConfig()
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if err := fn(cfg); err != nil {
		return err
	}
	cm.UpdateConfig(cfg)
	return cm.SaveConfig()
}

// MutateLoadedConfig reloads config, applies fn, then persists.
// MutateLoadedConfig 重新加载配置，执行 fn 后再持久化。
func (cm *ConfigManager) MutateLoadedConfig(fn func(*types.GlobalConfig) error) error {
	cfg, err := cm.ReloadConfig()
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if err := fn(cfg); err != nil {
		return err
	}
	cm.UpdateConfig(cfg)
	return cm.SaveConfig()
}

// LoadConfig loads the configuration from the current path.
// LoadConfig 从当前路径加载配置。
func (cm *ConfigManager) LoadConfig() error {
	path := cm.GetConfigPath()

	types.ConfigMu.RLock()
	config, err := types.LoadGlobalConfig(path)
	types.ConfigMu.RUnlock()
	if err != nil {
		return err
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.configPath = path
	cm.config = config

	// Update backupKeep from config if set / 如果配置中设置了则更新 backupKeep
	if config.Base.BackupKeep > 0 {
		cm.backupKeep = config.Base.BackupKeep
	}

	return nil
}

// SaveConfig saves the current configuration to the current path with backup.
// SaveConfig 将当前配置保存到当前路径（带备份）。
func (cm *ConfigManager) SaveConfig() error {
	path := cm.GetConfigPath()
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	backupKeep := cm.backupKeep
	if cfg.Base.BackupKeep > 0 {
		backupKeep = cfg.Base.BackupKeep
	}

	types.ConfigMu.Lock()
	defer types.ConfigMu.Unlock()

	return types.SaveGlobalConfigWithBackup(path, cfg, backupKeep)
}

// GetConfig returns a copy of the current configuration
// GetConfig 返回当前配置的副本
func (cm *ConfigManager) GetConfig() *types.GlobalConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	// Return a copy to prevent external modifications
	cfgCopy := *cm.config
	return &cfgCopy
}

// UpdateConfig updates the current configuration
// UpdateConfig 更新当前配置
func (cm *ConfigManager) UpdateConfig(newConfig *types.GlobalConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.config = newConfig
}

// GetBaseConfig returns the base configuration
// GetBaseConfig 返回基础配置
func (cm *ConfigManager) GetBaseConfig() *types.BaseConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	baseCfg := cm.config.Base
	return &baseCfg
}

// GetWebConfig returns the web configuration
// GetWebConfig 返回Web配置
func (cm *ConfigManager) GetWebConfig() *types.WebConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	webCfg := cm.config.Web
	return &webCfg
}

// GetMetricsConfig returns the metrics configuration
// GetMetricsConfig 返回指标配置
func (cm *ConfigManager) GetMetricsConfig() *types.MetricsConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	metricsCfg := cm.config.Metrics
	return &metricsCfg
}

// GetLoggingConfig returns the logging configuration
// GetLoggingConfig 返回日志配置
func (cm *ConfigManager) GetLoggingConfig() *logger.LoggingConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	loggingCfg := cm.config.Logging
	return &loggingCfg
}

// GetConntrackConfig returns the connection tracking configuration
// GetConntrackConfig 返回连接跟踪配置
func (cm *ConfigManager) GetConntrackConfig() *types.ConntrackConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	conntrackCfg := cm.config.Conntrack
	return &conntrackCfg
}

// GetRateLimitConfig returns the rate limiting configuration
// GetRateLimitConfig 返回速率限制配置
func (cm *ConfigManager) GetRateLimitConfig() *types.RateLimitConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	rateLimitCfg := cm.config.RateLimit
	return &rateLimitCfg
}

// GetPortConfig returns the port configuration
// GetPortConfig 返回端口配置
func (cm *ConfigManager) GetPortConfig() *types.PortConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	portCfg := cm.config.Port
	return &portCfg
}

// GetCapacityConfig returns the capacity configuration
// GetCapacityConfig 返回容量配置
func (cm *ConfigManager) GetCapacityConfig() *types.CapacityConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	capacityCfg := cm.config.Capacity
	return &capacityCfg
}

// GetLogEngineConfig returns the log engine configuration
// GetLogEngineConfig 返回日志引擎配置
func (cm *ConfigManager) GetLogEngineConfig() *types.LogEngineConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	logEngineCfg := cm.config.LogEngine
	return &logEngineCfg
}

// GetAIConfig returns the AI configuration
// GetAIConfig 返回AI配置
func (cm *ConfigManager) GetAIConfig() *types.AIConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	aiCfg := cm.config.AI
	return &aiCfg
}

// GetMCPConfig returns the MCP configuration
// GetMCPConfig 返回MCP配置
func (cm *ConfigManager) GetMCPConfig() *types.MCPConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	mcpCfg := cm.config.MCP
	return &mcpCfg
}

// GetClusterConfig returns the cluster configuration
// GetClusterConfig 返回集群配置
func (cm *ConfigManager) GetClusterConfig() *types.ClusterConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	clusterCfg := cm.config.Cluster
	return &clusterCfg
}

// SetBaseConfig updates the base configuration
// SetBaseConfig 更新基础配置
func (cm *ConfigManager) SetBaseConfig(baseConfig types.BaseConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Base = baseConfig
	}
}

// SetWebConfig updates the web configuration
// SetWebConfig 更新Web配置
func (cm *ConfigManager) SetWebConfig(webConfig types.WebConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Web = webConfig
	}
}

// SetMetricsConfig updates the metrics configuration
// SetMetricsConfig 更新指标配置
func (cm *ConfigManager) SetMetricsConfig(metricsConfig types.MetricsConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Metrics = metricsConfig
	}
}

// SetLoggingConfig updates the logging configuration
// SetLoggingConfig 更新日志配置
func (cm *ConfigManager) SetLoggingConfig(loggingConfig logger.LoggingConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Logging = loggingConfig
	}
}

// SetConntrackConfig updates the connection tracking configuration
// SetConntrackConfig 更新连接跟踪配置
func (cm *ConfigManager) SetConntrackConfig(conntrackConfig types.ConntrackConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Conntrack = conntrackConfig
	}
}

// SetRateLimitConfig updates the rate limiting configuration
// SetRateLimitConfig 更新速率限制配置
func (cm *ConfigManager) SetRateLimitConfig(rateLimitConfig types.RateLimitConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.RateLimit = rateLimitConfig
	}
}

// SetPortConfig updates the port configuration
// SetPortConfig 更新端口配置
func (cm *ConfigManager) SetPortConfig(portConfig types.PortConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Port = portConfig
	}
}

// SetCapacityConfig updates the capacity configuration
// SetCapacityConfig 更新容量配置
func (cm *ConfigManager) SetCapacityConfig(capacityConfig types.CapacityConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Capacity = capacityConfig
	}
}

// SetLogEngineConfig updates the log engine configuration
// SetLogEngineConfig 更新日志引擎配置
func (cm *ConfigManager) SetLogEngineConfig(logEngineConfig types.LogEngineConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.LogEngine = logEngineConfig
	}
}

// SetAIConfig updates the AI configuration
// SetAIConfig 更新AI配置
func (cm *ConfigManager) SetAIConfig(aiConfig types.AIConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.AI = aiConfig
	}
}

// SetMCPConfig updates the MCP configuration
// SetMCPConfig 更新MCP配置
func (cm *ConfigManager) SetMCPConfig(mcpConfig types.MCPConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.MCP = mcpConfig
	}
}

// SetClusterConfig updates the cluster configuration
// SetClusterConfig 更新集群配置
func (cm *ConfigManager) SetClusterConfig(clusterConfig types.ClusterConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Cluster = clusterConfig
	}
}

// GetConfigPath returns the current effective configuration file path
// GetConfigPath 返回当前有效配置文件路径
func (cm *ConfigManager) GetConfigPath() string {
	path := cm.resolvePath()

	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.configPath = path
	return path
}

// Validate validates the current configuration
// Validate 验证当前配置
func (cm *ConfigManager) Validate() error {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if cm.config == nil {
		return nil
	}

	return cm.config.Validate()
}
