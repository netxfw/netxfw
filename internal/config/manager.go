package config

import (
	"fmt"
	"sync"

	"github.com/netxfw/netxfw/internal/adapters/configfile"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// DefaultBackupKeep is the default number of backups to keep.
// DefaultBackupKeep 默认保留的备份数量。
const DefaultBackupKeep = 3

// ConfigManager handles all configuration-related operations in a centralized manner
// ConfigManager 以集中方式处理所有配置相关操作
type ConfigManager struct {
	configPath string
	mutex      sync.RWMutex
	config     *sdk.GlobalConfig
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
func (cm *ConfigManager) ReloadConfig() (*sdk.GlobalConfig, error) {
	path := cm.GetConfigPath()

	lockConfigRead()
	cfg, err := configfile.Load(path)
	unlockConfigRead()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// MutateConfig applies fn to the in-memory config snapshot and persists it.
// MutateConfig 对内存配置快照执行 fn 并持久化到文件。
func (cm *ConfigManager) MutateConfig(fn func(*sdk.GlobalConfig) error) error {
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

func cloneConfig(cfg *sdk.GlobalConfig) *sdk.GlobalConfig {
	return configfile.Clone(cfg)
}

// MutateLoadedConfig reloads config, applies fn, then persists.
// MutateLoadedConfig 重新加载配置，执行 fn 后再持久化。
func (cm *ConfigManager) MutateLoadedConfig(fn func(*sdk.GlobalConfig) error) error {
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

	lockConfigRead()
	config, err := configfile.Load(path)
	unlockConfigRead()
	if err != nil {
		return err
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.configPath = path
	cm.config = cloneConfig(config)

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

	lockConfigWrite()
	defer unlockConfigWrite()

	return DefaultWriteGateway().SaveGlobalConfig(path, cfg, backupKeep, "config.manager.SaveConfig")
}

// GetConfig returns a deep copy of the current configuration.
// GetConfig 返回当前配置的深拷贝。
func (cm *ConfigManager) GetConfig() *sdk.GlobalConfig {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	return cloneConfig(cm.config)
}

// UpdateConfig replaces the current configuration with a deep-copied snapshot.
// UpdateConfig 使用深拷贝快照替换当前配置。
func (cm *ConfigManager) UpdateConfig(newConfig *sdk.GlobalConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.config = cloneConfig(newConfig)
}

// GetBaseConfig returns the base configuration
// GetBaseConfig 返回基础配置
func (cm *ConfigManager) GetBaseConfig() *sdk.BaseConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	baseCfg := cfg.Base
	return &baseCfg
}

// GetWebConfig returns the web configuration
// GetWebConfig 返回Web配置
func (cm *ConfigManager) GetWebConfig() *sdk.WebConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	webCfg := cfg.Web
	return &webCfg
}

// GetMetricsConfig returns the metrics configuration
// GetMetricsConfig 返回指标配置
func (cm *ConfigManager) GetMetricsConfig() *sdk.MetricsConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	metricsCfg := cfg.Metrics
	return &metricsCfg
}

// GetLoggingConfig returns the logging configuration
// GetLoggingConfig 返回日志配置
func (cm *ConfigManager) GetLoggingConfig() *logger.LoggingConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	loggingCfg := cfg.Logging
	return &loggingCfg
}

// GetConntrackConfig returns the connection tracking configuration
// GetConntrackConfig 返回连接跟踪配置
func (cm *ConfigManager) GetConntrackConfig() *sdk.ConntrackConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	conntrackCfg := cfg.Conntrack
	return &conntrackCfg
}

// GetRateLimitConfig returns the rate limiting configuration
// GetRateLimitConfig 返回速率限制配置
func (cm *ConfigManager) GetRateLimitConfig() *sdk.RateLimitConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	rateLimitCfg := cfg.RateLimit
	return &rateLimitCfg
}

// GetPortConfig returns the port configuration
// GetPortConfig 返回端口配置
func (cm *ConfigManager) GetPortConfig() *sdk.PortConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	portCfg := cfg.Port
	return &portCfg
}

// GetCapacityConfig returns the capacity configuration
// GetCapacityConfig 返回容量配置
func (cm *ConfigManager) GetCapacityConfig() *sdk.CapacityConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	capacityCfg := cfg.Capacity
	return &capacityCfg
}

// GetLogEngineConfig returns the log engine configuration
// GetLogEngineConfig 返回日志引擎配置
func (cm *ConfigManager) GetLogEngineConfig() *sdk.LogEngineConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	logEngineCfg := cfg.LogEngine
	return &logEngineCfg
}

// GetAIConfig returns the AI configuration
// GetAIConfig 返回AI配置
func (cm *ConfigManager) GetAIConfig() *sdk.AIConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	aiCfg := cfg.AI
	return &aiCfg
}

// GetMCPConfig returns the MCP configuration
// GetMCPConfig 返回MCP配置
func (cm *ConfigManager) GetMCPConfig() *sdk.MCPConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	mcpCfg := cfg.MCP
	return &mcpCfg
}

// GetClusterConfig returns the cluster configuration
// GetClusterConfig 返回集群配置
func (cm *ConfigManager) GetClusterConfig() *sdk.ClusterConfig {
	cfg := cm.GetConfig()
	if cfg == nil {
		return nil
	}

	clusterCfg := cfg.Cluster
	return &clusterCfg
}

// SetBaseConfig updates the base configuration
// SetBaseConfig 更新基础配置
func (cm *ConfigManager) SetBaseConfig(baseConfig sdk.BaseConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Base = baseConfig
	}
}

// SetWebConfig updates the web configuration
// SetWebConfig 更新Web配置
func (cm *ConfigManager) SetWebConfig(webConfig sdk.WebConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Web = webConfig
	}
}

// SetMetricsConfig updates the metrics configuration
// SetMetricsConfig 更新指标配置
func (cm *ConfigManager) SetMetricsConfig(metricsConfig sdk.MetricsConfig) {
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
func (cm *ConfigManager) SetConntrackConfig(conntrackConfig sdk.ConntrackConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Conntrack = conntrackConfig
	}
}

// SetRateLimitConfig updates the rate limiting configuration
// SetRateLimitConfig 更新速率限制配置
func (cm *ConfigManager) SetRateLimitConfig(rateLimitConfig sdk.RateLimitConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.RateLimit = rateLimitConfig
	}
}

// SetPortConfig updates the port configuration
// SetPortConfig 更新端口配置
func (cm *ConfigManager) SetPortConfig(portConfig sdk.PortConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Port = portConfig
	}
}

// SetCapacityConfig updates the capacity configuration
// SetCapacityConfig 更新容量配置
func (cm *ConfigManager) SetCapacityConfig(capacityConfig sdk.CapacityConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.Capacity = capacityConfig
	}
}

// SetLogEngineConfig updates the log engine configuration
// SetLogEngineConfig 更新日志引擎配置
func (cm *ConfigManager) SetLogEngineConfig(logEngineConfig sdk.LogEngineConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.LogEngine = logEngineConfig
	}
}

// SetAIConfig updates the AI configuration
// SetAIConfig 更新AI配置
func (cm *ConfigManager) SetAIConfig(aiConfig sdk.AIConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.AI = aiConfig
	}
}

// SetMCPConfig updates the MCP configuration
// SetMCPConfig 更新MCP配置
func (cm *ConfigManager) SetMCPConfig(mcpConfig sdk.MCPConfig) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.config != nil {
		cm.config.MCP = mcpConfig
	}
}

// SetClusterConfig updates the cluster configuration
// SetClusterConfig 更新集群配置
func (cm *ConfigManager) SetClusterConfig(clusterConfig sdk.ClusterConfig) {
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
