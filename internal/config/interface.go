package config

import (
	"github.com/netxfw/netxfw/internal/configtypes"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// Configurable represents the interface for configuration management
// Configurable 表示配置管理的接口
type Configurable interface {
	LoadConfig() error
	SaveConfig() error
	ReloadConfig() (*types.GlobalConfig, error)
	GetConfig() *types.GlobalConfig
	UpdateConfig(*types.GlobalConfig)
	MutateConfig(func(*types.GlobalConfig) error) error
	MutateLoadedConfig(func(*types.GlobalConfig) error) error

	// Getters for specific configuration sections
	GetBaseConfig() *types.BaseConfig
	GetWebConfig() *types.WebConfig
	GetMetricsConfig() *types.MetricsConfig
	GetLoggingConfig() *logger.LoggingConfig
	GetConntrackConfig() *types.ConntrackConfig
	GetRateLimitConfig() *types.RateLimitConfig
	GetPortConfig() *types.PortConfig
	GetCapacityConfig() *types.CapacityConfig
	GetLogEngineConfig() *types.LogEngineConfig
	GetAIConfig() *types.AIConfig
	GetMCPConfig() *types.MCPConfig
	GetClusterConfig() *types.ClusterConfig

	// Setters for specific configuration sections
	SetBaseConfig(types.BaseConfig)
	SetWebConfig(types.WebConfig)
	SetMetricsConfig(types.MetricsConfig)
	SetLoggingConfig(logger.LoggingConfig)
	SetConntrackConfig(types.ConntrackConfig)
	SetRateLimitConfig(types.RateLimitConfig)
	SetPortConfig(types.PortConfig)
	SetCapacityConfig(types.CapacityConfig)
	SetLogEngineConfig(types.LogEngineConfig)
	SetAIConfig(types.AIConfig)
	SetMCPConfig(types.MCPConfig)
	SetClusterConfig(types.ClusterConfig)

	// Utility methods
	GetConfigPath() string
	Validate() error
}

// resolveConfigPath returns the effective config path considering CLI flags and defaults.
// resolveConfigPath 返回考虑 CLI 标志和默认值的有效配置路径。
func resolveConfigPath() string {
	if runtime.ConfigPath != "" {
		return runtime.ConfigPath
	}
	return GetDefaultConfigPath()
}

// SetConfigPath sets the configuration file path
// SetConfigPath 设置配置文件路径
func SetConfigPath(path string) {
	runtime.ConfigPath = path
}

// GetPinPath returns the BPF pinning path
// GetPinPath 返回BPF固定路径
func GetPinPath() string {
	return BPFPinPath
}
