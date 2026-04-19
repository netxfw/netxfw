package config

import (
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// Configurable represents the interface for configuration management
// Configurable 表示配置管理的接口
type Configurable interface {
	LoadConfig() error
	SaveConfig() error
	ReloadConfig() (*sdk.GlobalConfig, error)
	GetConfig() *sdk.GlobalConfig
	UpdateConfig(*sdk.GlobalConfig)
	MutateConfig(func(*sdk.GlobalConfig) error) error
	MutateLoadedConfig(func(*sdk.GlobalConfig) error) error

	// Getters for specific configuration sections
	GetBaseConfig() *sdk.BaseConfig
	GetWebConfig() *sdk.WebConfig
	GetMetricsConfig() *sdk.MetricsConfig
	GetLoggingConfig() *logger.LoggingConfig
	GetConntrackConfig() *sdk.ConntrackConfig
	GetRateLimitConfig() *sdk.RateLimitConfig
	GetPortConfig() *sdk.PortConfig
	GetCapacityConfig() *sdk.CapacityConfig
	GetLogEngineConfig() *sdk.LogEngineConfig
	GetAIConfig() *sdk.AIConfig
	GetMCPConfig() *sdk.MCPConfig
	GetClusterConfig() *sdk.ClusterConfig

	// Setters for specific configuration sections
	SetBaseConfig(sdk.BaseConfig)
	SetWebConfig(sdk.WebConfig)
	SetMetricsConfig(sdk.MetricsConfig)
	SetLoggingConfig(logger.LoggingConfig)
	SetConntrackConfig(sdk.ConntrackConfig)
	SetRateLimitConfig(sdk.RateLimitConfig)
	SetPortConfig(sdk.PortConfig)
	SetCapacityConfig(sdk.CapacityConfig)
	SetLogEngineConfig(sdk.LogEngineConfig)
	SetAIConfig(sdk.AIConfig)
	SetMCPConfig(sdk.MCPConfig)
	SetClusterConfig(sdk.ClusterConfig)

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
