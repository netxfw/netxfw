package config

import (
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/livp123/netxfw/internal/utils/logger"
)

// Configurable represents the interface for configuration management
// Configurable 表示配置管理的接口
type Configurable interface {
	LoadConfig() error
	SaveConfig() error
	GetConfig() *types.GlobalConfig
	UpdateConfig(*types.GlobalConfig)

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

// GetDefaultConfigPath returns the default configuration file path
// GetDefaultConfigPath 返回默认配置文件路径
func GetDefaultConfigPath() string {
	return DefaultConfigPath
}

// GetConfigPath returns the configuration file path
// If runtime.ConfigPath is set (e.g., via CLI flag or test), it takes precedence.
// GetConfigPath 返回配置文件路径
// 如果 runtime.ConfigPath 已设置（例如通过 CLI 标志或测试），则优先使用它。
func GetConfigPath() string {
	if runtime.ConfigPath != "" {
		return runtime.ConfigPath
	}
	return DefaultConfigPath
}

// GetPinPath returns the BPF pinning path
// GetPinPath 返回BPF固定路径
func GetPinPath() string {
	return BPFPinPath
}
