package config

import (
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type Config = sdk.GlobalConfig
type BaseConfig = sdk.BaseConfig
type WebConfig = sdk.WebConfig
type MetricsConfig = sdk.MetricsConfig
type PortConfig = sdk.PortConfig
type ConntrackConfig = sdk.ConntrackConfig
type RateLimitConfig = sdk.RateLimitConfig
type RateLimitRule = sdk.RateLimitRule
type LogEngineConfig = sdk.LogEngineConfig
type LogEngineRule = sdk.LogEngineRule
type CapacityConfig = sdk.CapacityConfig
type ClusterConfig = sdk.ClusterConfig
type CloudConfig = sdk.CloudConfig
type AIConfig = sdk.AIConfig
type MCPConfig = sdk.MCPConfig
type ModuleConfig = sdk.ModuleConfig
type BPFPluginConfig = sdk.BPFPluginConfig
type BPFPluginSettings = sdk.BPFPluginSettings
type LoggingConfig = logger.LoggingConfig
