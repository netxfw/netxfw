package ports

import (
	"time"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

// BlockedIP is the internal read model for blacklist entries.
type BlockedIP struct {
	IP        string
	ExpiresAt uint64
	Counter   uint64
}

// RateLimitConf is the internal read model for a runtime rate-limit rule.
type RateLimitConf struct {
	Rate  uint64
	Burst uint64
}

// DropDetailEntry is the internal read model for per-packet detail stats.
type DropDetailEntry struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Reason    uint32
	Count     uint64
	Payload   []byte
}

func BlockedIPsFromSDK(items []sdk.BlockedIP) []BlockedIP {
	if items == nil {
		return nil
	}
	out := make([]BlockedIP, len(items))
	for i := range items {
		out[i] = BlockedIP(items[i])
	}
	return out
}

func IPPortRulesFromSDK(items []sdk.IPPortRule) []domainconfig.IPPortRule {
	if items == nil {
		return nil
	}
	out := make([]domainconfig.IPPortRule, len(items))
	for i := range items {
		out[i] = domainconfig.IPPortRule(items[i])
	}
	return out
}

func IPPortRulesToSDK(items []domainconfig.IPPortRule) []sdk.IPPortRule {
	if items == nil {
		return nil
	}
	out := make([]sdk.IPPortRule, len(items))
	for i := range items {
		out[i] = sdk.IPPortRule(items[i])
	}
	return out
}

func RateLimitRulesFromSDK(items map[string]sdk.RateLimitConf) map[string]RateLimitConf {
	if items == nil {
		return nil
	}
	out := make(map[string]RateLimitConf, len(items))
	for key, value := range items {
		out[key] = RateLimitConf(value)
	}
	return out
}

func DropDetailEntriesFromSDK(items []sdk.DropDetailEntry) []DropDetailEntry {
	if items == nil {
		return nil
	}
	out := make([]DropDetailEntry, len(items))
	for i := range items {
		out[i] = DropDetailEntry(items[i])
	}
	return out
}

func PluginTypeFromSDK(kind sdk.PluginType) PluginType {
	switch kind {
	case sdk.PluginTypeCore:
		return PluginTypeCore
	default:
		return PluginTypeExtension
	}
}

func RuntimeKindFromPluginType(kind PluginType) domainruntime.Kind {
	switch kind {
	case PluginTypeCore:
		return domainruntime.KindCore
	default:
		return domainruntime.KindExtension
	}
}

func HealthCheckResultToSDK(result HealthCheckResult) sdk.HealthCheckResult {
	return sdk.HealthCheckResult{
		Status:  sdk.HealthStatus(result.Status),
		Message: result.Message,
		Details: result.Details,
	}
}

func ConfigFromSDK(cfg *sdk.GlobalConfig) *domainconfig.Config {
	if cfg == nil {
		return nil
	}
	return &domainconfig.Config{
		Cluster:   domainconfig.ClusterConfig(cfg.Cluster),
		Base:      domainconfig.BaseConfig(cfg.Base),
		Web:       domainconfig.WebConfig(cfg.Web),
		Metrics:   domainconfig.MetricsConfig(cfg.Metrics),
		Port:      domainconfig.PortConfig{AllowedPorts: append([]uint16(nil), cfg.Port.AllowedPorts...), IPPortRules: IPPortRulesFromSDK(cfg.Port.IPPortRules)},
		Conntrack: domainconfig.ConntrackConfig(cfg.Conntrack),
		RateLimit: rateLimitConfigFromSDK(cfg.RateLimit),
		LogEngine: logEngineConfigFromSDK(cfg.LogEngine),
		Capacity:  domainconfig.CapacityConfig(cfg.Capacity),
		Logging:   domainconfig.LoggingConfig(cfg.Logging),
		Cloud:     cloudConfigFromSDK(cfg.Cloud),
		BPFPlugin: bpfSettingsFromSDK(cfg.BPFPlugin),
		Modules:   modulesFromSDK(cfg.Modules),
		Runtime: domainconfig.RuntimeServicesConfig{
			AI:  domainconfig.AIConfig(cfg.Runtime.AI),
			MCP: domainconfig.MCPConfig(cfg.Runtime.MCP),
		},
	}
}

func ConfigToSDK(cfg *domainconfig.Config) *sdk.GlobalConfig {
	if cfg == nil {
		return nil
	}
	return &sdk.GlobalConfig{
		Cluster:   sdk.ClusterConfig(cfg.Cluster),
		Base:      sdk.BaseConfig(cfg.Base),
		Web:       sdk.WebConfig(cfg.Web),
		Metrics:   sdk.MetricsConfig(cfg.Metrics),
		Port:      sdk.PortConfig{AllowedPorts: append([]uint16(nil), cfg.Port.AllowedPorts...), IPPortRules: IPPortRulesToSDK(cfg.Port.IPPortRules)},
		Conntrack: sdk.ConntrackConfig(cfg.Conntrack),
		RateLimit: rateLimitConfigToSDK(cfg.RateLimit),
		LogEngine: logEngineConfigToSDK(cfg.LogEngine),
		Capacity:  sdk.CapacityConfig(cfg.Capacity),
		Logging:   sdk.LoggingConfig(cfg.Logging),
		Cloud:     cloudConfigToSDK(cfg.Cloud),
		BPFPlugin: bpfSettingsToSDK(cfg.BPFPlugin),
		Modules:   modulesToSDK(cfg.Modules),
		Runtime: sdk.RuntimeServicesConfig{
			AI:  sdk.AIConfig(cfg.Runtime.AI),
			MCP: sdk.MCPConfig(cfg.Runtime.MCP),
		},
	}
}

func rateLimitConfigFromSDK(cfg sdk.RateLimitConfig) domainconfig.RateLimitConfig {
	out := domainconfig.RateLimitConfig{
		Enabled:         cfg.Enabled,
		AutoBlock:       cfg.AutoBlock,
		AutoBlockExpiry: cfg.AutoBlockExpiry,
	}
	if cfg.Rules != nil {
		out.Rules = make([]domainconfig.RateLimitRule, len(cfg.Rules))
		for i := range cfg.Rules {
			out.Rules[i] = domainconfig.RateLimitRule(cfg.Rules[i])
		}
	}
	return out
}

func rateLimitConfigToSDK(cfg domainconfig.RateLimitConfig) sdk.RateLimitConfig {
	out := sdk.RateLimitConfig{
		Enabled:         cfg.Enabled,
		AutoBlock:       cfg.AutoBlock,
		AutoBlockExpiry: cfg.AutoBlockExpiry,
	}
	if cfg.Rules != nil {
		out.Rules = make([]sdk.RateLimitRule, len(cfg.Rules))
		for i := range cfg.Rules {
			out.Rules[i] = sdk.RateLimitRule(cfg.Rules[i])
		}
	}
	return out
}

func logEngineConfigFromSDK(cfg sdk.LogEngineConfig) domainconfig.LogEngineConfig {
	out := domainconfig.LogEngineConfig{Enabled: cfg.Enabled, Workers: cfg.Workers, MaxWindow: cfg.MaxWindow}
	if cfg.Rules != nil {
		out.Rules = make([]domainconfig.LogEngineRule, len(cfg.Rules))
		for i := range cfg.Rules {
			out.Rules[i] = domainconfig.LogEngineRule(cfg.Rules[i])
		}
	}
	return out
}

func logEngineConfigToSDK(cfg domainconfig.LogEngineConfig) sdk.LogEngineConfig {
	out := sdk.LogEngineConfig{Enabled: cfg.Enabled, Workers: cfg.Workers, MaxWindow: cfg.MaxWindow}
	if cfg.Rules != nil {
		out.Rules = make([]sdk.LogEngineRule, len(cfg.Rules))
		for i := range cfg.Rules {
			out.Rules[i] = sdk.LogEngineRule(cfg.Rules[i])
		}
	}
	return out
}

func cloudConfigFromSDK(cfg sdk.CloudConfig) domainconfig.CloudConfig {
	return domainconfig.CloudConfig{Enabled: cfg.Enabled, Provider: cfg.Provider, ProxyProtocol: domainconfig.ProxyProtocolConfig(cfg.ProxyProtocol)}
}

func cloudConfigToSDK(cfg domainconfig.CloudConfig) sdk.CloudConfig {
	return sdk.CloudConfig{Enabled: cfg.Enabled, Provider: cfg.Provider, ProxyProtocol: sdk.ProxyProtocolConfig(cfg.ProxyProtocol)}
}

func bpfSettingsFromSDK(cfg sdk.BPFPluginSettings) domainconfig.BPFPluginSettings {
	out := domainconfig.BPFPluginSettings{Enabled: cfg.Enabled}
	if cfg.Plugins != nil {
		out.Plugins = make([]domainconfig.BPFPluginConfig, len(cfg.Plugins))
		for i := range cfg.Plugins {
			out.Plugins[i] = domainconfig.BPFPluginConfig(cfg.Plugins[i])
		}
	}
	return out
}

func bpfSettingsToSDK(cfg domainconfig.BPFPluginSettings) sdk.BPFPluginSettings {
	out := sdk.BPFPluginSettings{Enabled: cfg.Enabled}
	if cfg.Plugins != nil {
		out.Plugins = make([]sdk.BPFPluginConfig, len(cfg.Plugins))
		for i := range cfg.Plugins {
			out.Plugins[i] = sdk.BPFPluginConfig(cfg.Plugins[i])
		}
	}
	return out
}

func modulesFromSDK(items []sdk.ModuleConfig) []domainconfig.ModuleConfig {
	if items == nil {
		return nil
	}
	out := make([]domainconfig.ModuleConfig, len(items))
	for i := range items {
		out[i] = domainconfig.ModuleConfig(items[i])
	}
	return out
}

func modulesToSDK(items []domainconfig.ModuleConfig) []sdk.ModuleConfig {
	if items == nil {
		return nil
	}
	out := make([]sdk.ModuleConfig, len(items))
	for i := range items {
		out[i] = sdk.ModuleConfig(items[i])
	}
	return out
}
