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
	// domainconfig.IPPortRule is now an alias for sdk.IPPortRule
	return items
}

func IPPortRulesToSDK(items []domainconfig.IPPortRule) []sdk.IPPortRule {
	// domainconfig.IPPortRule is now an alias for sdk.IPPortRule
	return items
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

// ConfigFromSDK is now an identity function — domain/config.Config is a type
// alias for sdk.GlobalConfig, so no conversion is needed.
func ConfigFromSDK(cfg *sdk.GlobalConfig) *domainconfig.Config {
	return cfg
}

// ConfigToSDK is now an identity function — domain/config.Config is a type
// alias for sdk.GlobalConfig, so no conversion is needed.
func ConfigToSDK(cfg *domainconfig.Config) *sdk.GlobalConfig {
	return cfg
}
