package configfile

import "github.com/netxfw/netxfw/pkg/sdk"

// Clone returns a deep copy of cfg.
func Clone(cfg *sdk.GlobalConfig) *sdk.GlobalConfig {
	if cfg == nil {
		return nil
	}

	clone := *cfg
	clone.Base = cloneBaseConfig(cfg.Base)
	clone.Port = clonePortConfig(cfg.Port)
	clone.RateLimit = cloneRateLimitConfig(cfg.RateLimit)
	clone.LogEngine = cloneLogEngineConfig(cfg.LogEngine)
	clone.Cloud = cloneCloudConfig(cfg.Cloud)
	clone.BPFPlugin = cloneBPFPluginSettings(cfg.BPFPlugin)
	clone.Modules = append([]sdk.ModuleConfig(nil), cfg.Modules...)
	return &clone
}

func cloneBaseConfig(cfg sdk.BaseConfig) sdk.BaseConfig {
	clone := cfg
	clone.Interfaces = append([]string(nil), cfg.Interfaces...)
	clone.Whitelist = append([]string(nil), cfg.Whitelist...)
	return clone
}

func clonePortConfig(cfg sdk.PortConfig) sdk.PortConfig {
	clone := cfg
	clone.AllowedPorts = append([]uint16(nil), cfg.AllowedPorts...)
	clone.IPPortRules = append([]sdk.IPPortRule(nil), cfg.IPPortRules...)
	return clone
}

func cloneRateLimitConfig(cfg sdk.RateLimitConfig) sdk.RateLimitConfig {
	clone := cfg
	clone.Rules = append([]sdk.RateLimitRule(nil), cfg.Rules...)
	return clone
}

func cloneLogEngineConfig(cfg sdk.LogEngineConfig) sdk.LogEngineConfig {
	clone := cfg
	clone.Rules = append([]sdk.LogEngineRule(nil), cfg.Rules...)
	for i := range clone.Rules {
		clone.Rules[i] = cloneLogEngineRule(clone.Rules[i])
	}
	return clone
}

func cloneLogEngineRule(rule sdk.LogEngineRule) sdk.LogEngineRule {
	clone := rule
	clone.Keywords = append([]string(nil), rule.Keywords...)
	clone.Contains = append([]string(nil), rule.Contains...)
	clone.AnyContains = append([]string(nil), rule.AnyContains...)
	clone.NotContains = append([]string(nil), rule.NotContains...)
	clone.And = append([]string(nil), rule.And...)
	clone.Is = append([]string(nil), rule.Is...)
	clone.Or = append([]string(nil), rule.Or...)
	clone.Not = append([]string(nil), rule.Not...)
	return clone
}

func cloneCloudConfig(cfg sdk.CloudConfig) sdk.CloudConfig {
	clone := cfg
	clone.ProxyProtocol = cloneProxyProtocolConfig(cfg.ProxyProtocol)
	return clone
}

func cloneProxyProtocolConfig(cfg sdk.ProxyProtocolConfig) sdk.ProxyProtocolConfig {
	clone := cfg
	clone.TrustedLBRanges = append([]string(nil), cfg.TrustedLBRanges...)
	return clone
}

func cloneBPFPluginSettings(cfg sdk.BPFPluginSettings) sdk.BPFPluginSettings {
	clone := cfg
	clone.Plugins = append([]sdk.BPFPluginConfig(nil), cfg.Plugins...)
	return clone
}
