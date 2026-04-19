package configfile

import domainconfig "github.com/netxfw/netxfw/internal/domain/config"

// Clone returns a deep copy of cfg.
func Clone(cfg *domainconfig.Config) *domainconfig.Config {
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
	clone.Modules = append([]domainconfig.ModuleConfig(nil), cfg.Modules...)
	return &clone
}

func cloneBaseConfig(cfg domainconfig.BaseConfig) domainconfig.BaseConfig {
	clone := cfg
	clone.Interfaces = append([]string(nil), cfg.Interfaces...)
	clone.Whitelist = append([]string(nil), cfg.Whitelist...)
	return clone
}

func clonePortConfig(cfg domainconfig.PortConfig) domainconfig.PortConfig {
	clone := cfg
	clone.AllowedPorts = append([]uint16(nil), cfg.AllowedPorts...)
	clone.IPPortRules = append([]domainconfig.IPPortRule(nil), cfg.IPPortRules...)
	return clone
}

func cloneRateLimitConfig(cfg domainconfig.RateLimitConfig) domainconfig.RateLimitConfig {
	clone := cfg
	clone.Rules = append([]domainconfig.RateLimitRule(nil), cfg.Rules...)
	return clone
}

func cloneLogEngineConfig(cfg domainconfig.LogEngineConfig) domainconfig.LogEngineConfig {
	clone := cfg
	clone.Rules = append([]domainconfig.LogEngineRule(nil), cfg.Rules...)
	for i := range clone.Rules {
		clone.Rules[i] = cloneLogEngineRule(clone.Rules[i])
	}
	return clone
}

func cloneLogEngineRule(rule domainconfig.LogEngineRule) domainconfig.LogEngineRule {
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

func cloneCloudConfig(cfg domainconfig.CloudConfig) domainconfig.CloudConfig {
	clone := cfg
	clone.ProxyProtocol = cloneProxyProtocolConfig(cfg.ProxyProtocol)
	return clone
}

func cloneProxyProtocolConfig(cfg domainconfig.ProxyProtocolConfig) domainconfig.ProxyProtocolConfig {
	clone := cfg
	clone.TrustedLBRanges = append([]string(nil), cfg.TrustedLBRanges...)
	return clone
}

func cloneBPFPluginSettings(cfg domainconfig.BPFPluginSettings) domainconfig.BPFPluginSettings {
	clone := cfg
	clone.Plugins = append([]domainconfig.BPFPluginConfig(nil), cfg.Plugins...)
	return clone
}
