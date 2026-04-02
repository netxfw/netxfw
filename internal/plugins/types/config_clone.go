package types

// CloneGlobalConfig returns a deep copy of cfg.
func CloneGlobalConfig(cfg *GlobalConfig) *GlobalConfig {
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
	clone.Modules = cloneModuleConfigs(cfg.Modules)
	return &clone
}

func cloneBaseConfig(cfg BaseConfig) BaseConfig {
	clone := cfg
	clone.Interfaces = append([]string(nil), cfg.Interfaces...)
	clone.Whitelist = append([]string(nil), cfg.Whitelist...)
	return clone
}

func clonePortConfig(cfg PortConfig) PortConfig {
	clone := cfg
	clone.AllowedPorts = append([]uint16(nil), cfg.AllowedPorts...)
	clone.IPPortRules = append([]IPPortRule(nil), cfg.IPPortRules...)
	return clone
}

func cloneRateLimitConfig(cfg RateLimitConfig) RateLimitConfig {
	clone := cfg
	clone.Rules = append([]RateLimitRule(nil), cfg.Rules...)
	return clone
}

func cloneLogEngineConfig(cfg LogEngineConfig) LogEngineConfig {
	clone := cfg
	clone.Rules = append([]LogEngineRule(nil), cfg.Rules...)
	for i := range clone.Rules {
		clone.Rules[i] = cloneLogEngineRule(clone.Rules[i])
	}
	return clone
}

func cloneLogEngineRule(rule LogEngineRule) LogEngineRule {
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

func cloneCloudConfig(cfg CloudConfig) CloudConfig {
	clone := cfg
	clone.ProxyProtocol = cloneProxyProtocolConfig(cfg.ProxyProtocol)
	return clone
}

func cloneProxyProtocolConfig(cfg ProxyProtocolConfig) ProxyProtocolConfig {
	clone := cfg
	clone.TrustedLBRanges = append([]string(nil), cfg.TrustedLBRanges...)
	return clone
}

func cloneBPFPluginSettings(cfg BPFPluginSettings) BPFPluginSettings {
	clone := cfg
	clone.Plugins = append([]BPFPluginConfig(nil), cfg.Plugins...)
	return clone
}

func cloneModuleConfigs(modules []ModuleConfig) []ModuleConfig {
	return append([]ModuleConfig(nil), modules...)
}
