package config

import (
	"fmt"
	"net"
)

func (v *ConfigValidator) detectConflicts(cfg *Config, result *ValidationResult) {
	v.checkWhitelistBlacklistOverlap(cfg, result)
	v.checkWhitelistRateLimitOverlap(cfg, result)
	v.checkDuplicatePorts(cfg, result)
	v.checkDuplicateIPPortRules(cfg, result)
	v.checkDuplicateRateLimitRules(cfg, result)
	v.checkPortConflicts(cfg, result)
	v.checkDuplicateLogEngineRules(cfg, result)
	v.checkIPPortRulePortConflicts(cfg, result)
}

func parseIPNet(ipStr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(ipStr)
	if err == nil {
		return ipNet
	}

	if ip := net.ParseIP(ipStr); ip != nil {
		maskBits := 32
		if ip.To4() == nil {
			maskBits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(maskBits, maskBits)}
	}
	return nil
}

func (v *ConfigValidator) checkWhitelistRateLimitOverlap(cfg *Config, result *ValidationResult) {
	for _, wlCIDR := range cfg.Base.Whitelist {
		wlNet := parseIPNet(wlCIDR)
		if wlNet == nil {
			continue
		}

		for i, rlRule := range cfg.RateLimit.Rules {
			rlNet := parseIPNet(rlRule.IP)
			if rlNet == nil {
				continue
			}

			if v.networksOverlap(wlNet, rlNet) {
				result.AddWarning(fmt.Sprintf("rate_limit.rules[%d].ip", i),
					fmt.Sprintf("IP/CIDR overlaps with whitelist entry '%s' - rate limiting whitelisted IPs may cause unexpected behavior", wlCIDR), rlRule.IP)
			}
		}
	}
}

func (v *ConfigValidator) checkDuplicatePorts(cfg *Config, result *ValidationResult) {
	portSet := make(map[uint16]int)
	for i, port := range cfg.Port.AllowedPorts {
		if existingIdx, exists := portSet[port]; exists {
			result.AddWarning(fmt.Sprintf("port.allowed_ports[%d]", i),
				fmt.Sprintf("Duplicate port %d already defined at index %d", port, existingIdx), port)
		}
		portSet[port] = i
	}
}

func (v *ConfigValidator) checkDuplicateIPPortRules(cfg *Config, result *ValidationResult) {
	type ruleKey struct {
		ip   string
		port uint16
	}
	ruleSet := make(map[ruleKey]int)
	for i, rule := range cfg.Port.IPPortRules {
		key := ruleKey{ip: rule.IP, port: rule.Port}
		if existingIdx, exists := ruleSet[key]; exists {
			result.AddWarning(fmt.Sprintf("port.ip_port_rules[%d]", i),
				fmt.Sprintf("Duplicate IP+Port rule already defined at index %d", existingIdx), rule)
		}
		ruleSet[key] = i
	}
}

func (v *ConfigValidator) checkDuplicateRateLimitRules(cfg *Config, result *ValidationResult) {
	rlSet := make(map[string]int)
	for i, rule := range cfg.RateLimit.Rules {
		if existingIdx, exists := rlSet[rule.IP]; exists {
			result.AddWarning(fmt.Sprintf("rate_limit.rules[%d]", i),
				fmt.Sprintf("Duplicate rate limit rule for IP '%s' already defined at index %d", rule.IP, existingIdx), rule.IP)
		}
		rlSet[rule.IP] = i
	}
}

func (v *ConfigValidator) checkPortConflicts(cfg *Config, result *ValidationResult) {
	if cfg.Web.Enabled && cfg.Metrics.ServerEnabled && cfg.Web.Port == cfg.Metrics.Port {
		result.AddError("web.port",
			fmt.Sprintf("Web and metrics server cannot use the same port (%d)", cfg.Web.Port), cfg.Web.Port)
	}

	if cfg.Web.Enabled && cfg.Base.EnablePprof && cfg.Web.Port == cfg.Base.PprofPort {
		result.AddWarning("base.pprof_port",
			fmt.Sprintf("Web and pprof server use the same port (%d) - this may cause conflicts", cfg.Web.Port), cfg.Base.PprofPort)
	}
}

func (v *ConfigValidator) checkDuplicateLogEngineRules(cfg *Config, result *ValidationResult) {
	logRuleSet := make(map[string]int)
	for i := range cfg.LogEngine.Rules {
		rule := &cfg.LogEngine.Rules[i]
		key := rule.Path + ":" + rule.ID
		if existingIdx, exists := logRuleSet[key]; exists {
			result.AddWarning(fmt.Sprintf("log_engine.rules[%d]", i),
				fmt.Sprintf("Duplicate log engine rule (path+id) already defined at index %d", existingIdx), rule.ID)
		}
		logRuleSet[key] = i
	}
}

func (v *ConfigValidator) networksOverlap(n1, n2 *net.IPNet) bool {
	return n1.Contains(n2.IP) || n2.Contains(n1.IP)
}

func (v *ConfigValidator) checkWhitelistBlacklistOverlap(cfg *Config, result *ValidationResult) {
	for _, wlCIDR := range cfg.Base.Whitelist {
		wlNet := parseIPNet(wlCIDR)
		if wlNet == nil {
			continue
		}

		for i, rule := range cfg.Port.IPPortRules {
			if IsDenyIPPortRuleAction(rule.Action) {
				rlNet := parseIPNet(rule.IP)
				if rlNet == nil {
					continue
				}

				if v.networksOverlap(wlNet, rlNet) {
					result.AddError(fmt.Sprintf("port.ip_port_rules[%d].ip", i),
						fmt.Sprintf("Deny rule '%s' overlaps with whitelist entry '%s' - this will cause conflicts", rule.IP, wlCIDR), rule.IP)
				}
			}
		}
	}
}

func (v *ConfigValidator) checkIPPortRulePortConflicts(cfg *Config, result *ValidationResult) {
	allowedPortSet := make(map[uint16]bool)
	for _, port := range cfg.Port.AllowedPorts {
		allowedPortSet[port] = true
	}

	for i, rule := range cfg.Port.IPPortRules {
		if IsDenyIPPortRuleAction(rule.Action) && allowedPortSet[rule.Port] {
			result.AddWarning(fmt.Sprintf("port.ip_port_rules[%d]", i),
				fmt.Sprintf("Deny rule for port %d conflicts with global allowed port %d", rule.Port, rule.Port), rule.Port)
		}
	}
}
