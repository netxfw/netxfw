package types

import (
	"fmt"
	"net"
)

// detectConflicts detects conflicts between different configuration sections.
// detectConflicts 检测不同配置部分之间的冲突。
func (v *ConfigValidator) detectConflicts(cfg *GlobalConfig, result *ValidationResult) {
	v.checkWhitelistRateLimitOverlap(cfg, result)
	v.checkDuplicatePorts(cfg, result)
	v.checkDuplicateIPPortRules(cfg, result)
	v.checkDuplicateRateLimitRules(cfg, result)
	v.checkPortConflicts(cfg, result)
	v.checkDuplicateLogEngineRules(cfg, result)
}

// parseIPNet parses an IP or CIDR string into a network.
// parseIPNet 将 IP 或 CIDR 字符串解析为网络。
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

// checkWhitelistRateLimitOverlap checks for overlapping IPs between whitelist and rate limit rules.
// checkWhitelistRateLimitOverlap 检查白名单和速率限制规则之间的 IP 重叠。
func (v *ConfigValidator) checkWhitelistRateLimitOverlap(cfg *GlobalConfig, result *ValidationResult) {
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

// checkDuplicatePorts checks for duplicate ports in allowed_ports.
// checkDuplicatePorts 检查 allowed_ports 中的重复端口。
func (v *ConfigValidator) checkDuplicatePorts(cfg *GlobalConfig, result *ValidationResult) {
	portSet := make(map[uint16]int)
	for i, port := range cfg.Port.AllowedPorts {
		if existingIdx, exists := portSet[port]; exists {
			result.AddWarning(fmt.Sprintf("port.allowed_ports[%d]", i),
				fmt.Sprintf("Duplicate port %d already defined at index %d", port, existingIdx), port)
		}
		portSet[port] = i
	}
}

// checkDuplicateIPPortRules checks for conflicting IP-Port rules.
// checkDuplicateIPPortRules 检查冲突的 IP-端口规则。
func (v *ConfigValidator) checkDuplicateIPPortRules(cfg *GlobalConfig, result *ValidationResult) {
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

// checkDuplicateRateLimitRules checks for conflicting rate limit rules.
// checkDuplicateRateLimitRules 检查冲突的速率限制规则。
func (v *ConfigValidator) checkDuplicateRateLimitRules(cfg *GlobalConfig, result *ValidationResult) {
	rlSet := make(map[string]int)
	for i, rule := range cfg.RateLimit.Rules {
		if existingIdx, exists := rlSet[rule.IP]; exists {
			result.AddWarning(fmt.Sprintf("rate_limit.rules[%d]", i),
				fmt.Sprintf("Duplicate rate limit rule for IP '%s' already defined at index %d", rule.IP, existingIdx), rule.IP)
		}
		rlSet[rule.IP] = i
	}
}

// checkPortConflicts checks for port conflicts between web, metrics, and pprof.
// checkPortConflicts 检查 Web、指标和 pprof 之间的端口冲突。
func (v *ConfigValidator) checkPortConflicts(cfg *GlobalConfig, result *ValidationResult) {
	if cfg.Web.Enabled && cfg.Metrics.ServerEnabled && cfg.Web.Port == cfg.Metrics.Port {
		result.AddError("web.port",
			fmt.Sprintf("Web and metrics server cannot use the same port (%d)", cfg.Web.Port), cfg.Web.Port)
	}

	if cfg.Web.Enabled && cfg.Base.EnablePprof && cfg.Web.Port == cfg.Base.PprofPort {
		result.AddWarning("base.pprof_port",
			fmt.Sprintf("Web and pprof server use the same port (%d) - this may cause conflicts", cfg.Web.Port), cfg.Base.PprofPort)
	}
}

// checkDuplicateLogEngineRules checks for conflicting log engine rules.
// checkDuplicateLogEngineRules 检查冲突的日志引擎规则。
func (v *ConfigValidator) checkDuplicateLogEngineRules(cfg *GlobalConfig, result *ValidationResult) {
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

// networksOverlap checks if two networks overlap.
// networksOverlap 检查两个网络是否重叠。
func (v *ConfigValidator) networksOverlap(n1, n2 *net.IPNet) bool {
	return n1.Contains(n2.IP) || n2.Contains(n1.IP)
}
