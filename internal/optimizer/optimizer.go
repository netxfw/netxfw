package optimizer

import (
	"fmt"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/utils/iputil"
)

// OptimizeWhitelistConfig optimizes the whitelist in the configuration.
// OptimizeWhitelistConfig 优化配置中的白名单。
func OptimizeWhitelistConfig(cfg *types.GlobalConfig) {
	rulesByPort := make(map[uint16][]string)
	for _, line := range cfg.Base.Whitelist {
		cidr := line
		var port uint16

		// Try parsing as IP:Port or CIDR:Port
		// 尝试解析为 IP:Port 或 CIDR:Port
		host, p, err := iputil.ParseIPPort(line)
		if err == nil {
			cidr = host
			port = p
		}

		rulesByPort[port] = append(rulesByPort[port], cidr)
	}

	var newWhitelist []string
	for port, cidrs := range rulesByPort {
		merged, err := ipmerge.MergeCIDRs(cidrs)
		if err != nil {
			merged = cidrs
		}
		for _, cidr := range merged {
			entry := cidr
			if port > 0 {
				entry = fmt.Sprintf("%s:%d", cidr, port)
			}
			newWhitelist = append(newWhitelist, entry)
		}
	}
	cfg.Base.Whitelist = newWhitelist
}

// OptimizeIPPortRulesConfig optimizes IP+Port rules in the configuration.
// OptimizeIPPortRulesConfig 优化配置中的 IP+端口规则。
func OptimizeIPPortRulesConfig(cfg *types.GlobalConfig) {
	type ruleKey struct {
		port   uint16
		action uint8
	}
	rulesByGroup := make(map[ruleKey][]string)

	for _, r := range cfg.Port.IPPortRules {
		key := ruleKey{r.Port, r.Action}
		rulesByGroup[key] = append(rulesByGroup[key], r.IP)
	}
	var newRules []types.IPPortRule
	for key, cidrs := range rulesByGroup {
		merged, err := ipmerge.MergeCIDRs(cidrs)
		if err != nil {
			merged = cidrs
		}
		for _, cidr := range merged {
			newRules = append(newRules, types.IPPortRule{
				IP:     cidr,
				Port:   key.port,
				Action: key.action,
			})
		}
	}
	cfg.Port.IPPortRules = newRules
}
