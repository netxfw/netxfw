package rule

import (
	"fmt"

	appconfig "github.com/netxfw/netxfw/internal/app/config"
	domainrule "github.com/netxfw/netxfw/internal/domain/rule"
	"github.com/netxfw/netxfw/internal/optimizer"
	appruntime "github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/iputil"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type Action = domainrule.Action

const (
	ActionDeny  = domainrule.ActionDeny
	ActionAllow = domainrule.ActionAllow
)

func Add(fw *sdk.SDK, ip string, port uint16, action Action) error {
	return AddWithRuntime(NewRuntime(fw), ip, port, action)
}

func AddWithRuntime(runtime ruleRuntime, ip string, port uint16, action Action) error {
	if port > 0 {
		act := uint8(action)
		if err := runtime.Rule().AddIPPortRule(ip, port, act); err != nil {
			return err
		}
		return persistIPPortRule(ip, port, act)
	}

	if action == ActionAllow {
		if err := runtime.Whitelist().Add(ip, 0); err != nil {
			return err
		}
		if err := persistWhitelistEntry(ip, 0); err != nil {
			return err
		}
		_ = runtime.Blacklist().Remove(ip)
		return nil
	}

	if err := runtime.Blacklist().Add(ip); err != nil {
		return err
	}
	_ = runtime.Whitelist().Remove(ip)
	return nil
}

func persistWhitelistEntry(ip string, port uint16) error {
	if appruntime.Mode == "test" {
		return nil
	}

	return appconfig.MutateLoadedConfig(func(globalCfg *sdk.GlobalConfig) error {
		normalizedCIDR := iputil.NormalizeCIDR(ip)
		entry := normalizedCIDR
		if port > 0 {
			entry = fmt.Sprintf("%s:%d", normalizedCIDR, port)
		}

		for _, existing := range globalCfg.Base.Whitelist {
			host, existingPort, parseErr := iputil.ParseIPPort(existing)
			existingCIDR := ""
			if parseErr == nil {
				existingCIDR = iputil.NormalizeCIDR(host)
			} else {
				existingCIDR = iputil.NormalizeCIDR(existing)
				existingPort = 0
			}

			if existingCIDR == normalizedCIDR && existingPort == port {
				return nil
			}
		}

		globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, entry)
		optimizer.OptimizeWhitelistConfig(globalCfg)
		return nil
	})
}

func persistIPPortRule(ip string, port uint16, action uint8) error {
	if appruntime.Mode == "test" {
		return nil
	}

	return appconfig.MutateLoadedConfig(func(globalCfg *sdk.GlobalConfig) error {
		normalizedCIDR := iputil.NormalizeCIDR(ip)
		updated := false

		for i := range globalCfg.Port.IPPortRules {
			ruleCIDR := iputil.NormalizeCIDR(globalCfg.Port.IPPortRules[i].IP)
			if ruleCIDR == normalizedCIDR && globalCfg.Port.IPPortRules[i].Port == port {
				globalCfg.Port.IPPortRules[i].Action = action
				updated = true
				break
			}
		}

		if !updated {
			globalCfg.Port.IPPortRules = append(globalCfg.Port.IPPortRules, sdk.IPPortRule{
				IP:     normalizedCIDR,
				Port:   port,
				Action: action,
			})
		}

		optimizer.OptimizeIPPortRulesConfig(globalCfg)
		return nil
	})
}
