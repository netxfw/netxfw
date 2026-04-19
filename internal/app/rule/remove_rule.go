package rule

import (
	"fmt"

	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/iputil"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

func Remove(cfg *sdk.GlobalConfig, fw *sdk.SDK, ip string, port uint16) (bool, error) {
	return RemoveWithRuntime(cfg, NewRuntime(fw), ip, port)
}

func RemoveWithRuntime(cfg *sdk.GlobalConfig, runtime ruleRuntime, ip string, port uint16) (removed bool, err error) {
	if port > 0 {
		if err := runtime.Rule().RemoveIPPortRule(ip, port); err != nil {
			return false, fmt.Errorf("failed to delete IP+Port rule: %v", err)
		}
		return true, nil
	}

	normalizedIP := iputil.NormalizeCIDR(ip)
	if err := runtime.Blacklist().Remove(ip); err == nil {
		if cfg != nil && cfg.Base.PersistRules && cfg.Base.LockListFile != "" {
			_ = fileutil.RemoveFromFile(cfg.Base.LockListFile, normalizedIP)
		}
		removed = true
	}
	if err := runtime.Whitelist().Remove(ip); err == nil {
		removed = true
	}
	return removed, nil
}

func RemoveFromAll(fw *sdk.SDK, ip string, port uint16) []string {
	return RemoveFromAllWithRuntime(NewRuntime(fw), ip, port)
}

func RemoveFromAllWithRuntime(runtime ruleRuntime, ip string, port uint16) []string {
	messages := make([]string, 0, 3)
	if port > 0 {
		if err := runtime.Rule().RemoveIPPortRule(ip, port); err == nil {
			messages = append(messages, fmt.Sprintf("Removed IP+Port rule: %s:%d", ip, port))
		}
		return messages
	}
	if err := runtime.Blacklist().Remove(ip); err == nil {
		messages = append(messages, fmt.Sprintf("Removed %s from static blacklist", ip))
	}
	if err := runtime.Blacklist().RemoveDynamic(ip); err == nil {
		messages = append(messages, fmt.Sprintf("Removed %s from dynamic blacklist", ip))
	}
	if err := runtime.Whitelist().Remove(ip); err == nil {
		messages = append(messages, fmt.Sprintf("Removed %s from whitelist", ip))
	}
	return messages
}
