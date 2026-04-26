package app

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	apprule "github.com/netxfw/netxfw/internal/app/rule"
	domainrule "github.com/netxfw/netxfw/internal/domain/rule"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

// RuleAction identifies the semantic intent of a rule operation.
type RuleAction = domainrule.Action

const (
	RuleActionDeny  = domainrule.ActionDeny
	RuleActionAllow = domainrule.ActionAllow
)

// ExportRule represents a single rule for structured import/export.
type ExportRule = apprule.ExportRule

// ExportData represents the complete export structure.
type ExportData = apprule.ExportData

// AddRule adds an allow/deny rule and persists configuration when needed.
func AddRule(s *sdk.SDK, ip string, port uint16, action RuleAction) error {
	return apprule.Add(s, ip, port, action)
}

// DeleteRule removes an IP or IP+port rule and updates persisted state when applicable.
func DeleteRule(cfg *sdk.GlobalConfig, s *sdk.SDK, ip string, port uint16) (removed bool, err error) {
	return apprule.Remove(cfg, s, ip, port)
}

// DeleteFromAllRuleStores removes an entry from every applicable runtime store.
func DeleteFromAllRuleStores(s *sdk.SDK, ip string, port uint16) []string {
	return apprule.RemoveFromAll(s, ip, port)
}

// LoadAndSyncConfigToRuntime reloads config and syncs it to runtime maps without overwrite.
func LoadAndSyncConfigToRuntime(s *sdk.SDK) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	return s.Sync.ToMap(cfg, false)
}

// SyncRuntimeToConfig dumps runtime BPF state into configuration files.
func SyncRuntimeToConfig(s *sdk.SDK) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	return s.Sync.ToConfig(cfg)
}

// SyncConfigToRuntime applies configuration files to runtime BPF maps.
func SyncConfigToRuntime(s *sdk.SDK, overwrite bool) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	return s.Sync.ToMap(cfg, overwrite)
}

// SyncConfigToRuntimeOverwrite applies configuration files to runtime BPF maps with overwrite enabled.
func SyncConfigToRuntimeOverwrite(s *sdk.SDK) error {
	return SyncConfigToRuntime(s, true)
}

// ClearBlacklist clears the requested blacklist map.
func ClearBlacklist(ctx context.Context, dynamic bool) error {
	return apprule.ClearBlacklist(ctx, dynamic)
}

// ResetResult captures warnings produced while resetting firewall state.
type ResetResult struct {
	Warnings []string
	SSHPort  uint16
}

// ResetFirewall clears runtime rule stores and preserves SSH access.
func ResetFirewall(s *sdk.SDK) ResetResult {
	result := ResetResult{}

	if err := s.Blacklist.Clear(); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to clear static blacklist: %v", err))
	}

	dynamicEntries, _, listErr := s.Blacklist.ListDynamic(0, "")
	if listErr != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to list dynamic blacklist: %v", listErr))
	} else {
		for _, entry := range dynamicEntries {
			if err := s.Blacklist.RemoveDynamic(entry.IP); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to remove dynamic blacklist entry %s: %v", entry.IP, err))
			}
		}
	}

	if err := s.Whitelist.Clear(); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to clear whitelist: %v", err))
	}

	rules, _, err := s.Rule.ListIPPortRules(0, "")
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to list IP+Port rules: %v", err))
	} else {
		for _, rule := range rules {
			if err := s.Rule.RemoveIPPortRule(rule.IP, rule.Port); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to remove IP+Port rule %s:%d: %v", rule.IP, rule.Port, err))
			}
		}
	}

	result.SSHPort = DetectSSHPort("/etc/ssh/sshd_config")
	if err := s.Whitelist.Add("0.0.0.0/0", result.SSHPort); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to preserve SSH port %d: %v", result.SSHPort, err))
	}

	return result
}

// DetectSSHPort reads sshd_config and returns the configured port, falling back to 22.
func DetectSSHPort(configPath string) uint16 {
	data, err := os.ReadFile(configPath) // #nosec G304 // sshd_config path is caller-controlled configuration input
	if err != nil {
		return 22
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Port ") || strings.HasPrefix(line, "Port\t") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			port, convErr := strconv.Atoi(fields[1])
			if convErr == nil && port > 0 && port <= 65535 {
				return uint16(port)
			}
		}
	}
	return 22
}
