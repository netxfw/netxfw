package sdk

import (
	"fmt"

	"strings"
)

func makeIPPortRuleKey(cidr string, port uint16) string {
	return fmt.Sprintf("%s:%d", cidr, port)
}

func matchSearch(value, search string) bool {
	if search == "" {
		return true
	}
	return strings.Contains(value, search)
}

func applyLimit[T any](items []T, limit int) []T {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func cloneRateLimitRules(src map[string]RateLimitConf) map[string]RateLimitConf {
	out := make(map[string]RateLimitConf, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneConntrackEntries(src []ConntrackEntry) []ConntrackEntry {
	return append([]ConntrackEntry(nil), src...)
}

func cloneBlockedIPs(src []BlockedIP) []BlockedIP {
	return append([]BlockedIP(nil), src...)
}

func cloneIPPortRules(src []IPPortRule) []IPPortRule {
	return append([]IPPortRule(nil), src...)
}

func cloneWhitelistEntries(src []string) []string {
	return append([]string(nil), src...)
}

func cloneAllowedPorts(src []uint16) []uint16 {
	return append([]uint16(nil), src...)
}
