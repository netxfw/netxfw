// Package configvalidate provides configvalidate functionality.
package configvalidate

import (
	"fmt"
	"net"
	"strings"
)

const (
	// IPPortRuleActionDeny denies traffic matching the rule.
	IPPortRuleActionDeny uint8 = 0
	// IPPortRuleActionAllow allows traffic matching the rule.
	IPPortRuleActionAllow uint8 = 1
	// IPPortRuleActionDenyCompat is a legacy deny encoding kept for compatibility.
	IPPortRuleActionDenyCompat uint8 = 2
)

// ValidateIPPortRuleAction validates the configured action value for IP+port rules.
func ValidateIPPortRuleAction(action uint8) error {
	switch action {
	case IPPortRuleActionDeny, IPPortRuleActionAllow, IPPortRuleActionDenyCompat:
		return nil
	default:
		return fmt.Errorf("action must be 0/2 (deny) or 1 (allow)")
	}
}

// ValidateBPFPluginIndex validates the configured BPF plugin slot.
func ValidateBPFPluginIndex(index, start, end int) error {
	if index < start || index > end {
		return fmt.Errorf("invalid index: %d (must be between %d and %d)", index, start, end)
	}
	return nil
}

// ValidateLockListMask validates a lock list mask value for IPv4 or IPv6.
func ValidateLockListMask(mask, maxBits int, field string) error {
	if mask < 0 || mask > maxBits {
		return fmt.Errorf("invalid %s: %d (must be 0-%d)", field, mask, maxBits)
	}
	return nil
}

// ValidateLogEngineTailPosition validates log engine tail_position values.
func ValidateLogEngineTailPosition(position string) error {
	if position == "" || position == "start" || position == "end" || position == "offset" {
		return nil
	}
	return fmt.Errorf("invalid tail_position '%s'", position)
}

// ValidateLogEngineAction validates log engine action values.
func ValidateLogEngineAction(action any) error {
	var actStr string
	switch v := action.(type) {
	case string:
		actStr = v
	case int64:
		actStr = fmt.Sprintf("%d", v)
	case int:
		actStr = fmt.Sprintf("%d", v)
	default:
		return fmt.Errorf("invalid action type: %T", action)
	}

	switch actStr {
	case "0", "1", "2", "log", "block", "dynamic", "static", "permanent", "lock", "deny", "black", "dynblock", "dynblack":
		return nil
	}
	if strings.HasPrefix(actStr, "block:") || strings.HasPrefix(actStr, "black:") {
		return nil
	}
	return fmt.Errorf("invalid action '%v'", action)
}

// IsDenyIPPortRuleAction reports whether the action is a deny semantic, including legacy encodings.
func IsDenyIPPortRuleAction(action uint8) bool {
	return action == IPPortRuleActionDeny || action == IPPortRuleActionDenyCompat
}

// ValidateCIDROrIPForConfig validates config CIDR/IP fields, including host:port forms.
func ValidateCIDROrIPForConfig(s string) error {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}
	host, _, err := net.SplitHostPort(s)
	if err == nil {
		if _, _, cidrErr := net.ParseCIDR(host); cidrErr == nil {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil {
			return nil
		}
	}
	return fmt.Errorf("invalid CIDR or IP format")
}
