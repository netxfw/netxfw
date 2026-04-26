package configvalidate

import (
	"fmt"
	"net"
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
