// Package config provides config functionality.
package config

import (
	"errors"

	"github.com/netxfw/netxfw/pkg/configvalidate"
)

const (
	// IPPortRuleActionDeny denies traffic matching the rule.
	IPPortRuleActionDeny = configvalidate.IPPortRuleActionDeny
	// IPPortRuleActionAllow allows traffic matching the rule.
	IPPortRuleActionAllow = configvalidate.IPPortRuleActionAllow
	// IPPortRuleActionDenyCompat is a legacy deny encoding kept for compatibility.
	IPPortRuleActionDenyCompat = configvalidate.IPPortRuleActionDenyCompat
)

// ValidateConfig runs the comprehensive domain-level validator on the config.
// This supplements the basic SDK Validate() method with normalization and
// cross-field conflict checks.
func ValidateConfigFull(c *Config) error {
	validator := NewConfigValidator()
	if err := validator.Normalize(c); err != nil {
		return err
	}
	return validator.ValidateErr(c)
}

// ValidateBPFPlugin validates a single BPF plugin config entry.
func ValidateBPFPlugin(c *BPFPluginConfig) error {
	validator := NewConfigValidator()
	result := newValidationResult()
	validator.validateBPFPluginEntry(c, 0, result)
	if result.Valid {
		return nil
	}
	return errors.New(result.Errors[0].Message)
}

// ValidateBPFPluginSettings validates the BPF plugin settings.
func ValidateBPFPluginSettings(c *BPFPluginSettings) error {
	validator := NewConfigValidator()
	result := newValidationResult()
	validator.validateBPFPluginConfig(c, result)
	if result.Valid {
		return nil
	}
	return errors.New(result.Errors[0].Message)
}

// ValidateIPPortRuleAction validates the configured action value for IP+port rules.
func ValidateIPPortRuleAction(action uint8) error {
	return configvalidate.ValidateIPPortRuleAction(action)
}

// IsDenyIPPortRuleAction reports whether the action is a deny semantic, including legacy encodings.
func IsDenyIPPortRuleAction(action uint8) bool {
	return configvalidate.IsDenyIPPortRuleAction(action)
}

// ValidateCIDROrIPForConfig validates config CIDR/IP fields, including host:port forms.
func ValidateCIDROrIPForConfig(s string) error {
	return configvalidate.ValidateCIDROrIPForConfig(s)
}
