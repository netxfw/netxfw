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

func (c *BPFPluginConfig) Validate() error {
	validator := NewConfigValidator()
	result := newValidationResult()
	validator.validateBPFPluginEntry(c, 0, result)
	if result.Valid {
		return nil
	}
	return errors.New(result.Errors[0].Message)
}

func (c *BPFPluginSettings) Validate() error {
	validator := NewConfigValidator()
	result := newValidationResult()
	validator.validateBPFPluginConfig(c, result)
	if result.Valid {
		return nil
	}
	return errors.New(result.Errors[0].Message)
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	validator := NewConfigValidator()
	if err := validator.Normalize(c); err != nil {
		return err
	}
	return validator.ValidateErr(c)
}

func (c *BaseConfig) Validate() error {
	cfg := DefaultConfig()
	cfg.Base = *c
	return NewConfigValidator().ValidateErr(&cfg)
}

func (c *PortConfig) Validate() error {
	cfg := DefaultConfig()
	cfg.Port = *c
	return NewConfigValidator().ValidateErr(&cfg)
}

func (c *RateLimitConfig) Validate() error {
	cfg := DefaultConfig()
	cfg.RateLimit = *c
	return NewConfigValidator().ValidateErr(&cfg)
}

func (c *LogEngineConfig) Validate() error {
	cfg := DefaultConfig()
	cfg.LogEngine = *c
	return NewConfigValidator().ValidateErr(&cfg)
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
