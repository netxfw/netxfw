package config

import (
	"fmt"
	"strings"

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
	if c.Path == "" {
		return fmt.Errorf("plugin path is required")
	}
	if c.Index < BPFPluginSlotStart || c.Index > BPFPluginSlotEnd {
		return fmt.Errorf("invalid index: %d (must be between %d and %d)", c.Index, BPFPluginSlotStart, BPFPluginSlotEnd)
	}
	return nil
}

func (c *BPFPluginSettings) Validate() error {
	if !c.Enabled {
		return nil
	}

	seen := make(map[int]int, len(c.Plugins))
	for i := range c.Plugins {
		plugin := &c.Plugins[i]
		if !plugin.Enabled {
			continue
		}
		if err := plugin.Validate(); err != nil {
			return fmt.Errorf("bpf plugin #%d: %w", i, err)
		}
		if prev, ok := seen[plugin.Index]; ok {
			return fmt.Errorf("bpf plugin #%d: duplicate index %d already used by plugin #%d", i, plugin.Index, prev)
		}
		seen[plugin.Index] = i
	}

	return nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if err := c.Base.Validate(); err != nil {
		return fmt.Errorf("base config error: %w", err)
	}
	if err := c.Port.Validate(); err != nil {
		return fmt.Errorf("port config error: %w", err)
	}
	if err := c.RateLimit.Validate(); err != nil {
		return fmt.Errorf("rate_limit config error: %w", err)
	}
	if err := c.LogEngine.Validate(); err != nil {
		return fmt.Errorf("log_engine config error: %w", err)
	}
	if err := c.BPFPlugin.Validate(); err != nil {
		return fmt.Errorf("bpf_plugin config error: %w", err)
	}
	if c.Conntrack.MaxEntries > 0 {
		c.Capacity.Conntrack = c.Conntrack.MaxEntries
	}
	return nil
}

func (c *BaseConfig) Validate() error {
	if c.LockListV4Mask < 0 || c.LockListV4Mask > 32 {
		return fmt.Errorf("invalid lock_list_v4_mask: %d (must be 0-32)", c.LockListV4Mask)
	}
	if c.LockListV6Mask < 0 || c.LockListV6Mask > 128 {
		return fmt.Errorf("invalid lock_list_v6_mask: %d (must be 0-128)", c.LockListV6Mask)
	}
	for i, cidr := range c.Whitelist {
		if err := configvalidate.ValidateCIDROrIPForConfig(cidr); err != nil {
			return fmt.Errorf("invalid whitelist entry #%d (%s): %w", i, cidr, err)
		}
	}
	return nil
}

func (c *PortConfig) Validate() error {
	for i, rule := range c.IPPortRules {
		if rule.Port == 0 {
			return fmt.Errorf("invalid ip_port_rule #%d: port cannot be 0", i)
		}
		if err := configvalidate.ValidateIPPortRuleAction(rule.Action); err != nil {
			return fmt.Errorf("invalid ip_port_rule #%d: %w", i, err)
		}
		if err := configvalidate.ValidateCIDROrIPForConfig(rule.IP); err != nil {
			return fmt.Errorf("invalid ip_port_rule #%d IP (%s): %w", i, rule.IP, err)
		}
	}
	return nil
}

func (c *RateLimitConfig) Validate() error {
	for i, rule := range c.Rules {
		if err := configvalidate.ValidateCIDROrIPForConfig(rule.IP); err != nil {
			return fmt.Errorf("invalid rate_limit rule #%d IP (%s): %w", i, rule.IP, err)
		}
	}
	return nil
}

func (c *LogEngineConfig) Validate() error {
	for i := range c.Rules {
		rule := &c.Rules[i]
		if rule.TailPosition != "" && rule.TailPosition != "start" && rule.TailPosition != "end" && rule.TailPosition != "offset" {
			return fmt.Errorf("invalid log_engine rule #%d: invalid tail_position '%s'", i, rule.TailPosition)
		}
		if rule.Action == "" {
			continue
		}
		switch rule.Action {
		case "0", "1", "2", "log", "block", "dynamic", "static", "permanent", "lock", "deny", "black", "dynblock", "dynblack":
			continue
		}
		if !strings.HasPrefix(rule.Action, "block:") && !strings.HasPrefix(rule.Action, "black:") {
			return fmt.Errorf("invalid log_engine rule #%d: invalid action '%s'", i, rule.Action)
		}
	}
	return nil
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
