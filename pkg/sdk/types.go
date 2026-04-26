package sdk

import (
	"fmt"

	"github.com/netxfw/netxfw/pkg/configvalidate"
)

func (c *BPFPluginConfig) Validate() error {
	if c.Path == "" {
		return fmt.Errorf("plugin path is required")
	}
	if err := configvalidate.ValidateBPFPluginIndex(c.Index, BPFPluginSlotStart, BPFPluginSlotEnd); err != nil {
		return err
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

func (c *GlobalConfig) Validate() error {
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
	if err := configvalidate.ValidateLockListMask(c.LockListV4Mask, 32, "lock_list_v4_mask"); err != nil {
		return err
	}
	if err := configvalidate.ValidateLockListMask(c.LockListV6Mask, 128, "lock_list_v6_mask"); err != nil {
		return err
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
		if err := configvalidate.ValidateLogEngineTailPosition(rule.TailPosition); err != nil {
			return fmt.Errorf("invalid log_engine rule #%d: %w", i, err)
		}
		if rule.Action == "" {
			continue
		}
		if err := configvalidate.ValidateLogEngineAction(rule.Action); err != nil {
			return fmt.Errorf("invalid log_engine rule #%d: %w", i, err)
		}
	}
	return nil
}
