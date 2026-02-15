package types

import (
	"fmt"
	"net"

	"github.com/livp123/netxfw/internal/utils/iputil"
)

// Validate checks the configuration for errors.
// Validate 检查配置是否存在错误。
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

	// Align Conntrack Capacity with Conntrack Config
	// 将连接跟踪容量与连接跟踪配置对齐
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
		if err := validateCIDR(cidr); err != nil {
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
		if rule.Action != 1 && rule.Action != 2 {
			return fmt.Errorf("invalid ip_port_rule #%d: action must be 1 (allow) or 2 (deny)", i)
		}
		if err := validateIP(rule.IP); err != nil {
			return fmt.Errorf("invalid ip_port_rule #%d IP (%s): %w", i, rule.IP, err)
		}
	}
	return nil
}

func (c *RateLimitConfig) Validate() error {
	for i, rule := range c.Rules {
		if err := validateCIDR(rule.IP); err != nil {
			return fmt.Errorf("invalid rate_limit rule #%d IP (%s): %w", i, rule.IP, err)
		}
	}
	return nil
}

func (c *LogEngineConfig) Validate() error {
	for i, rule := range c.Rules {
		if rule.TailPosition != "" && rule.TailPosition != "start" && rule.TailPosition != "end" && rule.TailPosition != "offset" {
			return fmt.Errorf("invalid log_engine rule #%d: invalid tail_position '%s'", i, rule.TailPosition)
		}
		if rule.Action != "" && rule.Action != "block" && rule.Action != "log" {
			return fmt.Errorf("invalid log_engine rule #%d: invalid action '%s'", i, rule.Action)
		}
	}
	return nil
}

func validateCIDR(s string) error {
	if iputil.IsValidCIDR(s) || iputil.IsValidIP(s) {
		return nil
	}

	// Try with port (CIDR:Port or IP:Port)
	host, _, err := net.SplitHostPort(s)
	if err == nil {
		if iputil.IsValidCIDR(host) || iputil.IsValidIP(host) {
			return nil
		}
	}

	return fmt.Errorf("invalid CIDR or IP format")
}

func validateIP(s string) error {
	return validateCIDR(s)
}
