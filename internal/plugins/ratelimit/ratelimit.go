package ratelimit

import (
	"log"
	"net"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

type RateLimitPlugin struct {
	config *types.RateLimitConfig
}

func (p *RateLimitPlugin) Name() string {
	return "ratelimit"
}

func (p *RateLimitPlugin) Init(config *types.GlobalConfig) error {
	p.config = &config.RateLimit
	return nil
}

func (p *RateLimitPlugin) Start(manager *xdp.Manager) error {
	if p.config == nil {
		return nil
	}

	// 1. Set global rate limit toggle
	if err := manager.SetEnableRateLimit(p.config.Enabled); err != nil {
		log.Printf("⚠️  [RateLimitPlugin] Failed to set enable rate limit: %v", err)
	}

	// 2. Set auto-block toggle and expiry (duplicated from base for safety or managed here)
	if err := manager.SetAutoBlock(p.config.AutoBlock); err != nil {
		log.Printf("⚠️  [RateLimitPlugin] Failed to set auto-block: %v", err)
	}

	if p.config.AutoBlockExpiry != "" {
		duration, err := time.ParseDuration(p.config.AutoBlockExpiry)
		if err == nil {
			if err := manager.SetAutoBlockExpiry(duration); err != nil {
				log.Printf("⚠️  [RateLimitPlugin] Failed to set auto-block expiry: %v", err)
			}
		}
	}

	// 3. Apply rate limit rules
	if p.config.Enabled {
		count := 0
		for _, rule := range p.config.Rules {
			_, ipNet, err := net.ParseCIDR(rule.IP)
			if err != nil {
				// Try parsing as single IP
				ip := net.ParseIP(rule.IP)
				if ip == nil {
					log.Printf("⚠️  [RateLimitPlugin] Invalid IP/CIDR: %s", rule.IP)
					continue
				}
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				ipNet = &net.IPNet{IP: ip, Mask: mask}
			}

			if err := manager.AddRateLimitRule(ipNet, rule.Rate, rule.Burst); err != nil {
				log.Printf("⚠️  [RateLimitPlugin] Failed to add rule for %s: %v", rule.IP, err)
				continue
			}
			count++
		}
		log.Printf("✅ [RateLimitPlugin] Applied %d rate limit rules", count)
	}

	return nil
}

func (p *RateLimitPlugin) Stop() error {
	return nil
}

func (p *RateLimitPlugin) DefaultConfig() interface{} {
	return types.RateLimitConfig{
		Enabled:         false,
		AutoBlock:       false,
		AutoBlockExpiry: "5m",
		Rules:           []types.RateLimitRule{},
	}
}

func (p *RateLimitPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
