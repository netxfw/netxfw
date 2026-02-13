package ratelimit

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

type RateLimitPlugin struct {
	config *types.RateLimitConfig
}

func (p *RateLimitPlugin) Name() string {
	return "ratelimit"
}

func (p *RateLimitPlugin) Init(ctx *sdk.PluginContext) error {
	p.config = &ctx.Config.RateLimit
	return nil
}

func (p *RateLimitPlugin) Reload(ctx *sdk.PluginContext) error {
	log.Println("🔄 [RateLimitPlugin] Reloading configuration (Full Sync)...")
	if err := p.Init(ctx); err != nil {
		return err
	}
	return p.Sync(ctx.Manager)
}

func (p *RateLimitPlugin) Start(ctx *sdk.PluginContext) error {
	log.Println("🚀 [RateLimitPlugin] Starting...")
	return p.Sync(ctx.Manager)
}

func (p *RateLimitPlugin) Stop() error {
	return nil
}

func (p *RateLimitPlugin) DefaultConfig() interface{} {
	return types.RateLimitConfig{}
}

func (p *RateLimitPlugin) Sync(manager *xdp.Manager) error {
	if p.config == nil {
		return nil
	}

	// 1. Set global rate limit toggle
	if err := manager.SetEnableRateLimit(p.config.Enabled); err != nil {
		log.Printf("⚠️  [RateLimitPlugin] Failed to set enable rate limit: %v", err)
	}

	// 2. Set auto-block toggle and expiry
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

	// 3. Sync Rate Limit Rules
	currentRules, _, err := manager.ListRateLimitRules(0, "")
	if err != nil {
		log.Printf("⚠️ [RateLimitPlugin] Failed to list current rules: %v", err)
		return fmt.Errorf("failed to list rate limit rules: %w", err)
	}

	desiredRules := make(map[string]types.RateLimitRule)
	for _, rule := range p.config.Rules {
		_, ipNet, err := net.ParseCIDR(rule.IP)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(rule.IP)
			if ip == nil {
				log.Printf("⚠️ [RateLimitPlugin] Invalid IP/CIDR: %s", rule.IP)
				continue
			}
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}

		ones, _ := ipNet.Mask.Size()
		key := fmt.Sprintf("%s/%d", ipNet.IP.String(), ones)
		desiredRules[key] = rule
	}

	// Remove obsolete
	for key := range currentRules {
		if _, ok := desiredRules[key]; !ok {
			_, ipNet, _ := net.ParseCIDR(key)
			if err := manager.RemoveRateLimitRule(ipNet); err != nil {
				log.Printf("⚠️ [RateLimitPlugin] Failed to remove rule %s: %v", key, err)
			} else {
				log.Printf("➖ [RateLimitPlugin] Removed rule %s", key)
			}
		}
	}

	// Add/Update
	for key, rule := range desiredRules {
		currentVal, exists := currentRules[key]
		if !exists || currentVal.Rate != rule.Rate || currentVal.Burst != rule.Burst {
			_, ipNet, _ := net.ParseCIDR(key)
			if err := manager.AddRateLimitRule(ipNet, rule.Rate, rule.Burst); err != nil {
				log.Printf("⚠️ [RateLimitPlugin] Failed to update rule %s: %v", key, err)
			} else {
				log.Printf("➕ [RateLimitPlugin] Updated rule %s", key)
			}
		}
	}

	log.Printf("✅ [RateLimitPlugin] Sync complete. Active rules: %d", len(desiredRules))
	return nil
}

func (p *RateLimitPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
