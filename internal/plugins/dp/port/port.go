package port

import (
	"fmt"
	"log"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

// PortPlugin implements a plugin that manages IP+Port rules.
type PortPlugin struct {
	config *types.PortConfig
}

func (p *PortPlugin) Name() string {
	return "port"
}

func (p *PortPlugin) Init(ctx *sdk.PluginContext) error {
	p.config = &ctx.Config.Port
	return nil
}

func (p *PortPlugin) Reload(ctx *sdk.PluginContext) error {
	log.Println("🔄 [PortPlugin] Reloading port configuration (Full Sync)...")
	if err := p.Init(ctx); err != nil {
		return err
	}
	return p.Sync(ctx.Manager)
}

func (p *PortPlugin) Start(ctx *sdk.PluginContext) error {
	log.Println("🚀 [PortPlugin] Starting...")
	return p.Sync(ctx.Manager)
}

// Sync synchronizes the current configuration with the BPF maps (Add/Remove)
func (p *PortPlugin) Sync(manager *xdp.Manager) error {
	if p.config == nil {
		return nil
	}

	// --- 1. Sync Global Allowed Ports ---
	currentPorts, err := manager.ListAllowedPorts()
	if err != nil {
		log.Printf("⚠️ [PortPlugin] Failed to list current allowed ports: %v", err)
		return fmt.Errorf("failed to list allowed ports: %w", err)
	}

	desiredPorts := make(map[uint16]bool)
	for _, port := range p.config.AllowedPorts {
		desiredPorts[port] = true
	}

	existingPorts := make(map[uint16]bool)
	for _, port := range currentPorts {
		existingPorts[port] = true
	}

	// Remove ports not in config
	for port := range existingPorts {
		if !desiredPorts[port] {
			if err := manager.RemovePort(port); err != nil {
				log.Printf("⚠️ [PortPlugin] Failed to remove port %d: %v", port, err)
			} else {
				log.Printf("➖ [PortPlugin] Removed port %d", port)
			}
		}
	}

	// Add ports in config
	for port := range desiredPorts {
		if !existingPorts[port] {
			if err := manager.AllowPort(port, nil); err != nil {
				log.Printf("⚠️ [PortPlugin] Failed to allow port %d: %v", port, err)
			} else {
				log.Printf("➕ [PortPlugin] Allowed port %d", port)
			}
		}
	}

	// --- 2. Sync IP+Port Rules ---
	if err := p.syncIPPortRules(manager, false); err != nil {
		log.Printf("⚠️ [PortPlugin] Failed to sync IPv4 rules: %v", err)
	}
	if err := p.syncIPPortRules(manager, true); err != nil {
		log.Printf("⚠️ [PortPlugin] Failed to sync IPv6 rules: %v", err)
	}

	log.Printf("✅ [PortPlugin] Sync complete. Active: %d global ports, %d IP+Port rules",
		len(p.config.AllowedPorts), len(p.config.IPPortRules))
	return nil
}

func (p *PortPlugin) syncIPPortRules(manager *xdp.Manager, isIPv6 bool) error {
	// List existing rules
	currentRulesMap, _, err := manager.ListIPPortRules(isIPv6, 0, "")
	if err != nil {
		return err
	}

	// Build desired rules map for fast lookup
	// Format: "IP/Prefix:Port"
	desiredRulesMap := make(map[string]types.IPPortRule)
	for _, rule := range p.config.IPPortRules {
		// Parse rule.IP to get canonical form
		ipNet, err := iputil.ParseCIDR(rule.IP)
		if err != nil {
			continue // Invalid IP
		}

		isV4 := ipNet.IP.To4() != nil
		if isIPv6 && isV4 {
			continue
		}
		if !isIPv6 && !isV4 {
			continue
		}

		// Canonical string
		ones, _ := ipNet.Mask.Size()
		key := fmt.Sprintf("%s/%d:%d", ipNet.IP.String(), ones, rule.Port)
		desiredRulesMap[key] = rule
	}

	// Remove rules not in config
	for key := range currentRulesMap {
		if _, ok := desiredRulesMap[key]; !ok {
			// Parse key back to IPNet and Port to remove
			// key: "IP/Prefix:Port"
			// iputil.ParseIPPort expects "Host:Port", and "IP/Prefix" is a valid host string for SplitHostPort
			ipCIDR, port, err := iputil.ParseIPPort(key)
			if err != nil {
				continue
			}

			ipNet, err := iputil.ParseCIDR(ipCIDR) // Should be valid as it came from Manager
			if err != nil {
				continue
			}

			if err := manager.RemoveIPPortRule(ipNet, port); err != nil {
				log.Printf("⚠️ [PortPlugin] Failed to remove rule %s: %v", key, err)
			} else {
				log.Printf("➖ [PortPlugin] Removed rule %s", key)
			}
		}
	}

	// Add/Update rules from config
	for key, rule := range desiredRulesMap {
		currentActionStr, exists := currentRulesMap[key]
		desiredActionStr := "allow"
		if rule.Action == 2 {
			desiredActionStr = "deny"
		}

		if !exists || currentActionStr != desiredActionStr {
			// Add or Update
			// Re-parse key to get clean IPNet
			ipCIDR, _, err := iputil.ParseIPPort(key)
			if err != nil {
				continue
			}
			ipNet, err := iputil.ParseCIDR(ipCIDR)
			if err != nil {
				continue
			}

			if err := manager.AddIPPortRule(ipNet, rule.Port, rule.Action, nil); err != nil {
				log.Printf("⚠️ [PortPlugin] Failed to update rule %s: %v", key, err)
			} else {
				log.Printf("➕ [PortPlugin] Updated rule %s (%s)", key, desiredActionStr)
			}
		}
	}
	return nil
}

func (p *PortPlugin) Stop() error {
	return nil
}

func (p *PortPlugin) DefaultConfig() interface{} {
	return types.PortConfig{
		AllowedPorts: []uint16{22},
		IPPortRules:  []types.IPPortRule{},
	}
}

func (p *PortPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
