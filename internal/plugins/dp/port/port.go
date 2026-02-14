package port

import (
	"fmt"

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
	ctx.Logger.Infof("🔄 [PortPlugin] Reloading port configuration (Full Sync)...")
	if err := p.Init(ctx); err != nil {
		return err
	}
	return p.Sync(ctx.Manager, ctx.Logger)
}

func (p *PortPlugin) Start(ctx *sdk.PluginContext) error {
	ctx.Logger.Infof("🚀 [PortPlugin] Starting...")
	return p.Sync(ctx.Manager, ctx.Logger)
}

// Sync synchronizes the current configuration with the BPF maps (Add/Remove)
func (p *PortPlugin) Sync(manager xdp.ManagerInterface, logger sdk.Logger) error {
	if p.config == nil {
		return nil
	}

	// --- 1. Sync Global Allowed Ports ---
	currentPorts, err := manager.ListAllowedPorts()
	if err != nil {
		logger.Warnf("⚠️ [PortPlugin] Failed to list current allowed ports: %v", err)
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
			if err := manager.RemoveAllowedPort(port); err != nil {
				logger.Warnf("⚠️ [PortPlugin] Failed to remove port %d: %v", port, err)
			} else {
				logger.Infof("➖ [PortPlugin] Removed port %d", port)
			}
		}
	}

	// Add ports in config
	for port := range desiredPorts {
		if !existingPorts[port] {
			if err := manager.AllowPort(port); err != nil {
				logger.Warnf("⚠️ [PortPlugin] Failed to allow port %d: %v", port, err)
			} else {
				logger.Infof("➕ [PortPlugin] Allowed port %d", port)
			}
		}
	}

	// --- 2. Sync IP+Port Rules ---
	if err := p.syncIPPortRules(manager, false, logger); err != nil {
		logger.Warnf("⚠️ [PortPlugin] Failed to sync IPv4 rules: %v", err)
	}
	if err := p.syncIPPortRules(manager, true, logger); err != nil {
		logger.Warnf("⚠️ [PortPlugin] Failed to sync IPv6 rules: %v", err)
	}

	logger.Infof("✅ [PortPlugin] Sync complete. Active: %d global ports, %d IP+Port rules",
		len(p.config.AllowedPorts), len(p.config.IPPortRules))
	return nil
}

func (p *PortPlugin) syncIPPortRules(manager xdp.ManagerInterface, isIPv6 bool, logger sdk.Logger) error {
	// List existing rules
	currentRulesSlice, _, err := manager.ListIPPortRules(isIPv6, 0, "")
	if err != nil {
		return err
	}

	// Convert slice to map for diffing
	currentRulesMap := make(map[string]uint8)
	for _, r := range currentRulesSlice {
		// Canonical string
		// r.IP should already be in "IP/Prefix" format from Manager
		key := fmt.Sprintf("%s:%d", r.IP, r.Port)
		currentRulesMap[key] = r.Action
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
	for keyStr := range currentRulesMap {
		if _, ok := desiredRulesMap[keyStr]; !ok {
			// Parse key back to IPNet and Port to remove
			// key: "IP/Prefix:Port"
			// iputil.ParseIPPort expects "Host:Port", and "IP/Prefix" is a valid host string for SplitHostPort
			ipCIDR, port, err := iputil.ParseIPPort(keyStr)
			if err != nil {
				continue
			}

			if err := manager.RemoveIPPortRule(ipCIDR, port); err != nil {
				logger.Warnf("⚠️ [PortPlugin] Failed to remove rule %s: %v", keyStr, err)
			} else {
				logger.Infof("➖ [PortPlugin] Removed rule %s", keyStr)
			}
		}
	}

	// Add/Update rules from config
	for key, rule := range desiredRulesMap {
		currentAction, exists := currentRulesMap[key]
		desiredAction := uint8(1) // Allow
		if rule.Action == 2 {
			desiredAction = 2
		}

		if !exists || currentAction != desiredAction {
			if err := manager.AddIPPortRule(rule.IP, rule.Port, desiredAction); err != nil {
				logger.Warnf("⚠️ [PortPlugin] Failed to add rule %s: %v", key, err)
			} else {
				logger.Infof("➕ [PortPlugin] Added/Updated rule %s", key)
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
