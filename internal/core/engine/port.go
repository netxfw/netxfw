package engine

import (
	"fmt"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type PortModule struct {
	config  *types.PortConfig
	manager sdk.ManagerInterface
	logger  sdk.Logger
}

func (m *PortModule) Name() string {
	return "port"
}

func (m *PortModule) Init(cfg *types.GlobalConfig, s *sdk.SDK, logger sdk.Logger) error {
	m.config = &cfg.Port
	m.manager = s.GetManager()
	m.logger = logger
	return nil
}

func (m *PortModule) Start() error {
	m.logger.Infof("[START] [Core] Starting Port Module...")
	return m.Sync()
}

func (m *PortModule) Reload(cfg *types.GlobalConfig) error {
	m.logger.Infof("[RELOAD] [Core] Reloading Port Module...")
	m.config = &cfg.Port
	return m.Sync()
}

func (m *PortModule) Stop() error {
	return nil
}

func (m *PortModule) Sync() error {
	if m.config == nil {
		return nil
	}

	// 1. Sync IP+Port Rules (Incremental update to avoid empty window)
	currentRules, _, err := m.manager.ListIPPortRules(false, 0, "")
	if err != nil {
		m.logger.Warnf("[WARN] [Port] Failed to list current IP+Port rules: %v", err)
	} else {
		// Build map of current rules for easy lookup
		// Key format: "IP:Port"
		currentRulesMap := make(map[string]sdk.IPPortRule)
		for _, rule := range currentRules {
			// ListIPPortRules returns normalized CIDR
			key := fmt.Sprintf("%s:%d", rule.IP, rule.Port)
			currentRulesMap[key] = rule
		}

		// Build map of desired rules
		desiredRulesMap := make(map[string]types.IPPortRule)
		for _, rule := range m.config.IPPortRules {
			// We need to normalize IP to match what ListIPPortRules returns
			// Assuming ListIPPortRules returns normalized CIDRs
			// But since we can't easily access iputil here without import, we might rely on exact match or careful normalization
			// However, let's try to match by key constructed same way
			key := fmt.Sprintf("%s:%d", rule.IP, rule.Port)
			desiredRulesMap[key] = rule
		}

		// Remove rules that are not in desired config
		for key, rule := range currentRulesMap {
			if _, desired := desiredRulesMap[key]; !desired {
				// Safety check: Do not delete "Allowed Ports" (Wildcard IP rules)
				// ListIPPortRules returns wildcard rules as "::/0" or "0.0.0.0/0"
				// We should preserve them if the port is in AllowedPorts config
				isWildcard := (rule.IP == "::/0" || rule.IP == "0.0.0.0/0")

				isAllowedPort := false
				if isWildcard {
					for _, p := range m.config.AllowedPorts {
						if p == rule.Port {
							isAllowedPort = true
							break
						}
					}
				}

				if isWildcard && isAllowedPort {
					// This is an Allowed Port rule, do not delete it here.
					// It will be handled in step 2 (Sync Allowed Ports).
					continue
				}

				if err := m.manager.RemoveIPPortRule(rule.IP, rule.Port); err != nil {
					m.logger.Warnf("[WARN] [Port] Failed to remove rule %s:%d: %v", rule.IP, rule.Port, err)
				}
			}
		}

		// Add or Update rules
		for key, rule := range desiredRulesMap {
			existing, exists := currentRulesMap[key]
			if !exists || existing.Action != rule.Action {
				if err := m.manager.AddIPPortRule(rule.IP, rule.Port, rule.Action); err != nil {
					m.logger.Warnf("[WARN] [Port] Failed to add/update rule %s:%d: %v", rule.IP, rule.Port, err)
				}
			}
		}
	}

	// 2. Sync Allowed Ports
	currentPorts, err := m.manager.ListAllowedPorts()
	if err != nil {
		m.logger.Warnf("[WARN] [Port] Failed to list current allowed ports: %v", err)
	} else {
		desiredPorts := make(map[uint16]bool)
		for _, port := range m.config.AllowedPorts {
			desiredPorts[port] = true
		}
		existingPorts := make(map[uint16]bool)
		for _, port := range currentPorts {
			existingPorts[port] = true
		}
		// Remove
		for port := range existingPorts {
			if !desiredPorts[port] {
				if err := m.manager.RemoveAllowedPort(port); err != nil {
					m.logger.Warnf("[WARN] [Port] Failed to remove port %d: %v", port, err)
				}
			}
		}
		// Add
		for port := range desiredPorts {
			if !existingPorts[port] {
				if err := m.manager.AllowPort(port); err != nil {
					m.logger.Warnf("[WARN] [Port] Failed to allow port %d: %v", port, err)
				}
			}
		}
	}

	return nil
}
