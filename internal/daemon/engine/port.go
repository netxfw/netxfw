package engine

import (
	"fmt"

	"github.com/netxfw/netxfw/pkg/sdk"
)

type PortModule struct {
	config  *sdk.PortConfig
	manager sdk.ManagerInterface
	logger  sdk.Logger
}

func (m *PortModule) Name() string {
	return "port"
}

func (m *PortModule) Init(cfg *sdk.GlobalConfig, s *sdk.SDK, logger sdk.Logger) error {
	m.config = &cfg.Port
	m.manager = s.GetManager()
	m.logger = logger
	return nil
}

func (m *PortModule) Start() error {
	m.logger.Infof("[START] [Core] Starting Port Module...")
	return m.Sync()
}

func (m *PortModule) Reload(cfg *sdk.GlobalConfig) error {
	m.logger.Infof("[RELOAD] [Core] Reloading Port Module...")
	m.config = &cfg.Port
	return m.Sync()
}

func (m *PortModule) Stop() error {
	return nil
}

//nolint:gocyclo // sync logic intentionally handles full incremental reconciliation in one place.
func (m *PortModule) Sync() error {
	if m.config == nil {
		return nil
	}

	currentRules, _, err := m.manager.ListIPPortRules(false, 0, "")
	if err != nil {
		m.logger.Warnf("[WARN] [Port] Failed to list current IP+Port rules: %v", err)
	} else {
		currentRulesMap := make(map[string]sdk.IPPortRule)
		for _, rule := range currentRules {
			key := fmt.Sprintf("%s:%d", rule.IP, rule.Port)
			currentRulesMap[key] = rule
		}

		desiredRulesMap := make(map[string]sdk.IPPortRule)
		for _, rule := range m.config.IPPortRules {
			key := fmt.Sprintf("%s:%d", rule.IP, rule.Port)
			desiredRulesMap[key] = rule
		}

		for key, rule := range currentRulesMap {
			if _, desired := desiredRulesMap[key]; desired {
				continue
			}

			isWildcard := rule.IP == "::/0" || rule.IP == "0.0.0.0/0"

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
				continue
			}

			if removeErr := m.manager.RemoveIPPortRule(rule.IP, rule.Port); removeErr != nil {
				m.logger.Warnf("[WARN] [Port] Failed to remove rule %s:%d: %v", rule.IP, rule.Port, removeErr)
			}
		}

		for key, rule := range desiredRulesMap {
			existing, exists := currentRulesMap[key]
			if !exists || existing.Action != rule.Action {
				if addErr := m.manager.AddIPPortRule(rule.IP, rule.Port, rule.Action); addErr != nil {
					m.logger.Warnf("[WARN] [Port] Failed to add/update rule %s:%d: %v", rule.IP, rule.Port, addErr)
				}
			}
		}
	}

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
		for port := range existingPorts {
			if !desiredPorts[port] {
				if err := m.manager.RemoveAllowedPort(port); err != nil {
					m.logger.Warnf("[WARN] [Port] Failed to remove port %d: %v", port, err)
				}
			}
		}
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
