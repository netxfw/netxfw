package engine

import (
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
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
	m.logger.Infof("🚀 [Core] Starting Port Module...")
	return m.Sync()
}

func (m *PortModule) Reload(cfg *types.GlobalConfig) error {
	m.logger.Infof("🔄 [Core] Reloading Port Module...")
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

	// 1. Sync Allowed Ports
	currentPorts, err := m.manager.ListAllowedPorts()
	if err != nil {
		m.logger.Warnf("⚠️ [Port] Failed to list current allowed ports: %v", err)
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
				m.manager.RemoveAllowedPort(port)
			}
		}
		// Add
		for port := range desiredPorts {
			if !existingPorts[port] {
				m.manager.AllowPort(port)
			}
		}
	}

	// 2. Sync IP+Port Rules (Simplified logic for migration)
	m.manager.ClearIPPortRules()
	for _, rule := range m.config.IPPortRules {
		if err := m.manager.AddIPPortRule(rule.IP, rule.Port, rule.Action); err != nil {
			m.logger.Warnf("⚠️ [Port] Failed to add rule %s:%d: %v", rule.IP, rule.Port, err)
		}
	}

	return nil
}
