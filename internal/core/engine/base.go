package engine

import (
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
)

type BaseModule struct {
	config  *types.BaseConfig
	manager sdk.ManagerInterface
	logger  sdk.Logger
}

func (m *BaseModule) Name() string {
	return "base"
}

func (m *BaseModule) Init(cfg *types.GlobalConfig, s *sdk.SDK, logger sdk.Logger) error {
	m.config = &cfg.Base
	m.manager = s.GetManager()
	m.logger = logger
	return nil
}

func (m *BaseModule) Start() error {
	m.logger.Infof("🚀 [Core] Starting Base Module...")
	return m.Sync()
}

func (m *BaseModule) Reload(cfg *types.GlobalConfig) error {
	m.logger.Infof("🔄 [Core] Reloading Base Module...")
	m.config = &cfg.Base
	return m.Sync()
}

func (m *BaseModule) Stop() error {
	return nil
}

func (m *BaseModule) Sync() error {
	if m.config == nil {
		return nil
	}
	// Sync all base configurations to BPF
	if err := m.manager.SetDefaultDeny(m.config.DefaultDeny); err != nil {
		m.logger.Warnf("⚠️  [Base] Failed to set default deny: %v", err)
	}
	if err := m.manager.SetAllowReturnTraffic(m.config.AllowReturnTraffic); err != nil {
		m.logger.Warnf("⚠️  [Base] Failed to set allow return traffic: %v", err)
	}
	if err := m.manager.SetAllowICMP(m.config.AllowICMP); err != nil {
		m.logger.Warnf("⚠️  [Base] Failed to set allow ICMP: %v", err)
	}
	if err := m.manager.SetEnableAFXDP(m.config.EnableAFXDP); err != nil {
		m.logger.Warnf("⚠️  [Base] Failed to set enable AF_XDP: %v", err)
	}
	if err := m.manager.SetStrictProtocol(m.config.StrictProtocol); err != nil {
		m.logger.Warnf("⚠️  [Base] Failed to set strict protocol: %v", err)
	}
	if err := m.manager.SetDropFragments(m.config.DropFragments); err != nil {
		m.logger.Warnf("⚠️  [Base] Failed to set drop fragments: %v", err)
	}
	if err := m.manager.SetStrictTCP(m.config.StrictTCP); err != nil {
		m.logger.Warnf("⚠️  [Base] Failed to set strict TCP: %v", err)
	}
	if err := m.manager.SetSYNLimit(m.config.SYNLimit); err != nil {
		m.logger.Warnf("⚠️  [Base] Failed to set SYN limit: %v", err)
	}
	if m.config.ICMPRate > 0 && m.config.ICMPBurst > 0 {
		if err := m.manager.SetICMPRateLimit(m.config.ICMPRate, m.config.ICMPBurst); err != nil {
			m.logger.Warnf("⚠️  [Base] Failed to set ICMP rate limit: %v", err)
		}
	}
	return nil
}
