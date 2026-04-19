package engine

import "github.com/netxfw/netxfw/pkg/sdk"

type BaseModule struct {
	config   *sdk.BaseConfig
	security sdk.SecurityAPI
	logger   sdk.Logger
}

func (m *BaseModule) Name() string {
	return "base"
}

func (m *BaseModule) Init(cfg *sdk.GlobalConfig, s *sdk.SDK, logger sdk.Logger) error {
	m.config = &cfg.Base
	m.security = s.Security
	m.logger = logger
	return nil
}

func (m *BaseModule) Start() error {
	m.logger.Infof("[START] [Core] Starting Base Module...")
	return m.Sync()
}

func (m *BaseModule) Reload(cfg *sdk.GlobalConfig) error {
	m.logger.Infof("[RELOAD] [Core] Reloading Base Module...")
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
	if err := m.security.SetDefaultDeny(m.config.DefaultDeny); err != nil {
		m.logger.Warnf("[WARN]  [Base] Failed to set default deny: %v", err)
	}
	if err := m.security.SetAllowReturnTraffic(m.config.AllowReturnTraffic); err != nil {
		m.logger.Warnf("[WARN]  [Base] Failed to set allow return traffic: %v", err)
	}
	if err := m.security.SetAllowICMP(m.config.AllowICMP); err != nil {
		m.logger.Warnf("[WARN]  [Base] Failed to set allow ICMP: %v", err)
	}
	if err := m.security.SetEnableAFXDP(m.config.EnableAFXDP); err != nil {
		m.logger.Warnf("[WARN]  [Base] Failed to set enable AF_XDP: %v", err)
	}
	if err := m.security.SetStrictProtocol(m.config.StrictProtocol); err != nil {
		m.logger.Warnf("[WARN]  [Base] Failed to set strict protocol: %v", err)
	}
	if err := m.security.SetDropFragments(m.config.DropFragments); err != nil {
		m.logger.Warnf("[WARN]  [Base] Failed to set drop fragments: %v", err)
	}
	if err := m.security.SetStrictTCP(m.config.StrictTCP); err != nil {
		m.logger.Warnf("[WARN]  [Base] Failed to set strict TCP: %v", err)
	}
	if err := m.security.SetSYNLimit(m.config.SYNLimit); err != nil {
		m.logger.Warnf("[WARN]  [Base] Failed to set SYN limit: %v", err)
	}
	if m.config.ICMPRate > 0 && m.config.ICMPBurst > 0 {
		if err := m.security.SetICMPRateLimit(m.config.ICMPRate, m.config.ICMPBurst); err != nil {
			m.logger.Warnf("[WARN]  [Base] Failed to set ICMP rate limit: %v", err)
		}
	}
	return nil
}
