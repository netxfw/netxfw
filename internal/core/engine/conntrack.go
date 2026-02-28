package engine

import (
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type ConntrackModule struct {
	config  *types.ConntrackConfig
	manager sdk.ManagerInterface
	logger  sdk.Logger
}

func (m *ConntrackModule) Name() string {
	return "conntrack"
}

func (m *ConntrackModule) Init(cfg *types.GlobalConfig, s *sdk.SDK, logger sdk.Logger) error {
	m.config = &cfg.Conntrack
	m.manager = s.GetManager()
	m.logger = logger
	return nil
}

func (m *ConntrackModule) Start() error {
	m.logger.Infof("[START] [Core] Starting Conntrack Module...")
	return m.Sync()
}

func (m *ConntrackModule) Reload(cfg *types.GlobalConfig) error {
	m.logger.Infof("[RELOAD] [Core] Reloading Conntrack Module...")
	m.config = &cfg.Conntrack
	return m.Sync()
}

func (m *ConntrackModule) Stop() error {
	return nil
}

func (m *ConntrackModule) Sync() error {
	if m.config == nil {
		return nil
	}
	if err := m.manager.SetConntrack(m.config.Enabled); err != nil {
		m.logger.Warnf("[WARN]  [Conntrack] Failed to set conntrack state: %v", err)
		return err
	}
	if !m.config.Enabled {
		return nil
	}

	var tcpDuration time.Duration
	var err error
	if m.config.TCPTimeout != "" {
		tcpDuration, err = time.ParseDuration(m.config.TCPTimeout)
		if err != nil {
			tcpDuration = time.Hour
		}
	} else {
		tcpDuration = time.Hour
	}

	if err := m.manager.SetConntrackTimeout(tcpDuration); err != nil {
		m.logger.Warnf("[WARN]  [Conntrack] Failed to set timeout: %v", err)
	}
	return nil
}
