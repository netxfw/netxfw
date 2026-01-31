package conntrack

import (
	"log"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

type ConntrackPlugin struct {
	config *types.ConntrackConfig
}

func (p *ConntrackPlugin) Name() string {
	return "conntrack"
}

func (p *ConntrackPlugin) Init(config *types.GlobalConfig) error {
	p.config = &config.Conntrack
	return nil
}

func (p *ConntrackPlugin) Start(manager *xdp.Manager) error {
	if p.config == nil || !p.config.Enabled {
		return nil
	}

	if err := manager.SetConntrack(true); err != nil {
		log.Printf("⚠️  [ConntrackPlugin] Failed to enable conntrack in BPF: %v", err)
		return err
	}

	// Set timeout if configured
	if p.config.TCPTimeout != "" {
		timeout, err := time.ParseDuration(p.config.TCPTimeout)
		if err == nil {
			if err := manager.SetConntrackTimeout(timeout); err != nil {
				log.Printf("⚠️  [ConntrackPlugin] Failed to set conntrack timeout: %v", err)
			} else {
				log.Printf("✅ [ConntrackPlugin] Conntrack timeout set to %v", timeout)
			}
		} else {
			log.Printf("⚠️  [ConntrackPlugin] Invalid TCPTimeout format: %s", p.config.TCPTimeout)
		}
	}

	log.Printf("✅ [ConntrackPlugin] Connection tracking (LRU-based) enabled")
	return nil
}

func (p *ConntrackPlugin) Stop() error {
	return nil
}

func (p *ConntrackPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}

func (p *ConntrackPlugin) DefaultConfig() interface{} {
	return types.ConntrackConfig{
		Enabled:    false,
		MaxEntries: 100000,
		TCPTimeout: "1h",
		UDPTimeout: "5m",
	}
}
