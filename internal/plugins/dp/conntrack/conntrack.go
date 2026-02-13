package conntrack

import (
	"log"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

type ConntrackPlugin struct {
	config *types.ConntrackConfig
}

func (p *ConntrackPlugin) Name() string {
	return "conntrack"
}

func (p *ConntrackPlugin) Init(ctx *sdk.PluginContext) error {
	p.config = &ctx.Config.Conntrack
	return nil
}

func (p *ConntrackPlugin) Reload(ctx *sdk.PluginContext) error {
	log.Println("🔄 [ConntrackPlugin] Reloading configuration (Full Sync)...")
	if err := p.Init(ctx); err != nil {
		return err
	}
	return p.Sync(ctx.Manager)
}

func (p *ConntrackPlugin) Start(ctx *sdk.PluginContext) error {
	log.Println("🚀 [ConntrackPlugin] Starting...")
	return p.Sync(ctx.Manager)
}

func (p *ConntrackPlugin) Stop() error {
	return nil
}

func (p *ConntrackPlugin) DefaultConfig() interface{} {
	return types.ConntrackConfig{
		Enabled:    true,
		MaxEntries: 100000,
		TCPTimeout: "1h",
		UDPTimeout: "5m",
	}
}

func (p *ConntrackPlugin) Sync(manager *xdp.Manager) error {
	if p.config == nil {
		return nil
	}

	// 1. Sync Enable/Disable
	// Even if disabled, we must explicitly call SetConntrack(false) to overwrite previous state
	if err := manager.SetConntrack(p.config.Enabled); err != nil {
		log.Printf("⚠️  [ConntrackPlugin] Failed to set conntrack state: %v", err)
		return err
	}

	if !p.config.Enabled {
		log.Println("ℹ️  [ConntrackPlugin] Connection tracking disabled")
		return nil
	}

	// 2. Set timeout if configured
	// TODO: Support separate TCP/UDP timeouts if BPF supports it
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

func (p *ConntrackPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
