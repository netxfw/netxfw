package conntrack

import (
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

// Init initializes the plugin with configuration.
// Init 使用配置初始化插件。
func (p *ConntrackPlugin) Init(ctx *sdk.PluginContext) error {
	p.config = &ctx.Config.Conntrack
	return nil
}

// Reload reloads the plugin configuration.
// Reload 重新加载插件配置。
func (p *ConntrackPlugin) Reload(ctx *sdk.PluginContext) error {
	ctx.Logger.Infof("🔄 [ConntrackPlugin] Reloading configuration (Full Sync)...")
	if err := p.Init(ctx); err != nil {
		return err
	}
	return p.Sync(ctx.Manager, ctx.Logger)
}

// Start starts the plugin.
// Start 启动插件。
func (p *ConntrackPlugin) Start(ctx *sdk.PluginContext) error {
	ctx.Logger.Infof("🚀 [ConntrackPlugin] Starting...")
	return p.Sync(ctx.Manager, ctx.Logger)
}

// Stop stops the plugin.
// Stop 停止插件。
func (p *ConntrackPlugin) Stop() error {
	return nil
}

// DefaultConfig returns the default configuration for the plugin.
// DefaultConfig 返回插件的默认配置。
func (p *ConntrackPlugin) DefaultConfig() interface{} {
	return types.ConntrackConfig{
		Enabled:    true,
		MaxEntries: 100000,
		TCPTimeout: "1h",
		UDPTimeout: "5m",
	}
}

// Sync synchronizes the configuration to BPF maps.
// Sync 将配置同步到 BPF Map。
func (p *ConntrackPlugin) Sync(manager xdp.ManagerInterface, logger sdk.Logger) error {
	if p.config == nil {
		return nil
	}

	// 1. Sync Enable/Disable
	// Even if disabled, we must explicitly call SetConntrack(false) to overwrite previous state
	if err := manager.SetConntrack(p.config.Enabled); err != nil {
		logger.Warnf("⚠️  [ConntrackPlugin] Failed to set conntrack state: %v", err)
		return err
	}

	if !p.config.Enabled {
		logger.Infof("ℹ️  [ConntrackPlugin] Connection tracking disabled")
		return nil
	}

	// 2. Set timeout if configured
	var tcpDuration time.Duration
	var err error

	if p.config.TCPTimeout != "" {
		tcpDuration, err = time.ParseDuration(p.config.TCPTimeout)
		if err != nil {
			logger.Warnf("⚠️  [ConntrackPlugin] Invalid TCPTimeout format: %s", p.config.TCPTimeout)
			tcpDuration = time.Hour // Default
		}
	} else {
		tcpDuration = time.Hour
	}

	if p.config.UDPTimeout != "" {
		_, err := time.ParseDuration(p.config.UDPTimeout)
		if err != nil {
			logger.Warnf("⚠️  [ConntrackPlugin] Invalid UDPTimeout format: %s", p.config.UDPTimeout)
		}
	}

	if err := manager.SetConntrackTimeout(tcpDuration); err != nil {
		logger.Warnf("⚠️  [ConntrackPlugin] Failed to set conntrack timeout: %v", err)
	} else {
		logger.Infof("✅ [ConntrackPlugin] Conntrack timeout set to %v (Global)", tcpDuration)
	}

	logger.Infof("✅ [ConntrackPlugin] Connection tracking (LRU-based) enabled")
	return nil
}

func (p *ConntrackPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
