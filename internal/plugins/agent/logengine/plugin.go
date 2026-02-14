package logengine

import (
	"fmt"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
)

// LogEnginePlugin implements the Plugin interface.
type LogEnginePlugin struct {
	engine       *LogEngine
	config       types.LogEngineConfig
	lockListFile string
}

// Name returns the name of the plugin.
func (p *LogEnginePlugin) Name() string {
	return "log_engine"
}

// Init initializes the plugin with the global configuration.
func (p *LogEnginePlugin) Init(ctx *sdk.PluginContext) error {
	p.config = ctx.Config.LogEngine
	p.lockListFile = ctx.Config.Base.LockListFile
	return nil
}

// Reload updates the plugin configuration without restarting
func (p *LogEnginePlugin) Reload(ctx *sdk.PluginContext) error {
	ctx.Logger.Infof("🔄 [LogEngine] Reloading configuration...")
	newCfg := ctx.Config.LogEngine
	p.lockListFile = ctx.Config.Base.LockListFile

	if !newCfg.Enabled {
		if p.engine != nil {
			p.engine.Stop()
			p.engine = nil
		}
		return nil
	}

	if p.engine == nil {
		// Was disabled, now enabled
		p.Init(ctx)
		return p.Start(ctx)
	}

	// Was enabled, update config
	return p.engine.UpdateConfig(newCfg)
}

// Start starts the log engine.
func (p *LogEnginePlugin) Start(ctx *sdk.PluginContext) error {
	if !p.config.Enabled {
		return nil
	}

	ctx.Logger.Infof("Starting LogEngine plugin...")
	actionHandler := NewXDPActionHandler(ctx.Manager, p.lockListFile)
	p.engine = New(p.config, ctx.Logger, actionHandler)
	p.engine.Start()
	return nil
}

// Stop stops the log engine.
func (p *LogEnginePlugin) Stop() error {
	if p.engine != nil {
		p.engine.Stop()
	}
	return nil
}

// DefaultConfig returns the default configuration.
func (p *LogEnginePlugin) DefaultConfig() interface{} {
	return types.LogEngineConfig{
		Enabled: false,
		Workers: 4,
		Rules:   []types.LogEngineRule{},
	}
}

// Validate checks the configuration for errors.
func (p *LogEnginePlugin) Validate(config *types.GlobalConfig) error {
	if !config.LogEngine.Enabled {
		return nil
	}
	if len(config.LogEngine.Rules) == 0 {
		return fmt.Errorf("log_engine enabled but no rules specified")
	}
	return nil
}
