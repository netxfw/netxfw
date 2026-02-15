package logengine

import (
	"fmt"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
)

// LogEnginePlugin implements the Plugin interface.
// LogEnginePlugin 实现了插件接口。
type LogEnginePlugin struct {
	engine       *LogEngine
	config       types.LogEngineConfig
	lockListFile string
}

// Name returns the name of the plugin.
// Name 返回插件的名称。
func (p *LogEnginePlugin) Name() string {
	return "log_engine"
}

// Init initializes the plugin with the global configuration.
// Init 使用全局配置初始化插件。
func (p *LogEnginePlugin) Init(ctx *sdk.PluginContext) error {
	p.config = ctx.Config.LogEngine
	p.lockListFile = ctx.Config.Base.LockListFile
	return nil
}

// Reload updates the plugin configuration without restarting
// Reload 在不重启的情况下更新插件配置。
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
// Start 启动日志引擎。
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
// Stop 停止日志引擎。
func (p *LogEnginePlugin) Stop() error {
	if p.engine != nil {
		p.engine.Stop()
	}
	return nil
}

// DefaultConfig returns the default configuration.
// DefaultConfig 返回默认配置。
func (p *LogEnginePlugin) DefaultConfig() interface{} {
	return types.LogEngineConfig{
		Enabled: false,
		Workers: 4,
		Rules:   []types.LogEngineRule{},
	}
}

// Validate checks the configuration for errors.
// Validate 检查配置是否存在错误。
func (p *LogEnginePlugin) Validate(config *types.GlobalConfig) error {
	if !config.LogEngine.Enabled {
		return nil
	}
	if len(config.LogEngine.Rules) == 0 {
		return fmt.Errorf("log_engine enabled but no rules specified")
	}
	return nil
}
