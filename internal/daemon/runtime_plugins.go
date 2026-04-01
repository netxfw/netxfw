package daemon

import (
	"context"

	"github.com/netxfw/netxfw/internal/plugins"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// BuildPluginContext constructs a plugin context with the provided runtime dependencies.
func BuildPluginContext(ctx context.Context, fw sdk.Firewall, manager sdk.ManagerInterface, cfg *sdk.GlobalConfig, log *zap.SugaredLogger, s *sdk.SDK, web sdk.WebHost) *sdk.PluginContext {
	return &sdk.PluginContext{
		Context:  ctx,
		Firewall: fw,
		Manager:  manager,
		Config:   cfg,
		Logger:   log,
		SDK:      s,
		Web:      web,
	}
}

// StartPlugins initializes and starts all registered plugins, returning the successfully started ones.
func StartPlugins(pluginCtx *sdk.PluginContext, log *zap.SugaredLogger) []sdk.Plugin {
	allPlugins := plugins.GetPlugins()
	started := make([]sdk.Plugin, 0, len(allPlugins))
	for _, p := range allPlugins {
		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("[WARN]  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(pluginCtx); err != nil {
			log.Warnf("[WARN]  Failed to start plugin %s: %v", p.Name(), err)
			continue
		}
		started = append(started, p)
	}
	return started
}

// ReloadPlugins preserves the current plugin reload semantics: Init followed by Reload.
func ReloadPlugins(pluginCtx *sdk.PluginContext, log *zap.SugaredLogger) {
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("[WARN]  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Reload(pluginCtx); err != nil {
			log.Warnf("[WARN]  Failed to reload plugin %s: %v", p.Name(), err)
		}
	}
}

// StartRuntimePlugins is a small convenience wrapper around context build + start.
func StartRuntimePlugins(ctx context.Context, fw sdk.Firewall, manager sdk.ManagerInterface, cfg *sdk.GlobalConfig, log *zap.SugaredLogger, s *sdk.SDK, web sdk.WebHost) (*sdk.PluginContext, []sdk.Plugin) {
	pluginCtx := BuildPluginContext(ctx, fw, manager, cfg, log, s, web)
	started := StartPlugins(pluginCtx, log)
	return pluginCtx, started
}

// StopPlugins stops all previously started plugins.
func StopPlugins(started []sdk.Plugin) {
	for _, p := range started {
		_ = p.Stop()
	}
}
