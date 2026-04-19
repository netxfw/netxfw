package daemon

import (
	"context"

	runtimehost "github.com/netxfw/netxfw/internal/adapters/plugins/runtime"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// BuildPluginContext constructs a runtime plugin context with the provided runtime dependencies.
func BuildPluginContext(ctx context.Context, fw sdk.Firewall, manager sdk.ManagerInterface, cfg *sdk.GlobalConfig, log *zap.SugaredLogger, s *sdk.SDK, web sdk.WebHost) *sdk.RuntimePluginContext {
	if manager == nil && s != nil {
		manager = s.GetManager()
	}
	host := runtimehost.NewHost(nil)
	return host.BuildContext(ctx, fw, manager, cfg, log, s, web)
}

// StartPlugins initializes and starts all registered plugins, returning the successfully started ones.
func StartPlugins(pluginCtx *sdk.RuntimePluginContext, log *zap.SugaredLogger) []sdk.RuntimePlugin {
	host := runtimehost.NewHost(nil)
	return host.Start(pluginCtx, log)
}

// ReloadPlugins preserves the current plugin reload semantics: Init followed by Reload.
func ReloadPlugins(pluginCtx *sdk.RuntimePluginContext, log *zap.SugaredLogger) {
	host := runtimehost.NewHost(nil)
	host.Reload(pluginCtx, log)
}

// StartRuntimePlugins is a small convenience wrapper around context build + start.
func StartRuntimePlugins(ctx context.Context, fw sdk.Firewall, manager sdk.ManagerInterface, cfg *sdk.GlobalConfig, log *zap.SugaredLogger, s *sdk.SDK, web sdk.WebHost) (*sdk.RuntimePluginContext, []sdk.RuntimePlugin) {
	pluginCtx := BuildPluginContext(ctx, fw, manager, cfg, log, s, web)
	started := StartPlugins(pluginCtx, log)
	return pluginCtx, started
}

// StopPlugins stops all previously started plugins.
func StopPlugins(started []sdk.RuntimePlugin) {
	host := runtimehost.NewHost(nil)
	host.Stop(started)
}
