package runtime

import (
	"context"

	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// ValidationFailure captures a single runtime plugin validation failure.
type ValidationFailure struct {
	Name string
	Err  error
}

// Host orchestrates runtime plugin lifecycle through a registry.
type Host interface {
	BuildContext(ctx context.Context, fw sdk.Firewall, manager sdk.ManagerInterface, cfg *sdk.GlobalConfig, log *zap.SugaredLogger, s *sdk.SDK, web sdk.WebHost) *sdk.RuntimePluginContext
	Start(pluginCtx *sdk.RuntimePluginContext, log *zap.SugaredLogger) []sdk.RuntimePlugin
	Reload(pluginCtx *sdk.RuntimePluginContext, log *zap.SugaredLogger)
	Stop(started []sdk.RuntimePlugin)
	ValidateConfig(cfg *sdk.GlobalConfig) []ValidationFailure
	Inventory() []domainruntime.Descriptor
	Statuses(cfg *sdk.GlobalConfig) []domainruntime.Status
}

type runtimeHost struct {
	registry Registry
}

// NewHost returns the default runtime plugin host adapter.
func NewHost(registry Registry) Host {
	if registry == nil {
		registry = NewRegistry()
	}
	return runtimeHost{registry: registry}
}

func (h runtimeHost) BuildContext(ctx context.Context, fw sdk.Firewall, manager sdk.ManagerInterface, cfg *sdk.GlobalConfig, log *zap.SugaredLogger, s *sdk.SDK, web sdk.WebHost) *sdk.RuntimePluginContext {
	return &sdk.RuntimePluginContext{
		Context:  ctx,
		Firewall: fw,
		Manager:  manager,
		Config:   cfg,
		Logger:   log,
		SDK:      s,
		Web:      web,
	}
}

func (h runtimeHost) Start(pluginCtx *sdk.RuntimePluginContext, log *zap.SugaredLogger) []sdk.RuntimePlugin {
	allPlugins := h.registry.Plugins()
	started := make([]sdk.RuntimePlugin, 0, len(allPlugins))
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

func (h runtimeHost) Reload(pluginCtx *sdk.RuntimePluginContext, log *zap.SugaredLogger) {
	for _, p := range h.registry.Plugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("[WARN]  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Reload(pluginCtx); err != nil {
			log.Warnf("[WARN]  Failed to reload plugin %s: %v", p.Name(), err)
		}
	}
}

func (h runtimeHost) Stop(started []sdk.RuntimePlugin) {
	for _, p := range started {
		_ = p.Stop()
	}
}

func (h runtimeHost) ValidateConfig(cfg *sdk.GlobalConfig) []ValidationFailure {
	failures := make([]ValidationFailure, 0)
	for _, p := range h.registry.Plugins() {
		if err := p.Validate(cfg); err != nil {
			failures = append(failures, ValidationFailure{
				Name: p.Name(),
				Err:  err,
			})
		}
	}
	return failures
}

func (h runtimeHost) Inventory() []domainruntime.Descriptor {
	return h.registry.Inventory()
}

func (h runtimeHost) Statuses(cfg *sdk.GlobalConfig) []domainruntime.Status {
	items := h.registry.Plugins()
	statuses := make([]domainruntime.Status, 0, len(items))
	for _, p := range items {
		status := domainruntime.Status{
			Name: p.Name(),
			Kind: kindFromSDK(p.Type()),
		}

		if cfg == nil {
			status.Message = "config unavailable"
			statuses = append(statuses, status)
			continue
		}

		status.Enabled = runtimePluginEnabled(cfg, p.Name())
		if !status.Enabled {
			status.Healthy = true
			status.Message = "disabled by config"
			statuses = append(statuses, status)
			continue
		}

		if err := p.Validate(cfg); err != nil {
			status.Message = err.Error()
			statuses = append(statuses, status)
			continue
		}

		status.Running = true
		status.Healthy = true
		status.Message = "enabled by config"
		statuses = append(statuses, status)
	}
	return statuses
}

func runtimePluginEnabled(cfg *sdk.GlobalConfig, name string) bool {
	switch name {
	case "log_engine":
		return cfg.LogEngine.Enabled
	case "metrics":
		return cfg.Metrics.Enabled && cfg.Metrics.ServerEnabled
	case "web":
		return cfg.Web.Enabled
	default:
		return true
	}
}
