package metrics

import (
	"fmt"

	"github.com/livp123/netxfw/internal/api"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
)

type MetricsPlugin struct {
	config  *types.MetricsConfig
	server  *api.MetricsServer
	running bool
}

func (p *MetricsPlugin) Name() string {
	return "metrics"
}

func (p *MetricsPlugin) Type() sdk.PluginType {
	return sdk.PluginTypeExtension
}

func (p *MetricsPlugin) DefaultConfig() interface{} {
	return types.MetricsConfig{
		Enabled:       true,
		ServerEnabled: true,
		Port:          11812,
	}
}

func (p *MetricsPlugin) Validate(cfg *types.GlobalConfig) error {
	if cfg.Metrics.Enabled && cfg.Metrics.ServerEnabled {
		if cfg.Metrics.Port <= 0 || cfg.Metrics.Port > 65535 {
			return fmt.Errorf("invalid metrics port: %d", cfg.Metrics.Port)
		}
	}
	return nil
}

func (p *MetricsPlugin) Init(ctx *sdk.PluginContext) error {
	p.config = &ctx.Config.Metrics
	p.server = api.NewMetricsServer(ctx.SDK, p.config)
	return nil
}

func (p *MetricsPlugin) Start(ctx *sdk.PluginContext) error {
	if !p.config.Enabled || !p.config.ServerEnabled {
		ctx.Logger.Infof("📊 Metrics server is disabled via config.")
		return nil
	}

	if err := p.server.Start(ctx.Context); err != nil {
		return fmt.Errorf("failed to start metrics server: %v", err)
	}

	p.running = true
	ctx.Logger.Infof("📊 Metrics server started successfully on :%d", p.config.Port)
	return nil
}

func (p *MetricsPlugin) Stop() error {
	if !p.config.Enabled || !p.config.ServerEnabled {
		// If metrics server is disabled, no server to stop
		return nil
	}

	p.running = false
	if p.server != nil {
		return p.server.Stop()
	}
	return nil
}

func (p *MetricsPlugin) Reload(ctx *sdk.PluginContext) error {
	if err := p.Stop(); err != nil {
		return err
	}
	if err := p.Init(ctx); err != nil {
		return err
	}
	return p.Start(ctx)
}
