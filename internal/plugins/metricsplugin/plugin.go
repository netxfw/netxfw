// Package metrics provides metrics functionality.
package metrics

import (
	"fmt"

	"github.com/netxfw/netxfw/internal/metrics/exporter"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

type MetricsPlugin struct {
	config  *sdk.MetricsConfig
	server  *exporter.Server
	running bool
}

func (p *MetricsPlugin) Name() string {
	return "metrics"
}

func (p *MetricsPlugin) Type() sdk.PluginType {
	return sdk.PluginTypeExtension
}

func (p *MetricsPlugin) DefaultConfig() any {
	return sdk.MetricsConfig{
		Enabled:       true,
		ServerEnabled: true,
		Port:          11812,
	}
}

func (p *MetricsPlugin) Validate(cfg *sdk.GlobalConfig) error {
	if cfg.Metrics.Enabled && cfg.Metrics.ServerEnabled {
		if cfg.Metrics.Port <= 0 || cfg.Metrics.Port > 65535 {
			return fmt.Errorf("invalid metrics port: %d", cfg.Metrics.Port)
		}
	}
	return nil
}

func (p *MetricsPlugin) Init(ctx *sdk.RuntimePluginContext) error {
	p.config = &ctx.Config.Metrics
	p.server = exporter.NewServer(ctx.SDK, p.config)
	return nil
}

func (p *MetricsPlugin) Start(ctx *sdk.RuntimePluginContext) error {
	if !p.config.Enabled || !p.config.ServerEnabled {
		ctx.Logger.Infof("[STATS] Metrics server is disabled via config.")
		return nil
	}

	if err := p.server.Start(ctx.Context); err != nil {
		return fmt.Errorf("failed to start metrics server: %v", err)
	}

	p.running = true
	ctx.Logger.Infof("[STATS] Metrics server started successfully on :%d", p.config.Port)
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

func (p *MetricsPlugin) Reload(ctx *sdk.RuntimePluginContext) error {
	if err := p.Stop(); err != nil {
		return err
	}
	if err := p.Init(ctx); err != nil {
		return err
	}
	return p.Start(ctx)
}
