package web

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/livp123/netxfw/internal/api"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	xdpDropTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_xdp_drop_total",
			Help: "Total dropped packets by the XDP program",
		},
		[]string{"reason"},
	)
	xdpPassTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_xdp_pass_total",
			Help: "Total passed packets by the XDP program",
		},
		[]string{"reason"},
	)
	lockedIPsCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "netxfw_locked_ips_count",
			Help: "Current number of locked IP addresses",
		},
	)
)

type WebPlugin struct {
	config  *types.WebConfig
	server  *http.Server
	running bool
	api     *api.Server
}

func (p *WebPlugin) Name() string {
	return "web"
}

func (p *WebPlugin) Type() sdk.PluginType {
	return sdk.PluginTypeExtension
}

func (p *WebPlugin) DefaultConfig() interface{} {
	return types.WebConfig{
		Enabled: true,
		Port:    11811,
	}
}

func (p *WebPlugin) Validate(cfg *types.GlobalConfig) error {
	if cfg.Web.Enabled {
		if cfg.Web.Port <= 0 || cfg.Web.Port > 65535 {
			return fmt.Errorf("invalid web port: %d", cfg.Web.Port)
		}
	}
	return nil
}

func (p *WebPlugin) Init(ctx *sdk.PluginContext) error {
	p.config = &ctx.Config.Web
	p.api = api.NewServer(ctx.SDK, p.config.Port)
	return nil
}

func (p *WebPlugin) Start(ctx *sdk.PluginContext) error {
	if !p.config.Enabled {
		ctx.Logger.Infof("🌐 Web plugin is disabled via config.")
		return nil
	}

	// Create main mux
	mux := http.NewServeMux()

	// 1. Register API Routes
	apiHandler := p.api.Handler()
	mux.Handle("/", apiHandler)

	// 2. Register Metrics Route
	mux.Handle("/metrics", promhttp.Handler())

	p.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.config.Port),
		Handler: mux,
	}

	p.running = true

	// Start HTTP Server
	go func() {
		ctx.Logger.Infof("🌐 Web & Metrics server starting on :%d", p.config.Port)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ctx.Logger.Errorf("❌ Web server error: %v", err)
			p.running = false
		}
	}()

	// Start Metrics Collection Loop
	go p.collectStats(ctx)

	return nil
}

func (p *WebPlugin) Stop() error {
	p.running = false
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}

func (p *WebPlugin) Reload(ctx *sdk.PluginContext) error {
	p.Stop()
	p.Init(ctx)
	return p.Start(ctx)
}

func (p *WebPlugin) collectStats(ctx *sdk.PluginContext) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for p.running {
		select {
		case <-ticker.C:
			if ctx.SDK.Stats != nil {
				// Update Prometheus metrics
				_, _, err := ctx.SDK.Stats.GetCounters()
				if err == nil {
					// Counters are updated internally by prometheus via GetDropDetails/GetPassDetails
				}

				locked, err := ctx.SDK.Stats.GetLockedIPCount()
				if err == nil {
					lockedIPsCount.Set(float64(locked))
				}

				drops, err := ctx.SDK.Stats.GetDropDetails()
				if err == nil {
					for _, d := range drops {
						reasonStr := fmt.Sprintf("%d", d.Reason)
						xdpDropTotal.WithLabelValues(reasonStr).Set(float64(d.Count))
					}
				}

				passes, err := ctx.SDK.Stats.GetPassDetails()
				if err == nil {
					for _, d := range passes {
						reasonStr := fmt.Sprintf("%d", d.Reason)
						xdpPassTotal.WithLabelValues(reasonStr).Set(float64(d.Count))
					}
				}
			}
		}
	}
}
