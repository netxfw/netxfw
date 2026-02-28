package web

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/netxfw/netxfw/internal/api"
	"github.com/netxfw/netxfw/internal/metrics"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type WebPlugin struct {
	config  *types.WebConfig
	server  *http.Server
	running bool
	mu      sync.RWMutex // Protects running field from concurrent access / 保护 running 字段免受并发访问
	api     *api.Server
}

// isRunning returns whether the plugin is running (thread-safe).
// isRunning 返回插件是否正在运行（线程安全）。
func (p *WebPlugin) isRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

// setRunning sets the running state (thread-safe).
// setRunning 设置运行状态（线程安全）。
func (p *WebPlugin) setRunning(running bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = running
}

func (p *WebPlugin) Name() string {
	return "web"
}

func (p *WebPlugin) Type() sdk.PluginType {
	return sdk.PluginTypeExtension
}

func (p *WebPlugin) DefaultConfig() any {
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
		ctx.Logger.Infof("[WEB] Web plugin is disabled via config.")
		return nil
	}

	// Create main mux
	mux := http.NewServeMux()

	// 1. Register Metrics Route based on configuration
	// If metrics server is disabled, serve metrics on the same server
	if !ctx.Config.Metrics.Enabled || !ctx.Config.Metrics.ServerEnabled {
		mux.Handle("/metrics", promhttp.Handler())
	}

	// 2. Get API handler (handles both API and UI routes)
	apiHandler := p.api.Handler()

	// 3. Register API routes (under /api/)
	mux.Handle("/api/", http.StripPrefix("/api", apiHandler))

	// 4. Register UI route (for root and other non-API/non-metrics paths)
	mux.Handle("/", apiHandler)

	p.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", p.config.Port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	p.setRunning(true)

	// Start HTTP Server
	go func() {
		ctx.Logger.Infof("[WEB] Web & Metrics server starting on :%d", p.config.Port)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ctx.Logger.Errorf("[ERROR] Web server error: %v", err)
			p.setRunning(false)
		}
	}()

	// Start Metrics Collection Loop
	go p.collectStats(ctx)

	return nil
}

func (p *WebPlugin) Stop() error {
	p.setRunning(false)
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}

func (p *WebPlugin) Reload(ctx *sdk.PluginContext) error {
	// Update configuration
	newConfig := ctx.Config.Web
	p.config = &newConfig

	// For web plugin, we might want to restart the server with new config
	// But for now, just update the config reference
	return nil
}

func (p *WebPlugin) collectStats(ctx *sdk.PluginContext) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for p.isRunning() {
		<-ticker.C
		if p.api != nil && p.api.Sdk() != nil {
			stats := p.api.Sdk().Stats
			if stats != nil {
				// Update locked IPs count
				locked, err := stats.GetLockedIPCount()
				if err == nil {
					metrics.WhitelistCount.Set(float64(locked))
				}

				// Update drop details
				drops, err := stats.GetDropDetails()
				if err == nil {
					for _, d := range drops {
						reasonStr := fmt.Sprintf("%d", d.Reason)
						metrics.XdpDropTotal.WithLabelValues(reasonStr).Set(float64(d.Count))
					}
				}

				// Update pass details
				passes, err := stats.GetPassDetails()
				if err == nil {
					for _, d := range passes {
						reasonStr := fmt.Sprintf("%d", d.Reason)
						metrics.XdpPassTotal.WithLabelValues(reasonStr).Set(float64(d.Count))
					}
				}
			}
		}
	}
}
