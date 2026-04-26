// Package web provides web functionality.
package web

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/netxfw/netxfw/internal/metrics/exporter"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type WebPlugin struct {
	config    *sdk.WebConfig
	server    *http.Server
	running   bool
	mu        sync.RWMutex // Protects running field from concurrent access / 保护 running 字段免受并发访问
	web       sdk.WebHost
	collector *exporter.Collector
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
	return sdk.WebConfig{
		Enabled: true,
		Port:    11811,
	}
}

func (p *WebPlugin) Validate(cfg *sdk.GlobalConfig) error {
	if cfg.Web.Enabled {
		if cfg.Web.Port <= 0 || cfg.Web.Port > 65535 {
			return fmt.Errorf("invalid web port: %d", cfg.Web.Port)
		}
	}
	return nil
}

func (p *WebPlugin) Init(ctx *sdk.RuntimePluginContext) error {
	p.config = &ctx.Config.Web
	p.web = ctx.Web
	p.collector = exporter.NewCollector(ctx.SDK)
	if p.web == nil {
		return fmt.Errorf("web host not available")
	}
	return p.web.EnsureHandlerInitialized()
}

func (p *WebPlugin) Start(ctx *sdk.RuntimePluginContext) error {
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
	} else {
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}

	// 2. Get handlers from injected web host
	apiHandler := p.web.APIHandler()
	uiHandler := p.web.UIHandler()

	// 3. Register API routes and operational endpoints
	mux.Handle("/api/", apiHandler)
	mux.Handle("/healthz", apiHandler)
	mux.Handle("/health", apiHandler)
	mux.Handle("/health/maps", apiHandler)
	mux.Handle("/health/map", apiHandler)
	mux.Handle("/version", apiHandler)
	mux.Handle("/debug/pprof/", apiHandler)
	mux.Handle("/debug/pprof/cmdline", apiHandler)
	mux.Handle("/debug/pprof/profile", apiHandler)
	mux.Handle("/debug/pprof/symbol", apiHandler)
	mux.Handle("/debug/pprof/trace", apiHandler)

	// 4. Register UI route
	mux.Handle("/", uiHandler)

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

func (p *WebPlugin) Reload(ctx *sdk.RuntimePluginContext) error {
	// Update configuration
	newConfig := ctx.Config.Web
	p.config = &newConfig

	// For web plugin, we might want to restart the server with new config
	// But for now, just update the config reference
	return nil
}

func (p *WebPlugin) collectStats(ctx *sdk.RuntimePluginContext) {
	if p.collector == nil {
		var pluginSDK *sdk.SDK
		if ctx != nil {
			pluginSDK = ctx.SDK
		}
		p.collector = exporter.NewCollector(pluginSDK)
	}

	var runCtx context.Context
	if ctx != nil {
		runCtx = ctx.Context
	}

	p.collector.Run(runCtx, p.isRunning)
}
