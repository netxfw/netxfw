package api

import (
	"net/http"
	"net/http/pprof"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// Server represents the API and UI server instance.
// Server 表示 API 和 UI 服务器实例。
type Server struct {
	sdk        *sdk.SDK
	port       int
	configPath string
}

// Sdk returns the SDK instance associated with this server.
// Sdk 返回与此服务器关联的 SDK 实例。
func (s *Server) Sdk() *sdk.SDK {
	return s.sdk
}

// Port returns the port number of the server.
// Port 返回服务器的端口号。
func (s *Server) Port() int {
	return s.port
}

// NewServer creates a new API and UI server instance.
// NewServer 创建一个新的 API 和 UI 服务器实例。
func NewServer(s *sdk.SDK, port int) *Server {
	return &Server{
		sdk:        s,
		port:       port,
		configPath: config.GetConfigPath(),
	}
}

// Handler returns the http.Handler for the API and UI.
// Handler 返回 API 和 UI 的 http.Handler。
func (s *Server) Handler() http.Handler {
	log := logger.Get(nil)
	// Auto-generate token if not configured
	// 如果未配置 Token，则自动生成
	types.ConfigMu.Lock()

	// Load config using the new config manager
	cfgManager := config.GetConfigManager()
	err := cfgManager.LoadConfig()
	if err != nil {
		log.Errorf("Failed to load config: %v", err)
		types.ConfigMu.Unlock()
		return nil
	}

	cfg := cfgManager.GetConfig()
	if cfg == nil {
		log.Error("Config is nil after loading")
		types.ConfigMu.Unlock()
		return nil
	}

	if cfg.Web.Token == "" {
		token := generateRandomToken(16)
		cfg.Web.Token = token
		cfg.Web.Enabled = true
		cfg.Web.Port = s.port

		// Update config in the manager
		cfgManager.UpdateConfig(cfg)

		// Save config using the new config manager
		if err := cfgManager.SaveConfig(); err != nil {
			log.Errorf("Failed to save config: %v", err)
			types.ConfigMu.Unlock()
			return nil
		}

		log.Infof("[KEY] No Web Token configured. Automatically generated a new one: %s", token)
		log.Infof("[LOG] Token has been saved to %s", s.configPath)
	} else {
		log.Infof("[KEY] Using configured Web Token for authentication")
	}

	types.ConfigMu.Unlock()

	mux := http.NewServeMux()

	// Health check endpoint
	// 健康检查端点
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/health/maps", s.handleHealthMaps)
	mux.HandleFunc("/health/map", s.handleHealthMap)

	// Version endpoint
	// 版本端点
	mux.HandleFunc("/version", s.handleVersion)

	// API Routes
	// API 路由
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/sync", s.handleSync)
	mux.HandleFunc("/api/conntrack", s.handleConntrack)

	// Performance monitoring API routes
	// 性能监控 API 路由
	mux.HandleFunc("/api/perf", s.handlePerfStats)
	mux.HandleFunc("/api/perf/latency", s.handlePerfLatency)
	mux.HandleFunc("/api/perf/cache", s.handlePerfCache)
	mux.HandleFunc("/api/perf/traffic", s.handlePerfTraffic)
	mux.HandleFunc("/api/perf/reset", s.handlePerfReset)

	// Metrics API routes (v1)
	// 指标 API 路由 (v1)
	RegisterMetricsRoutes(mux, s.sdk)

	// UI Route
	// UI 路由
	mux.HandleFunc("/", s.handleUI)

	// Pprof routes for debugging (only if enabled in config)
	// 调试用 Pprof 路由（仅在配置中启用时）
	if cfg.Base.EnablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	return mux
}
