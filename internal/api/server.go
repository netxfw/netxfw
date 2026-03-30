package api

import (
	"net/http"
	"net/http/pprof"
	"sync"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// Server represents the API and UI server instance.
// Server 表示 API 和 UI 服务器实例。
type Server struct {
	sdk  *sdk.SDK
	port int

	// EnsureHandlerInitialized makes Handler() side-effect free for callers.
	// It lazily ensures config-dependent defaults (e.g., Web token) are in place.
	initOnce sync.Once
	initErr  error
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
		sdk:  s,
		port: port,
	}
}

func (s *Server) EnsureHandlerInitialized() error {
	s.initOnce.Do(func() {
		log := logger.Get(nil)
		s.initErr = config.MutateLoadedConfig(func(cfg *sdk.GlobalConfig) error {
			if cfg.Web.Token != "" {
				log.Infof("[KEY] Using configured Web Token for authentication")
				return nil
			}

			token := generateRandomToken(16)
			cfg.Web.Token = token
			cfg.Web.Enabled = true
			cfg.Web.Port = s.port

			log.Infof("[KEY] No Web Token configured. Automatically generated and saved a new token")
			log.Infof("[LOG] Token has been saved to %s", config.GetConfigPath())
			return nil
		})
	})

	return s.initErr
}

// Handler returns the http.Handler for the API and UI.
// Handler 返回 API 和 UI 的 http.Handler。
func (s *Server) Handler() http.Handler {
	log := logger.Get(nil)
	if err := s.EnsureHandlerInitialized(); err != nil {
		log.Errorf("Failed to initialize API handler: %v", err)
		return nil
	}

	cfg := config.GetCurrentConfig()
	if cfg == nil {
		log.Error("Config is nil after initialization")
		return nil
	}

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
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.Handle("/api/stats", s.withAuth(http.HandlerFunc(s.handleStats)))
	mux.Handle("/api/rules", s.withAuth(http.HandlerFunc(s.handleRules)))
	mux.Handle("/api/config", s.withAuth(http.HandlerFunc(s.handleConfig)))
	mux.Handle("/api/sync", s.withAuth(http.HandlerFunc(s.handleSync)))
	mux.Handle("/api/conntrack", s.withAuth(http.HandlerFunc(s.handleConntrack)))

	// Performance monitoring API routes
	// 性能监控 API 路由
	mux.Handle("/api/perf", s.withAuth(http.HandlerFunc(s.handlePerfStats)))
	mux.Handle("/api/perf/latency", s.withAuth(http.HandlerFunc(s.handlePerfLatency)))
	mux.Handle("/api/perf/cache", s.withAuth(http.HandlerFunc(s.handlePerfCache)))
	mux.Handle("/api/perf/traffic", s.withAuth(http.HandlerFunc(s.handlePerfTraffic)))
	mux.Handle("/api/perf/reset", s.withAuth(http.HandlerFunc(s.handlePerfReset)))

	// Metrics API routes (v1)
	// 指标 API 路由 (v1)
	RegisterMetricsRoutes(mux, s.sdk, s.withAuth)

	// UI Route
	// UI 路由
	mux.HandleFunc("/", s.handleUI)

	// Pprof routes for debugging (only if enabled in config)
	// 调试用 Pprof 路由（仅在配置中启用时）
	if cfg.Base.EnablePprof {
		mux.Handle("/debug/pprof/", s.withAuth(http.HandlerFunc(pprof.Index)))
		mux.Handle("/debug/pprof/cmdline", s.withAuth(http.HandlerFunc(pprof.Cmdline)))
		mux.Handle("/debug/pprof/profile", s.withAuth(http.HandlerFunc(pprof.Profile)))
		mux.Handle("/debug/pprof/symbol", s.withAuth(http.HandlerFunc(pprof.Symbol)))
		mux.Handle("/debug/pprof/trace", s.withAuth(http.HandlerFunc(pprof.Trace)))
	}

	return mux
}
