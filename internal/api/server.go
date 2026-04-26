package api

import (
	"net/http"
	"net/http/pprof"
	"sync"

	appconfig "github.com/netxfw/netxfw/internal/app/config"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	"github.com/netxfw/netxfw/internal/utils/logger"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
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

	configMu       sync.RWMutex
	configSnapshot *domainconfig.Config
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
		cfg, err := s.prepareConfigSnapshot()
		if err != nil {
			logger.Get(nil).Warnf("Config initialization skipped (this is normal in test environments): %v", err)
			s.initErr = nil
			return
		}

		cfg, err = s.ensureWebConfig(cfg)
		if err != nil {
			logger.Get(nil).Warnf("Config initialization skipped (this is normal in test environments): %v", err)
			s.initErr = nil
			return
		}

		s.setConfigSnapshot(cfg)
	})

	return s.initErr
}

func (s *Server) prepareConfigSnapshot() (*domainconfig.Config, error) {
	cfg, err := appconfig.LoadConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return cfg, nil
}

func (s *Server) ensureWebConfig(cfg *domainconfig.Config) (*domainconfig.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.Web.Token != "" {
		logger.Get(nil).Infof("[KEY] Using configured Web Token for authentication")
		return cfg, nil
	}

	log := logger.Get(nil)
	token := generateRandomToken(16)

	if err := appconfig.MutateLoadedConfig(func(liveCfg *domainconfig.Config) error {
		liveCfg.Web.Token = token
		liveCfg.Web.Enabled = true
		liveCfg.Web.Port = s.port
		return nil
	}); err != nil {
		return nil, err
	}

	cfg.Web.Token = token
	cfg.Web.Enabled = true
	cfg.Web.Port = s.port

	log.Infof("[KEY] No Web Token configured. Automatically generated and saved a new token")
	log.Infof("[LOG] Token has been saved to %s", appconfig.GetConfigPath())
	return cfg, nil
}

func (s *Server) setConfigSnapshot(cfg *domainconfig.Config) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.configSnapshot = cfg
}

func (s *Server) getConfigSnapshot() *domainconfig.Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.configSnapshot
}

// APIHandler returns the http.Handler for API and operational endpoints.
func (s *Server) APIHandler() http.Handler {
	log := logger.Get(nil)
	if err := s.EnsureHandlerInitialized(); err != nil {
		log.Errorf("Failed to initialize API handler: %v", err)
		return http.NotFoundHandler()
	}

	cfg := s.getConfigSnapshot()
	if cfg == nil {
		log.Error("Config snapshot is nil after initialization")
		return http.NotFoundHandler()
	}

	return s.buildAPIHandler(cfg)
}

func (s *Server) buildAPIHandler(cfg *domainconfig.Config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/health/maps", s.handleHealthMaps)
	mux.HandleFunc("/health/map", s.handleHealthMap)
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.Handle("/api/stats", s.withAuth(http.HandlerFunc(s.handleStats)))
	mux.Handle("/api/rules", s.withAuth(http.HandlerFunc(s.handleRules)))
	mux.Handle("/api/config", s.withAuth(http.HandlerFunc(s.handleConfig)))
	mux.Handle("/api/sync", s.withAuth(http.HandlerFunc(s.handleSync)))
	mux.Handle("/api/conntrack", s.withAuth(http.HandlerFunc(s.handleConntrack)))
	mux.Handle("/api/perf", s.withAuth(http.HandlerFunc(s.handlePerfStats)))
	mux.Handle("/api/perf/latency", s.withAuth(http.HandlerFunc(s.handlePerfLatency)))
	mux.Handle("/api/perf/cache", s.withAuth(http.HandlerFunc(s.handlePerfCache)))
	mux.Handle("/api/perf/traffic", s.withAuth(http.HandlerFunc(s.handlePerfTraffic)))
	mux.Handle("/api/perf/reset", s.withAuth(http.HandlerFunc(s.handlePerfReset)))
	registerMetricsRoutes(mux, NewMetricsHandler(s.sdk), s.withAuth)

	if cfg.Base.EnablePprof {
		mux.Handle("/debug/pprof/", s.withAuth(http.HandlerFunc(pprof.Index)))
		mux.Handle("/debug/pprof/cmdline", s.withAuth(http.HandlerFunc(pprof.Cmdline)))
		mux.Handle("/debug/pprof/profile", s.withAuth(http.HandlerFunc(pprof.Profile)))
		mux.Handle("/debug/pprof/symbol", s.withAuth(http.HandlerFunc(pprof.Symbol)))
		mux.Handle("/debug/pprof/trace", s.withAuth(http.HandlerFunc(pprof.Trace)))
	}

	return mux
}

// UIHandler returns the http.Handler for the embedded UI only.
func (s *Server) UIHandler() http.Handler {
	if err := s.EnsureHandlerInitialized(); err != nil {
		logger.Get(nil).Errorf("Failed to initialize UI handler: %v", err)
		return http.NotFoundHandler()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	return mux
}

// Handler returns the combined http.Handler for older callers.
// Handler 返回 API 和 UI 的 http.Handler。
func (s *Server) Handler() http.Handler {
	apiHandler := s.APIHandler()
	uiHandler := s.UIHandler()
	if uiHandler == nil {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/", uiHandler)
	mux.Handle("/healthz", apiHandler)
	mux.Handle("/health", apiHandler)
	mux.Handle("/health/maps", apiHandler)
	mux.Handle("/health/map", apiHandler)
	mux.Handle("/version", apiHandler)
	mux.Handle("/api/", apiHandler)
	mux.Handle("/debug/pprof/", apiHandler)
	mux.Handle("/debug/pprof/cmdline", apiHandler)
	mux.Handle("/debug/pprof/profile", apiHandler)
	mux.Handle("/debug/pprof/symbol", apiHandler)
	mux.Handle("/debug/pprof/trace", apiHandler)
	return mux
}
