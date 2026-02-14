package api

import (
	"fmt"
	"net/http"
	"net/http/pprof"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
)

type Server struct {
	manager    xdp.ManagerInterface
	port       int
	configPath string
}

// NewServer creates a new API and UI server instance.
func NewServer(manager xdp.ManagerInterface, port int) *Server {
	return &Server{
		manager:    manager,
		port:       port,
		configPath: config.GetConfigPath(),
	}
}

// Start launches the HTTP server for management.
func (s *Server) Start() error {
	log := logger.Get(nil)
	// Auto-generate token if not configured
	cfg, err := types.LoadGlobalConfig(s.configPath)
	if err == nil {
		if cfg.Web.Token == "" {
			token := generateRandomToken(16)
			cfg.Web.Token = token
			cfg.Web.Enabled = true
			cfg.Web.Port = s.port
			types.SaveGlobalConfig(s.configPath, cfg)
			log.Infof("🔑 No Web Token configured. Automatically generated a new one: %s", token)
			log.Infof("📝 Token has been saved to %s", s.configPath)
		} else {
			log.Infof("🔑 Using configured Web Token for authentication")
		}
	}

	mux := http.NewServeMux()

	// Auth & Login
	mux.HandleFunc("/api/login", s.handleLogin)

	// API Endpoints with Token Auth
	mux.Handle("/api/stats", s.withAuth(http.HandlerFunc(s.handleStats)))
	mux.Handle("/api/rules", s.withAuth(http.HandlerFunc(s.handleRules)))
	mux.Handle("/api/config", s.withAuth(http.HandlerFunc(s.handleConfig)))
	mux.Handle("/api/sync", s.withAuth(http.HandlerFunc(s.handleSync)))
	mux.Handle("/api/conntrack", s.withAuth(http.HandlerFunc(s.handleConntrack)))

	// Pprof Endpoints (Protected)
	mux.Handle("/debug/pprof/", s.withAuth(http.HandlerFunc(pprof.Index)))
	mux.Handle("/debug/pprof/cmdline", s.withAuth(http.HandlerFunc(pprof.Cmdline)))
	mux.Handle("/debug/pprof/profile", s.withAuth(http.HandlerFunc(pprof.Profile)))
	mux.Handle("/debug/pprof/symbol", s.withAuth(http.HandlerFunc(pprof.Symbol)))
	mux.Handle("/debug/pprof/trace", s.withAuth(http.HandlerFunc(pprof.Trace)))

	// UI (Embedded)
	mux.HandleFunc("/", s.handleUI)

	addr := fmt.Sprintf(":%d", s.port)
	log.Infof("🚀 Management API and UI starting on http://localhost%s", addr)
	return http.ListenAndServe(addr, mux)
}
