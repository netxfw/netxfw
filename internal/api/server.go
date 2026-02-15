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

// Server represents the API and UI server.
// Server 代表 API 和 UI 服务器。
type Server struct {
	manager    xdp.ManagerInterface
	port       int
	configPath string
}

// NewServer creates a new API and UI server instance.
// NewServer 创建一个新的 API 和 UI 服务器实例。
func NewServer(manager xdp.ManagerInterface, port int) *Server {
	return &Server{
		manager:    manager,
		port:       port,
		configPath: config.GetConfigPath(),
	}
}

// Start launches the HTTP server for management.
// Start 启动用于管理的 HTTP 服务器。
func (s *Server) Start() error {
	log := logger.Get(nil)
	// Auto-generate token if not configured
	// 如果未配置 Token，则自动生成
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

	// Auth & Login / 认证与登录
	mux.HandleFunc("/api/login", s.handleLogin)

	// API Endpoints with Token Auth / 带有 Token 认证的 API 端点
	mux.Handle("/api/stats", s.withAuth(http.HandlerFunc(s.handleStats)))
	mux.Handle("/api/rules", s.withAuth(http.HandlerFunc(s.handleRules)))
	mux.Handle("/api/config", s.withAuth(http.HandlerFunc(s.handleConfig)))
	mux.Handle("/api/sync", s.withAuth(http.HandlerFunc(s.handleSync)))
	mux.Handle("/api/conntrack", s.withAuth(http.HandlerFunc(s.handleConntrack)))

	// Pprof Endpoints (Protected) / Pprof 端点（受保护）
	mux.Handle("/debug/pprof/", s.withAuth(http.HandlerFunc(pprof.Index)))
	mux.Handle("/debug/pprof/cmdline", s.withAuth(http.HandlerFunc(pprof.Cmdline)))
	mux.Handle("/debug/pprof/profile", s.withAuth(http.HandlerFunc(pprof.Profile)))
	mux.Handle("/debug/pprof/symbol", s.withAuth(http.HandlerFunc(pprof.Symbol)))
	mux.Handle("/debug/pprof/trace", s.withAuth(http.HandlerFunc(pprof.Trace)))

	// UI (Embedded) / UI（内嵌）
	mux.HandleFunc("/", s.handleUI)

	addr := fmt.Sprintf(":%d", s.port)
	log.Infof("🚀 Management API and UI starting on http://localhost%s", addr)
	return http.ListenAndServe(addr, mux)
}
