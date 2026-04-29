package exporter

import (
	"context"
	"crypto/hmac"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netxfw/netxfw/internal/utils/logger"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const defaultMetricsBind = "127.0.0.1"

// Server exposes Prometheus metrics on a dedicated HTTP listener.
type Server struct {
	config    *sdk.MetricsConfig
	server    *http.Server
	running   bool
	mu        sync.RWMutex
	collector *Collector
}

func NewServer(s *sdk.SDK, config *sdk.MetricsConfig) *Server {
	return &Server{
		config:    config,
		collector: NewCollector(s),
	}
}

func (s *Server) isRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *Server) setRunning(running bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = running
}

func (s *Server) Start(ctx context.Context) error {
	if !s.config.Enabled || !s.config.ServerEnabled {
		logger.Get(ctx).Infof("[STATS] Metrics server is disabled via config.")
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", NewPrometheusHandler(s.config.Token))

	s.server = &http.Server{
		Addr:              net.JoinHostPort(metricsBind(s.config.Bind), strconv.Itoa(s.config.Port)),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.setRunning(true)

	go func() {
		logger.Get(ctx).Infof("[STATS] Metrics server starting on %s", s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Get(ctx).Errorf("[ERROR] Metrics server error: %v", err)
			s.setRunning(false)
		}
	}()

	go s.collector.Run(ctx, s.isRunning)

	return nil
}

// NewPrometheusHandler returns a Prometheus handler protected by a bearer token when configured.
func NewPrometheusHandler(token string) http.Handler {
	base := promhttp.Handler()
	if token == "" {
		return base
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if provided == "" {
			provided = r.Header.Get("X-NetXFW-Metrics-Token")
		}
		if provided == "" || !hmac.Equal([]byte(provided), []byte(token)) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		base.ServeHTTP(w, r)
	})
}

func metricsBind(bind string) string {
	if bind == "" {
		return defaultMetricsBind
	}
	return bind
}

func (s *Server) Stop() error {
	s.setRunning(false)
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}
