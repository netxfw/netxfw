package exporter

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server exposes Prometheus metrics on a dedicated HTTP listener.
type Server struct {
	config    *types.MetricsConfig
	server    *http.Server
	running   bool
	mu        sync.RWMutex
	collector *Collector
}

func NewServer(s *sdk.SDK, config *types.MetricsConfig) *Server {
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
	mux.Handle("/metrics", promhttp.Handler())

	s.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.config.Port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.setRunning(true)

	go func() {
		logger.Get(ctx).Infof("[STATS] Metrics server starting on :%d", s.config.Port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Get(ctx).Errorf("[ERROR] Metrics server error: %v", err)
			s.setRunning(false)
		}
	}()

	go s.collector.Run(ctx, s.isRunning)

	return nil
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
