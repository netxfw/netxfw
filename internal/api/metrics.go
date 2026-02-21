package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/netxfw/netxfw/internal/metrics"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsServer represents the metrics server.
// MetricsServer 代表指标服务器。
type MetricsServer struct {
	config  *types.MetricsConfig
	server  *http.Server
	running bool
	mu      sync.RWMutex // Protects running field from concurrent access / 保护 running 字段免受并发访问
	sdk     *sdk.SDK
}

// NewMetricsServer creates a new metrics server instance.
// NewMetricsServer 创建一个新的指标服务器实例。
func NewMetricsServer(s *sdk.SDK, config *types.MetricsConfig) *MetricsServer {
	return &MetricsServer{
		sdk:    s,
		config: config,
	}
}

// isRunning returns whether the server is running (thread-safe).
// isRunning 返回服务器是否正在运行（线程安全）。
func (m *MetricsServer) isRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// setRunning sets the running state (thread-safe).
// setRunning 设置运行状态（线程安全）。
func (m *MetricsServer) setRunning(running bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = running
}

// Start starts the metrics server.
// Start 启动指标服务器。
func (m *MetricsServer) Start(ctx context.Context) error {
	if !m.config.Enabled {
		logger.Get(ctx).Infof("📊 Metrics server is disabled via config.")
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	m.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", m.config.Port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	m.setRunning(true)

	// Start HTTP Server
	go func() {
		logger.Get(ctx).Infof("📊 Metrics server starting on :%d", m.config.Port)
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Get(ctx).Errorf("❌ Metrics server error: %v", err)
			m.setRunning(false)
		}
	}()

	// Start Metrics Collection Loop
	go m.collectStats(ctx)

	return nil
}

// Stop stops the metrics server.
// Stop 停止指标服务器。
func (m *MetricsServer) Stop() error {
	m.setRunning(false)
	if m.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return m.server.Shutdown(ctx)
	}
	return nil
}

// collectStats collects metrics periodically.
// collectStats 定期收集指标。
func (m *MetricsServer) collectStats(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for m.isRunning() {
		select {
		case <-ticker.C:
			if m.sdk.Stats != nil {
				// Update locked IPs count
				locked, err := m.sdk.Stats.GetLockedIPCount()
				if err == nil {
					metrics.WhitelistCount.Set(float64(locked))
				}

				// Update drop details
				drops, err := m.sdk.Stats.GetDropDetails()
				if err == nil {
					for _, d := range drops {
						reasonStr := fmt.Sprintf("%d", d.Reason)
						metrics.XdpDropTotal.WithLabelValues(reasonStr).Set(float64(d.Count))
					}
				}

				// Update pass details
				passes, err := m.sdk.Stats.GetPassDetails()
				if err == nil {
					for _, d := range passes {
						reasonStr := fmt.Sprintf("%d", d.Reason)
						metrics.XdpPassTotal.WithLabelValues(reasonStr).Set(float64(d.Count))
					}
				}

				// Update conntrack entries count
				if m.sdk.GetManager() != nil {
					count, err := m.sdk.GetManager().GetConntrackCount()
					if err == nil {
						metrics.ConntrackCount.Set(float64(count))
					}
				}

				// Update rules count
				if m.sdk.GetManager() != nil {
					whitelistCount, _ := m.sdk.GetManager().GetWhitelistCount()
					blacklistCount, _ := m.sdk.GetManager().GetLockedIPCount() // Locked IPs represent blacklist
					// Note: ListIPPortRules returns a slice, total count and error as the three return values
					_, ipPortRuleCount, _ := m.sdk.GetManager().ListIPPortRules(false, 0, "")

					metrics.RulesCount.WithLabelValues("whitelist").Set(float64(whitelistCount))
					metrics.RulesCount.WithLabelValues("blacklist").Set(float64(blacklistCount))
					metrics.RulesCount.WithLabelValues("ipport").Set(float64(ipPortRuleCount))
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
