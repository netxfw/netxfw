package metrics

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type MetricsPlugin struct {
	config  *types.MetricsConfig
	running bool
	server  *http.Server
}

var (
	blockedTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_blocked_total",
			Help: "Total blocked packets by reason",
		},
		[]string{"reason"},
	)
)

func (p *MetricsPlugin) Name() string {
	return "metrics"
}

func (p *MetricsPlugin) Init(config *types.GlobalConfig) error {
	p.config = &config.Metrics
	return nil
}

func (p *MetricsPlugin) Start(manager *xdp.Manager) error {
	if !p.config.Enabled {
		log.Println("📊 Metrics server is disabled via plugin config.")
		return nil
	}

	addr := fmt.Sprintf(":%d", p.config.Port)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	p.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		log.Printf("📊 Metrics server listening on %s", addr)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ Metrics server error: %v", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		for range ticker.C {
			if !p.running {
				return
			}
			count, err := manager.GetDropCount()
			if err == nil {
				blockedTotal.WithLabelValues("lock").Set(float64(count))
			}
		}
	}()

	p.running = true
	return nil
}

func (p *MetricsPlugin) Stop() error {
	p.running = false
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

func (p *MetricsPlugin) DefaultConfig() interface{} {
	return types.MetricsConfig{
		Enabled: true,
		Port:    9100,
	}
}

func (p *MetricsPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
