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
	xdpDropTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_xdp_drop_total",
			Help: "Total dropped packets by the XDP program",
		},
		[]string{"reason"},
	)
	xdpPassTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "netxfw_xdp_pass_total",
			Help: "Total passed packets by the XDP program",
		},
	)
	lockedIPsCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "netxfw_locked_ips_count",
			Help: "Current number of locked IP addresses",
		},
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
			// Update drop count
			dropCount, err := manager.GetDropCount()
			if err == nil {
				xdpDropTotal.WithLabelValues("firewall").Set(float64(dropCount))
			}

			// Update pass count
			passCount, err := manager.GetPassCount()
			if err == nil {
				xdpPassTotal.Set(float64(passCount))
			}

			// Update locked IP count
			lockedCount, err := manager.GetLockedIPCount()
			if err == nil {
				lockedIPsCount.Set(float64(lockedCount))
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
		Enabled: false,
		Port:    9100,
	}
}

func (p *MetricsPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
