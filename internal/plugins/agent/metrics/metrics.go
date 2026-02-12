package metrics

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/prometheus/common/expfmt"
)

// StatsProvider defines the interface for retrieving firewall statistics.
type StatsProvider interface {
	GetDropCount() (uint64, error)
	GetPassCount() (uint64, error)
	GetLockedIPCount() (uint64, error)
}

type MetricsPlugin struct {
	config   *types.MetricsConfig
	running  bool
	server   *http.Server
	provider StatsProvider
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

func (p *MetricsPlugin) Reload(config *types.GlobalConfig, manager *xdp.Manager) error {
	log.Println("🔄 [Metrics] Reloading configuration...")
	if err := p.Stop(); err != nil {
		log.Printf("⚠️  [Metrics] Error stopping during reload: %v", err)
	}
	p.Init(config)
	return p.Start(manager)
}

func (p *MetricsPlugin) Start(manager *xdp.Manager) error {
	if !p.config.Enabled {
		log.Println("📊 Metrics plugin is disabled via config.")
		return nil
	}

	// Assign the manager as the stats provider
	p.provider = manager

	// Default port if not set
	if p.config.Port == 0 {
		p.config.Port = 11812
	}

	// 1. Start HTTP Server if enabled and port is positive
	if p.config.ServerEnabled && p.config.Port > 0 {
		addr := fmt.Sprintf(":%d", p.config.Port)
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		p.server = &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		go func() {
			log.Printf("📊 Metrics HTTP server listening on %s", addr)
			if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("❌ Metrics server error: %v", err)
			}
		}()
	}

	// 2. Metrics Collection and Export Loop
	p.running = true
	go func() {
		collectionInterval := 2 * time.Second
		pushInterval := 1 * time.Minute
		if p.config.PushInterval != "" {
			if d, err := time.ParseDuration(p.config.PushInterval); err == nil {
				pushInterval = d
			}
		}

		ticker := time.NewTicker(collectionInterval)
		lastPush := time.Now()
		defer ticker.Stop()

		for range ticker.C {
			if !p.running {
				return
			}

			// Update internal metrics from BPF maps
			p.updateMetrics()

			// 3. Handle Textfile Export (for node_exporter)
			if p.config.TextfileEnabled && p.config.TextfilePath != "" {
				p.writeTextFile()
			}

			// 4. Handle Active Push (e.g. to PushGateway)
			if p.config.PushEnabled && time.Since(lastPush) >= pushInterval {
				p.pushMetrics()
				lastPush = time.Now()
			}
		}
	}()

	return nil
}

func (p *MetricsPlugin) updateMetrics() {
	if p.provider == nil {
		return
	}

	// Update drop count
	dropCount, err := p.provider.GetDropCount()
	if err == nil {
		xdpDropTotal.WithLabelValues("firewall").Set(float64(dropCount))
	}

	// Update pass count
	passCount, err := p.provider.GetPassCount()
	if err == nil {
		xdpPassTotal.Set(float64(passCount))
	}

	// Update locked IP count
	lockedCount, err := p.provider.GetLockedIPCount()
	if err == nil {
		lockedIPsCount.Set(float64(lockedCount))
	}
}

func (p *MetricsPlugin) writeTextFile() {
	f, err := os.Create(p.config.TextfilePath + ".tmp")
	if err != nil {
		log.Printf("❌ Failed to create metrics textfile: %v", err)
		return
	}

	enc := expfmt.NewEncoder(f, expfmt.Format("text/plain; version=0.0.4"))
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		log.Printf("❌ Failed to gather metrics for textfile: %v", err)
		f.Close()
		return
	}

	for _, mf := range mfs {
		enc.Encode(mf)
	}
	f.Close()

	// Atomic rename
	if err := os.Rename(p.config.TextfilePath+".tmp", p.config.TextfilePath); err != nil {
		log.Printf("❌ Failed to rename metrics textfile: %v", err)
	}
}

func (p *MetricsPlugin) pushMetrics() {
	if p.config.PushGatewayAddr == "" {
		return
	}

	log.Printf("📤 Pushing metrics to %s", p.config.PushGatewayAddr)
	err := push.New(p.config.PushGatewayAddr, "netxfw").
		Gatherer(prometheus.DefaultGatherer).
		Push()
	if err != nil {
		log.Printf("❌ Could not push to PushGateway: %v", err)
	}
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
		Enabled:         false,
		ServerEnabled:   true,
		Port:            11812,
		PushEnabled:     false,
		PushGatewayAddr: "",
		PushInterval:    "1m",
		TextfileEnabled: false,
		TextfilePath:    "",
	}
}

func (p *MetricsPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
