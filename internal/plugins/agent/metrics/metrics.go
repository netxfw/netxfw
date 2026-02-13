package metrics

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"

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
	GetDropDetails() ([]xdp.DropDetailEntry, error)
	GetPassDetails() ([]xdp.DropDetailEntry, error)
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
	xdpPassTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_xdp_pass_total",
			Help: "Total passed packets by the XDP program",
		},
		[]string{"reason"},
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

func (p *MetricsPlugin) Init(ctx *sdk.PluginContext) error {
	p.config = &ctx.Config.Metrics
	return nil
}

func (p *MetricsPlugin) Reload(ctx *sdk.PluginContext) error {
	log.Println("🔄 [Metrics] Reloading configuration...")
	if err := p.Stop(); err != nil {
		log.Printf("⚠️  [Metrics] Error stopping during reload: %v", err)
	}
	p.Init(ctx)
	return p.Start(ctx)
}

func (p *MetricsPlugin) Start(ctx *sdk.PluginContext) error {
	if !p.config.Enabled {
		log.Println("📊 Metrics plugin is disabled via config.")
		return nil
	}

	// Assign the manager as the stats provider
	p.provider = ctx.Manager

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

	// Update locked IP count
	lockedCount, err := p.provider.GetLockedIPCount()
	if err == nil {
		lockedIPsCount.Set(float64(lockedCount))
	}

	// Detailed Drop Stats
	dropDetails, err := p.provider.GetDropDetails()
	if err == nil {
		// Aggregate by reason
		reasonCounts := make(map[string]float64)
		for _, d := range dropDetails {
			rStr := reasonToString(d.Reason)
			reasonCounts[rStr] += float64(d.Count)
		}
		for r, c := range reasonCounts {
			xdpDropTotal.WithLabelValues(r).Set(c)
		}
	} else {
		// Fallback to global counter if details fail (or not available)
		dropCount, err := p.provider.GetDropCount()
		if err == nil {
			xdpDropTotal.WithLabelValues("total").Set(float64(dropCount))
		}
	}

	// Detailed Pass Stats
	passDetails, err := p.provider.GetPassDetails()
	if err == nil {
		// Aggregate by reason
		reasonCounts := make(map[string]float64)
		for _, d := range passDetails {
			rStr := passReasonToString(d.Reason)
			reasonCounts[rStr] += float64(d.Count)
		}
		for r, c := range reasonCounts {
			xdpPassTotal.WithLabelValues(r).Set(c)
		}
	} else {
		// Fallback
		passCount, err := p.provider.GetPassCount()
		if err == nil {
			xdpPassTotal.WithLabelValues("total").Set(float64(passCount))
		}
	}
}

func reasonToString(code uint32) string {
	switch code {
	case 0:
		return "UNKNOWN"
	case 1:
		return "INVALID"
	case 2:
		return "PROTOCOL"
	case 3:
		return "BLACKLIST"
	case 4:
		return "RATELIMIT"
	case 5:
		return "STRICT_TCP"
	case 6:
		return "DEFAULT"
	case 7:
		return "LAND_ATTACK"
	case 8:
		return "BOGON"
	case 9:
		return "FRAGMENT"
	case 10:
		return "BAD_HEADER"
	case 11:
		return "TCP_FLAGS"
	case 12:
		return "SPOOF"
	default:
		return fmt.Sprintf("CODE_%d", code)
	}
}

func passReasonToString(code uint32) string {
	switch code {
	case 100:
		return "UNKNOWN"
	case 101:
		return "WHITELIST"
	case 102:
		return "RETURN"
	case 103:
		return "CONNTRACK"
	case 104:
		return "DEFAULT"
	default:
		return fmt.Sprintf("CODE_%d", code)
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
