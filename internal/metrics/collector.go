package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// XDP metrics
	XdpDropTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_xdp_drop_total",
			Help: "Total dropped packets by the XDP program",
		},
		[]string{"reason"},
	)
	XdpPassTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_xdp_pass_total",
			Help: "Total passed packets by the XDP program",
		},
		[]string{"reason"},
	)

	// Rules metrics
	RulesCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_rules_count",
			Help: "Number of rules in different categories",
		},
		[]string{"type"},
	)

	// Security metrics
	SecuritySettings = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_security_settings",
			Help: "Security settings status",
		},
		[]string{"setting"},
	)

	// Connection tracking metrics
	ConntrackCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "netxfw_conntrack_entries_total",
			Help: "Total number of conntrack entries",
		},
	)

	// Whitelist metrics
	WhitelistCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "netxfw_whitelist_entries_total",
			Help: "Total number of whitelist entries",
		},
	)
)
