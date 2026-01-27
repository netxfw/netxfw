package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	blockedTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netxfw_blocked_total",
			Help: "Total blocked packets by reason",
		},
		[]string{"reason"},
	)
)

func UpdateMetrics(count uint64) {
	blockedTotal.WithLabelValues("blacklist").Set(float64(count))
}
