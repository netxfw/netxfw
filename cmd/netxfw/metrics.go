package main

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    blockedTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "netxfw_blocked_total",
            Help: "Total blocked packets by reason",
        },
        []string{"reason"},
    )
)