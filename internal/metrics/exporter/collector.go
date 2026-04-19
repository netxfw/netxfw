package exporter

import (
	"context"
	"fmt"
	"time"

	sharedmetrics "github.com/netxfw/netxfw/internal/metrics"
	"github.com/netxfw/netxfw/pkg/sdk"
)

const defaultCollectInterval = 5 * time.Second

// Collector updates Prometheus metrics from the shared SDK/manager state.
type Collector struct {
	sdk *sdk.SDK
}

func NewCollector(s *sdk.SDK) *Collector {
	return &Collector{sdk: s}
}

func (c *Collector) Run(ctx context.Context, isRunning func() bool) {
	if ctx == nil {
		ctx = context.Background()
	}

	ticker := time.NewTicker(defaultCollectInterval)
	defer ticker.Stop()

	for isRunning() {
		c.CollectOnce()

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func (c *Collector) CollectOnce() {
	if c == nil || c.sdk == nil || c.sdk.Stats == nil {
		return
	}

	locked, err := c.sdk.Stats.GetLockedIPCount()
	if err == nil {
		sharedmetrics.WhitelistCount.Set(float64(locked))
	}

	drops, err := c.sdk.Stats.GetDropDetails()
	if err == nil {
		for _, d := range drops {
			reasonStr := fmt.Sprintf("%d", d.Reason)
			sharedmetrics.XdpDropTotal.WithLabelValues(reasonStr).Set(float64(d.Count))
		}
	}

	passes, err := c.sdk.Stats.GetPassDetails()
	if err == nil {
		for _, d := range passes {
			reasonStr := fmt.Sprintf("%d", d.Reason)
			sharedmetrics.XdpPassTotal.WithLabelValues(reasonStr).Set(float64(d.Count))
		}
	}

	globalStats, err := c.sdk.Stats.GetGlobalStats()
	if err == nil && globalStats != nil {
		sharedmetrics.XdpDropTotal.WithLabelValues("default_deny").Set(float64(globalStats.DropDefaultDeny))
	}

	count, err := c.sdk.Conntrack.Count()
	if err == nil {
		sharedmetrics.ConntrackCount.Set(float64(count))
	}

	whitelistEntries, whitelistCount, err := c.sdk.Whitelist.List(0, "")
	if err == nil {
		_ = whitelistEntries
		sharedmetrics.RulesCount.WithLabelValues("whitelist").Set(float64(whitelistCount))
	}

	blacklistEntries, blacklistCount, err := c.sdk.Blacklist.List(0, "")
	if err == nil {
		_ = blacklistEntries
		sharedmetrics.RulesCount.WithLabelValues("blacklist").Set(float64(blacklistCount))
	}

	_, ipPortRuleCount, err := c.sdk.Rule.List(false, 0, "")
	if err == nil {
		sharedmetrics.RulesCount.WithLabelValues("ipport").Set(float64(ipPortRuleCount))
	}
}
