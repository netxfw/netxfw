package exporter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	sharedmetrics "github.com/netxfw/netxfw/internal/metrics"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type stubStats struct {
	locked int
	drops  []sdk.DropDetailEntry
	passes []sdk.DropDetailEntry
	global *sdk.GlobalStats
}

func (s *stubStats) GetCounters() (pass uint64, drop uint64, err error) {
	return 0, 0, nil
}

func (s *stubStats) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	return s.drops, nil
}

func (s *stubStats) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	return s.passes, nil
}

func (s *stubStats) GetLockedIPCount() (int, error) {
	return s.locked, nil
}

func (s *stubStats) GetDynamicLockedIPCount() (uint64, error) {
	return 0, nil
}

func (s *stubStats) GetWhitelistCount() (int, error) {
	return 0, nil
}

func (s *stubStats) GetConntrackCount() (int, error) {
	return 0, nil
}

func (s *stubStats) GetGlobalStats() (*sdk.GlobalStats, error) {
	return s.global, nil
}

type stubManager struct {
	*xdp.MockManager
	conntrackCount int
}

func (m *stubManager) GetConntrackCount() (int, error) {
	return m.conntrackCount, nil
}

func resetMetricsForTest() {
	sharedmetrics.WhitelistCount.Set(0)
	sharedmetrics.ConntrackCount.Set(0)
	sharedmetrics.XdpDropTotal.Reset()
	sharedmetrics.XdpPassTotal.Reset()
	sharedmetrics.RulesCount.Reset()
}

func TestCollectorCollectOnceHandlesNilDependencies(t *testing.T) {
	resetMetricsForTest()

	var nilCollector *Collector
	nilCollector.CollectOnce()

	collector := NewCollector(nil)
	collector.CollectOnce()

	collector = NewCollector(&sdk.SDK{})
	collector.CollectOnce()
}

func TestCollectorCollectOnceUpdatesSharedMetrics(t *testing.T) {
	resetMetricsForTest()

	mgr := &stubManager{
		MockManager:    xdp.NewMockManager(),
		conntrackCount: 9,
	}
	requireNoError(t, mgr.AddBlacklistIP("10.0.0.1"))
	requireNoError(t, mgr.AddWhitelistIP("10.0.0.2", 0))
	requireNoError(t, mgr.AddIPPortRule("10.0.0.3/32", 443, 1))

	stats := &stubStats{
		locked: 4,
		drops: []sdk.DropDetailEntry{
			{Reason: 7, Count: 11},
		},
		passes: []sdk.DropDetailEntry{
			{Reason: 8, Count: 12},
		},
		global: &sdk.GlobalStats{DropDefaultDeny: 13},
	}

	fullSDK := sdk.NewSDK(mgr)
	fullSDK.Stats = stats
	collector := NewCollector(fullSDK)
	collector.CollectOnce()

	metricsText := scrapeMetrics(t)
	assertMetricLine(t, metricsText, `netxfw_whitelist_entries_total 4`, "whitelist count")
	assertMetricLine(t, metricsText, `netxfw_xdp_drop_total{reason="7"} 11`, "drop reason 7")
	assertMetricLine(t, metricsText, `netxfw_xdp_pass_total{reason="8"} 12`, "pass reason 8")
	assertMetricLine(t, metricsText, `netxfw_xdp_drop_total{reason="default_deny"} 13`, "default_deny")
	assertMetricLine(t, metricsText, `netxfw_conntrack_entries_total 9`, "conntrack count")
	assertMetricLine(t, metricsText, `netxfw_rules_count{type="whitelist"} 1`, "whitelist rules")
	assertMetricLine(t, metricsText, `netxfw_rules_count{type="blacklist"} 1`, "blacklist rules")
	assertMetricLine(t, metricsText, `netxfw_rules_count{type="ipport"} 1`, "ipport rules")
}

func scrapeMetrics(t *testing.T) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, req)

	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	return string(body)
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertMetricLine(t *testing.T, metricsText, wantLine, name string) {
	t.Helper()
	if !strings.Contains(metricsText, wantLine) {
		t.Fatalf("missing %s line %q in metrics output:\n%s", name, wantLine, metricsText)
	}
}
