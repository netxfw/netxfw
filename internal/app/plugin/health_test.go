package plugin

import (
	"testing"

	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	"github.com/netxfw/netxfw/internal/ports"
)

func TestSummarizeHealth(t *testing.T) {
	snapshot := StatusSnapshot{
		Runtime: []domainruntime.Status{
			{Name: "web", Enabled: true, Running: true, Healthy: true, Message: "enabled by config"},
			{Name: "metrics", Enabled: false, Healthy: true, Message: "disabled by config"},
		},
		Datapath: []domaindatapath.LifecycleStatus{
			{Path: "/tmp/plugin-a.o", Index: 2, Loaded: true, Healthy: true, Message: "loaded"},
			{Path: "/tmp/plugin-b.o", Index: 3, Loaded: false, Healthy: false, Message: "configured but not loaded"},
		},
	}

	health := SummarizeHealth(snapshot)
	if health.Runtime.Status != ports.HealthStatusHealthy {
		t.Fatalf("expected healthy runtime status, got %s", health.Runtime.Status)
	}
	if health.Datapath.Status != ports.HealthStatusDegraded {
		t.Fatalf("expected degraded datapath status, got %s", health.Datapath.Status)
	}
}
