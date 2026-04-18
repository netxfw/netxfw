package config

import (
	"context"
	"testing"

	"github.com/netxfw/netxfw/pkg/sdk"
)

func TestReconcileConfigToRuntime(t *testing.T) {
	mgr := sdk.NewMockManager()
	cfg := &sdk.GlobalConfig{}
	cfg.Base.Whitelist = []string{"10.0.0.1/32"}
	cfg.Port.AllowedPorts = []uint16{443}
	cfg.Port.IPPortRules = []sdk.IPPortRule{{IP: "10.0.0.2/32", Port: 80, Action: 1}}
	cfg.RateLimit.Rules = []sdk.RateLimitRule{{IP: "10.0.0.0/24", Rate: 1000, Burst: 100}}

	plan, err := ReconcileConfigToRuntime(context.Background(), mgr, cfg)
	if err != nil {
		t.Fatalf("ReconcileConfigToRuntime failed: %v", err)
	}
	if plan.Mode != ModeConfigToRuntime || !plan.Overwrite {
		t.Fatalf("unexpected plan: %+v", plan)
	}

	ports, err := mgr.ListAllowedPorts()
	if err != nil || len(ports) != 1 || ports[0] != 443 {
		t.Fatalf("expected allowed ports to be synced, got %v, err=%v", ports, err)
	}
	rules, _, err := mgr.ListRateLimitRules(0, "")
	if err != nil || len(rules) != 1 {
		t.Fatalf("expected rate limit rules to be synced, got %v, err=%v", rules, err)
	}
}

func TestReconcileRuntimeToConfig(t *testing.T) {
	mgr := sdk.NewMockManager()
	if err := mgr.AddWhitelistIP("10.0.0.1/32", 0); err != nil {
		t.Fatalf("AddWhitelistIP failed: %v", err)
	}
	if err := mgr.AllowPort(443); err != nil {
		t.Fatalf("AllowPort failed: %v", err)
	}
	cfg := &sdk.GlobalConfig{}

	plan, err := ReconcileRuntimeToConfig(context.Background(), mgr, cfg)
	if err != nil {
		t.Fatalf("ReconcileRuntimeToConfig failed: %v", err)
	}
	if plan.Mode != ModeRuntimeToConfig {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if len(cfg.Base.Whitelist) != 1 || len(cfg.Port.AllowedPorts) != 1 {
		t.Fatalf("expected config to be updated from runtime: %+v", cfg)
	}
}

func TestVerifyAndRepair(t *testing.T) {
	mgr := sdk.NewMockManager()
	cfg := &sdk.GlobalConfig{}
	cfg.Base.Whitelist = []string{"10.0.0.1/32"}

	plan, err := VerifyAndRepair(context.Background(), mgr, cfg)
	if err != nil {
		t.Fatalf("VerifyAndRepair failed: %v", err)
	}
	if plan.Mode != ModeVerifyAndRepair || plan.Overwrite {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}
