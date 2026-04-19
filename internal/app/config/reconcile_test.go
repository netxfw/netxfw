package config

import (
	"context"
	"testing"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

type mockReconciler struct {
	*sdk.MockManager
}

func toSDKConfig(cfg *domainconfig.Config) *sdk.GlobalConfig {
	if cfg == nil {
		return nil
	}
	return &sdk.GlobalConfig{
		Base: sdk.BaseConfig{
			Whitelist: append([]string(nil), cfg.Base.Whitelist...),
		},
		Port: sdk.PortConfig{
			AllowedPorts: append([]uint16(nil), cfg.Port.AllowedPorts...),
			IPPortRules:  toSDKIPPortRules(cfg.Port.IPPortRules),
		},
		RateLimit: sdk.RateLimitConfig{
			Rules: toSDKRateLimitRules(cfg.RateLimit.Rules),
		},
	}
}

func toSDKIPPortRules(rules []domainconfig.IPPortRule) []sdk.IPPortRule {
	out := make([]sdk.IPPortRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, sdk.IPPortRule{IP: rule.IP, Port: rule.Port, Action: rule.Action})
	}
	return out
}

func toSDKRateLimitRules(rules []domainconfig.RateLimitRule) []sdk.RateLimitRule {
	out := make([]sdk.RateLimitRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, sdk.RateLimitRule{IP: rule.IP, Rate: rule.Rate, Burst: rule.Burst})
	}
	return out
}

func applySDKConfig(dst *domainconfig.Config, src *sdk.GlobalConfig) {
	if dst == nil || src == nil {
		return
	}
	dst.Base.Whitelist = append([]string(nil), src.Base.Whitelist...)
	dst.Port.AllowedPorts = append([]uint16(nil), src.Port.AllowedPorts...)
	dst.Port.IPPortRules = make([]domainconfig.IPPortRule, 0, len(src.Port.IPPortRules))
	for _, rule := range src.Port.IPPortRules {
		dst.Port.IPPortRules = append(dst.Port.IPPortRules, domainconfig.IPPortRule{IP: rule.IP, Port: rule.Port, Action: rule.Action})
	}
	dst.RateLimit.Rules = make([]domainconfig.RateLimitRule, 0, len(src.RateLimit.Rules))
	for _, rule := range src.RateLimit.Rules {
		dst.RateLimit.Rules = append(dst.RateLimit.Rules, domainconfig.RateLimitRule{IP: rule.IP, Rate: rule.Rate, Burst: rule.Burst})
	}
}

func (m mockReconciler) SyncFromFiles(cfg *domainconfig.Config, overwrite bool) error {
	sdkCfg := toSDKConfig(cfg)
	return m.MockManager.SyncFromFiles(sdkCfg, overwrite)
}

func (m mockReconciler) SyncToFiles(cfg *domainconfig.Config) error {
	sdkCfg := toSDKConfig(cfg)
	if err := m.MockManager.SyncToFiles(sdkCfg); err != nil {
		return err
	}
	applySDKConfig(cfg, sdkCfg)
	return nil
}

func (m mockReconciler) VerifyAndRepair(cfg *domainconfig.Config) error {
	sdkCfg := toSDKConfig(cfg)
	if err := m.MockManager.VerifyAndRepair(sdkCfg); err != nil {
		return err
	}
	applySDKConfig(cfg, sdkCfg)
	return nil
}

func TestReconcileConfigToRuntime(t *testing.T) {
	mgr := mockReconciler{MockManager: sdk.NewMockManager()}
	cfg := &domainconfig.Config{}
	cfg.Base.Whitelist = []string{"10.0.0.1/32"}
	cfg.Port.AllowedPorts = []uint16{443}
	cfg.Port.IPPortRules = []domainconfig.IPPortRule{{IP: "10.0.0.2/32", Port: 80, Action: 1}}
	cfg.RateLimit.Rules = []domainconfig.RateLimitRule{{IP: "10.0.0.0/24", Rate: 1000, Burst: 100}}

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
	mgr := mockReconciler{MockManager: sdk.NewMockManager()}
	if err := mgr.AddWhitelistIP("10.0.0.1/32", 0); err != nil {
		t.Fatalf("AddWhitelistIP failed: %v", err)
	}
	if err := mgr.AllowPort(443); err != nil {
		t.Fatalf("AllowPort failed: %v", err)
	}
	cfg := &domainconfig.Config{}

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
	mgr := mockReconciler{MockManager: sdk.NewMockManager()}
	cfg := &domainconfig.Config{}
	cfg.Base.Whitelist = []string{"10.0.0.1/32"}

	plan, err := VerifyAndRepair(context.Background(), mgr, cfg)
	if err != nil {
		t.Fatalf("VerifyAndRepair failed: %v", err)
	}
	if plan.Mode != ModeVerifyAndRepair || plan.Overwrite {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}
