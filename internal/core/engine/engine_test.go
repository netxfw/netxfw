package engine_test

import (
	"testing"

	"github.com/livp123/netxfw/internal/core/engine"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

// TestLogger implements sdk.Logger for testing
type TestLogger struct {
	t *testing.T
}

func (l *TestLogger) Infof(format string, args ...interface{}) {
	l.t.Logf("[INFO] "+format, args...)
}
func (l *TestLogger) Warnf(format string, args ...interface{}) {
	l.t.Logf("[WARN] "+format, args...)
}
func (l *TestLogger) Errorf(format string, args ...interface{}) {
	l.t.Logf("[ERROR] "+format, args...)
}

func TestCoreModules(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	logger := &TestLogger{t: t}
	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: true,
		},
		Conntrack: types.ConntrackConfig{
			Enabled:    true,
			TCPTimeout: "1h",
		},
		Port: types.PortConfig{
			AllowedPorts: []uint16{80, 443},
			IPPortRules: []types.IPPortRule{
				{IP: "192.168.1.100", Port: 22, Action: 1}, // Allow SSH
			},
		},
		RateLimit: types.RateLimitConfig{
			Enabled:   true,
			AutoBlock: true,
			Rules: []types.RateLimitRule{
				{IP: "10.0.0.1", Rate: 100, Burst: 10},
			},
		},
	}

	t.Run("BaseModule", func(t *testing.T) {
		mod := &engine.BaseModule{}
		if err := mod.Init(globalCfg, s, logger); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if err := mod.Start(); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		// Verify Base settings
		// Note: Since MockManager is internal, we can't easily check internal state here
		// unless we export it or add getters to MockManager.
		// For now, we rely on no error returned.
	})

	t.Run("ConntrackModule", func(t *testing.T) {
		mod := &engine.ConntrackModule{}
		if err := mod.Init(globalCfg, s, logger); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if err := mod.Start(); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
	})

	t.Run("PortModule", func(t *testing.T) {
		mod := &engine.PortModule{}
		if err := mod.Init(globalCfg, s, logger); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if err := mod.Start(); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		// Verify Port settings via Manager
		ports, _ := mockMgr.ListAllowedPorts()
		found80 := false
		for _, p := range ports {
			if p == 80 {
				found80 = true
				break
			}
		}
		if !found80 {
			t.Errorf("Port 80 should be allowed")
		}
	})

	t.Run("RateLimitModule", func(t *testing.T) {
		mod := &engine.RateLimitModule{}
		if err := mod.Init(globalCfg, s, logger); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if err := mod.Start(); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		// Verify RateLimit settings
		rules, _, _ := mockMgr.ListRateLimitRules(0, "")
		found := false
		for ip := range rules {
			if ip == "10.0.0.1" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("RateLimit rule for 10.0.0.1 not found")
		}
	})
}
