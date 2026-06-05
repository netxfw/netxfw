package config

import "testing"

func TestDefaultConfig(t *testing.T) {
	SetDefaultLogDirCreationEnabled(false)

	cfg := DefaultConfig()
	if cfg.Base.ICMPRate != 10 {
		t.Fatalf("unexpected icmp_rate: %d", cfg.Base.ICMPRate)
	}
	if cfg.Web.Port != 11811 {
		t.Fatalf("unexpected web port: %d", cfg.Web.Port)
	}
}

func TestValidate(t *testing.T) {
	SetDefaultLogDirCreationEnabled(false)

	cfg := DefaultConfig()
	if err := Validate(&cfg); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}

	cfg.Base.LockListV4Mask = 64
	if err := Validate(&cfg); err == nil {
		t.Fatalf("expected validation error")
	}

	// Test negative rate limits capacity
	cfg = DefaultConfig()
	cfg.Capacity.RateLimits = -1
	if err := Validate(&cfg); err == nil {
		t.Fatalf("expected validation error for negative rate_limits")
	}
}
