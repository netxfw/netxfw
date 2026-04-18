package system

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/pkg/sdk"
)

func TestFromConfig(t *testing.T) {
	cfg := &sdk.GlobalConfig{}
	cfg.Base.DefaultDeny = true
	cfg.Base.AllowReturnTraffic = true
	cfg.Base.AllowICMP = true
	cfg.Base.EnableAFXDP = true
	cfg.Base.StrictProtocol = true
	cfg.Base.StrictTCP = true
	cfg.Base.SYNLimit = true
	cfg.Base.BogonFilter = true
	cfg.Base.DropFragments = true
	cfg.Base.ICMPRate = 100
	cfg.Base.ICMPBurst = 200
	cfg.Base.Whitelist = []string{"10.0.0.1/32", "10.0.0.2/32"}
	cfg.Base.Interfaces = []string{"eth0", "eth1"}
	cfg.Conntrack.Enabled = true
	cfg.Conntrack.TCPTimeout = "5m"
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.AutoBlock = true
	cfg.RateLimit.AutoBlockExpiry = "5m"
	cfg.Port.AllowedPorts = []uint16{80, 443}
	cfg.Port.IPPortRules = []sdk.IPPortRule{{IP: "10.0.0.1/32", Port: 80, Action: 1}}
	cfg.RateLimit.Rules = []sdk.RateLimitRule{{IP: "10.0.0.0/24", Rate: 1000, Burst: 100}}

	state := FromConfig(cfg)

	if !state.DefaultDeny || !state.EnableConntrack || !state.EnableRateLimit {
		t.Fatalf("expected projected booleans to be preserved: %+v", state)
	}
	if state.WhitelistCount != 2 || state.AllowedPortCount != 2 || state.IPPortRuleCount != 1 || state.RateLimitRuleCount != 1 {
		t.Fatalf("unexpected projected counts: %+v", state)
	}
	if state.InterfaceCount != 2 || state.ConntrackTimeout != "5m" || state.AutoBlockExpiry != 5*time.Minute {
		t.Fatalf("unexpected projected metadata: %+v", state)
	}
}
