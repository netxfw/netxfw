// Package system provides system functionality.
package system

import (
	"time"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
)

// DesiredState captures the policy and count-oriented state we expect runtime to match.
type DesiredState struct {
	DefaultDeny        bool
	AllowReturnTraffic bool
	AllowICMP          bool
	EnableAFXDP        bool
	EnableConntrack    bool
	EnableRateLimit    bool
	StrictProtocol     bool
	StrictTCP          bool
	SYNLimit           bool
	BogonFilter        bool
	DropFragments      bool
	AutoBlock          bool

	ICMPRate         uint64
	ICMPBurst        uint64
	AutoBlockExpiry  time.Duration
	ConntrackTimeout string

	WhitelistCount     int
	AllowedPortCount   int
	IPPortRuleCount    int
	RateLimitRuleCount int
	InterfaceCount     int
}

// FromConfig projects a configuration file into a runtime-oriented desired state.
func FromConfig(cfg *domainconfig.Config) DesiredState {
	if cfg == nil {
		return DesiredState{}
	}

	autoBlockExpiry, _ := time.ParseDuration(cfg.RateLimit.AutoBlockExpiry)

	return DesiredState{
		DefaultDeny:        cfg.Base.DefaultDeny,
		AllowReturnTraffic: cfg.Base.AllowReturnTraffic,
		AllowICMP:          cfg.Base.AllowICMP,
		EnableAFXDP:        cfg.Base.EnableAFXDP,
		EnableConntrack:    cfg.Conntrack.Enabled,
		EnableRateLimit:    cfg.RateLimit.Enabled,
		StrictProtocol:     cfg.Base.StrictProtocol,
		StrictTCP:          cfg.Base.StrictTCP,
		SYNLimit:           cfg.Base.SYNLimit,
		BogonFilter:        cfg.Base.BogonFilter,
		DropFragments:      cfg.Base.DropFragments,
		AutoBlock:          cfg.RateLimit.AutoBlock,
		ICMPRate:           cfg.Base.ICMPRate,
		ICMPBurst:          cfg.Base.ICMPBurst,
		AutoBlockExpiry:    autoBlockExpiry,
		ConntrackTimeout:   cfg.Conntrack.TCPTimeout,
		WhitelistCount:     len(cfg.Base.Whitelist),
		AllowedPortCount:   len(cfg.Port.AllowedPorts),
		IPPortRuleCount:    len(cfg.Port.IPPortRules),
		RateLimitRuleCount: len(cfg.RateLimit.Rules),
		InterfaceCount:     len(cfg.Base.Interfaces),
	}
}
