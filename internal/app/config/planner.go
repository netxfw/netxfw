package config

import (
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	runtimestate "github.com/netxfw/netxfw/internal/domain/runtime"
	systemstate "github.com/netxfw/netxfw/internal/domain/system"
	"github.com/netxfw/netxfw/internal/ports"
)

type Mode string

const (
	ModeConfigToRuntime Mode = "config_to_runtime"
	ModeRuntimeToConfig Mode = "runtime_to_config"
	ModeVerifyAndRepair Mode = "verify_and_repair"
)

type Plan struct {
	Mode      Mode
	Overwrite bool
	Desired   systemstate.DesiredState
	Actual    runtimestate.ActualState
	Drift     runtimestate.StateDiff
}

type Planner struct{}

func NewPlanner() *Planner {
	return &Planner{}
}

func (p *Planner) PlanConfigToRuntime(cfg *domainconfig.Config, mgr ports.RuntimeStateReader) Plan {
	desired := systemstate.FromConfig(cfg)
	actual := runtimestate.FromManager(mgr)
	return Plan{
		Mode:      ModeConfigToRuntime,
		Overwrite: true,
		Desired:   desired,
		Actual:    actual,
		Drift:     runtimestate.CompareDesired(desired, actual),
	}
}

func (p *Planner) PlanRuntimeToConfig(mgr ports.RuntimeStateReader) Plan {
	return Plan{
		Mode:   ModeRuntimeToConfig,
		Actual: runtimestate.FromManager(mgr),
	}
}

func (p *Planner) PlanVerifyAndRepair(cfg *domainconfig.Config, mgr ports.RuntimeStateReader) Plan {
	desired := systemstate.FromConfig(cfg)
	actual := runtimestate.FromManager(mgr)
	return Plan{
		Mode:      ModeVerifyAndRepair,
		Overwrite: false,
		Desired:   desired,
		Actual:    actual,
		Drift:     runtimestate.CompareDesired(desired, actual),
	}
}
