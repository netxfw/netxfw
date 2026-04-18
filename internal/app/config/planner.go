package config

import (
	runtimestate "github.com/netxfw/netxfw/internal/domain/runtime"
	systemstate "github.com/netxfw/netxfw/internal/domain/system"
	"github.com/netxfw/netxfw/pkg/sdk"
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

func (p *Planner) PlanConfigToRuntime(cfg *sdk.GlobalConfig, mgr sdk.ManagerInterface) Plan {
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

func (p *Planner) PlanRuntimeToConfig(mgr sdk.ManagerInterface) Plan {
	return Plan{
		Mode:   ModeRuntimeToConfig,
		Actual: runtimestate.FromManager(mgr),
	}
}

func (p *Planner) PlanVerifyAndRepair(cfg *sdk.GlobalConfig, mgr sdk.ManagerInterface) Plan {
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
