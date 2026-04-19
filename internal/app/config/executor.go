package config

import (
	"fmt"

	datapathsync "github.com/netxfw/netxfw/internal/datapath/xdp/sync"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	"github.com/netxfw/netxfw/internal/ports"
)

type runtimeSyncPort = ports.DatapathSyncer

type Executor struct{}

func NewExecutor() *Executor {
	return &Executor{}
}

func (e *Executor) Execute(plan Plan, mgr runtimeSyncPort, cfg *domainconfig.Config) error {
	if mgr == nil {
		return fmt.Errorf("manager is nil")
	}

	switch plan.Mode {
	case ModeConfigToRuntime:
		return datapathsync.SyncConfigToRuntime(mgr, cfg, plan.Overwrite)
	case ModeRuntimeToConfig:
		return datapathsync.SyncRuntimeToConfig(mgr, cfg)
	case ModeVerifyAndRepair:
		return datapathsync.VerifyRuntimeConfig(mgr, cfg)
	default:
		return fmt.Errorf("unknown reconcile mode: %s", plan.Mode)
	}
}
