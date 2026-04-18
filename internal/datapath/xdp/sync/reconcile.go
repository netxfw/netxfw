package sync

import (
	"fmt"

	"github.com/netxfw/netxfw/pkg/sdk"
)

type RuntimeSyncPort interface {
	SyncFromFiles(cfg *sdk.GlobalConfig, overwrite bool) error
	SyncToFiles(cfg *sdk.GlobalConfig) error
	VerifyAndRepair(cfg *sdk.GlobalConfig) error
}

// SyncConfigToRuntime applies config to runtime through the datapath sync facade.
func SyncConfigToRuntime(mgr RuntimeSyncPort, cfg *sdk.GlobalConfig, overwrite bool) error {
	if mgr == nil {
		return fmt.Errorf("manager is nil")
	}
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	return mgr.SyncFromFiles(cfg, overwrite)
}

// VerifyRuntimeConfig applies verify-and-repair through the datapath sync facade.
func VerifyRuntimeConfig(mgr RuntimeSyncPort, cfg *sdk.GlobalConfig) error {
	if mgr == nil {
		return fmt.Errorf("manager is nil")
	}
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	return mgr.VerifyAndRepair(cfg)
}
