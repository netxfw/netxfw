package sync

import (
	"fmt"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
)

type RuntimeSyncPort interface {
	SyncFromFiles(cfg *domainconfig.Config, overwrite bool) error
	SyncToFiles(cfg *domainconfig.Config) error
	VerifyAndRepair(cfg *domainconfig.Config) error
}

// SyncConfigToRuntime applies config to runtime through the datapath sync facade.
func SyncConfigToRuntime(mgr RuntimeSyncPort, cfg *domainconfig.Config, overwrite bool) error {
	if mgr == nil {
		return fmt.Errorf("manager is nil")
	}
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	return mgr.SyncFromFiles(cfg, overwrite)
}

// VerifyRuntimeConfig applies verify-and-repair through the datapath sync facade.
func VerifyRuntimeConfig(mgr RuntimeSyncPort, cfg *domainconfig.Config) error {
	if mgr == nil {
		return fmt.Errorf("manager is nil")
	}
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	return mgr.VerifyAndRepair(cfg)
}
