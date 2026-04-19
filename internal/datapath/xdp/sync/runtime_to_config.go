package sync

import (
	"fmt"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
)

// SyncRuntimeToConfig captures runtime state back into config through the datapath sync facade.
func SyncRuntimeToConfig(mgr RuntimeSyncPort, cfg *domainconfig.Config) error {
	if mgr == nil {
		return fmt.Errorf("manager is nil")
	}
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	return mgr.SyncToFiles(cfg)
}
