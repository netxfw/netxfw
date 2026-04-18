package sync

import (
	"fmt"

	"github.com/netxfw/netxfw/pkg/sdk"
)

// SyncRuntimeToConfig captures runtime state back into config through the datapath sync facade.
func SyncRuntimeToConfig(mgr RuntimeSyncPort, cfg *sdk.GlobalConfig) error {
	if mgr == nil {
		return fmt.Errorf("manager is nil")
	}
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	return mgr.SyncToFiles(cfg)
}
