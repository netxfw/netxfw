package lifecycle

import (
	"context"

	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// Remove detaches XDP from selected interfaces or fully unloads pinned state
// when no interface filter is provided.
func Remove(ctx context.Context, pinPath string, cliInterfaces []string, globalCfg *sdk.GlobalConfig) error {
	log := logger.Get(ctx)

	cfg := globalCfg
	if cfg == nil {
		cfg = &sdk.GlobalConfig{}
	}

	var interfaces []string
	fullUnload := false

	if len(cliInterfaces) > 0 {
		interfaces = cliInterfaces
		log.Infof("[INFO]  Detaching from specific interfaces: %v", interfaces)
	} else {
		fullUnload = true

		uniqueInterfaces := make(map[string]bool)

		phyInterfaces, phyErr := datapathprograms.GetPhysicalInterfaces()
		if phyErr == nil {
			for _, iface := range phyInterfaces {
				uniqueInterfaces[iface] = true
			}
		}

		for _, iface := range cfg.Base.Interfaces {
			uniqueInterfaces[iface] = true
		}

		attachedIfaces, attachErr := datapathprograms.GetAttachedInterfaces(pinPath)
		if attachErr == nil {
			for _, iface := range attachedIfaces {
				uniqueInterfaces[iface] = true
			}
		}

		for iface := range uniqueInterfaces {
			interfaces = append(interfaces, iface)
		}
		log.Infof("[INFO]  Detaching from all detected interfaces: %v", interfaces)
	}

	manager, err := datapathprograms.CreateManager(cfg.Capacity, log)
	if err != nil {
		return err
	}
	defer manager.Close()

	if err := manager.Detach(interfaces); err != nil {
		log.Warnf("[WARN]  Some interfaces could not be detached: %v", err)
	}

	if fullUnload {
		if err := manager.Unpin(pinPath); err != nil {
			log.Warnf("[WARN]  Could not unpin all maps: %v", err)
		}
		log.Info("[OK] XDP driver removed and maps unpinned.")
	} else {
		log.Infof("[OK] XDP driver detached from %v", interfaces)
	}

	return nil
}

// UnloadInstructions logs the current unload guidance for foreground-loaded XDP.
func UnloadInstructions() {
	log := logger.Get(nil)
	log.Infof("[BYE] Unloading XDP and cleaning up...")
	log.Infof("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}
