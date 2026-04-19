package lifecycle

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	datapathsync "github.com/netxfw/netxfw/internal/datapath/xdp/sync"
	"github.com/netxfw/netxfw/internal/ports"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

type InterfaceReconcileOrder int

const (
	AttachOnly InterfaceReconcileOrder = iota
	DetachBeforeAttach
	DetachAfterAttach
)

type InstallResult struct {
	Manager    *programs.Handle
	Interfaces []string
}

// ResolveInterfaces resolves interfaces from CLI override, config, or
// physical NIC discovery.
func ResolveInterfaces(cliInterfaces []string, globalCfg *sdk.GlobalConfig, log *zap.SugaredLogger) ([]string, error) {
	if len(cliInterfaces) > 0 {
		log.Infof("[INFO]  Using CLI provided interfaces: %v", cliInterfaces)
		return cliInterfaces, nil
	}

	if len(globalCfg.Base.Interfaces) > 0 {
		log.Infof("[INFO]  Using configured interfaces: %v", globalCfg.Base.Interfaces)
		return globalCfg.Base.Interfaces, nil
	}

	interfaces, err := programs.GetPhysicalInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no physical interfaces found")
	}
	log.Infof("[INFO]  Auto-detected interfaces: %v", interfaces)
	return interfaces, nil
}

// Install loads or creates the datapath manager, syncs config, and reconciles
// interface attachments.
func Install(ctx context.Context, pinPath string, cliInterfaces []string, globalCfg *sdk.GlobalConfig, log *zap.SugaredLogger) (*InstallResult, error) {
	_ = ctx

	interfaces, err := ResolveInterfaces(cliInterfaces, globalCfg, log)
	if err != nil {
		return nil, err
	}

	manager, err := programs.LoadOrCreateManager(log, pinPath, globalCfg)
	if err != nil {
		return nil, err
	}

	if err := programs.PinManager(manager, pinPath); err != nil {
		return nil, fmt.Errorf("failed to pin maps: %v", err)
	}

	log.Infof("[SYNC] Syncing global config and loading persisted rules...")
	syncMgr := ports.SDKConfigReconcilerAdapter{ManagerInterface: programs.NewAdapter(manager)}
	if err := datapathsync.SyncConfigToRuntime(syncMgr, ports.ConfigFromSDK(globalCfg), false); err != nil {
		log.Warnf("[WARN]  Failed to sync config and load rules: %v (continuing anyway)", err)
	}

	if err := ReconcileInterfaces(manager, pinPath, interfaces, log, DetachAfterAttach); err != nil {
		return nil, fmt.Errorf("failed to attach XDP: %v", err)
	}

	return &InstallResult{
		Manager:    manager,
		Interfaces: interfaces,
	}, nil
}

// DetachOrphanedInterfaces detaches XDP from interfaces no longer desired.
func DetachOrphanedInterfaces(manager *programs.Handle, pinPath string, configuredInterfaces []string, log *zap.SugaredLogger) {
	attachedIfaces, err := programs.GetAttachedInterfaces(pinPath)
	if err != nil {
		return
	}

	var toDetach []string
	for _, attached := range attachedIfaces {
		found := false
		for _, configured := range configuredInterfaces {
			if attached == configured {
				found = true
				break
			}
		}
		if !found {
			toDetach = append(toDetach, attached)
		}
	}

	if len(toDetach) > 0 {
		log.Infof("[INFO]  Detaching from removed interfaces: %v", toDetach)
		if err := manager.Detach(toDetach); err != nil {
			log.Warnf("[WARN]  Failed to detach from removed interfaces: %v", err)
		}
	}
}

// ReconcileInterfaces applies attach/detach in the caller-selected order.
func ReconcileInterfaces(manager *programs.Handle, pinPath string, interfaces []string, log *zap.SugaredLogger, order InterfaceReconcileOrder) error {
	switch order {
	case DetachBeforeAttach:
		DetachOrphanedInterfaces(manager, pinPath, interfaces, log)
		return manager.Attach(interfaces)
	case DetachAfterAttach:
		if err := manager.Attach(interfaces); err != nil {
			return err
		}
		DetachOrphanedInterfaces(manager, pinPath, interfaces, log)
		return nil
	default:
		return manager.Attach(interfaces)
	}
}
