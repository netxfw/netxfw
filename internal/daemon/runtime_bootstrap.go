package daemon

import (
	"fmt"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
	"go.uber.org/zap"
)

// LoadOrCreateManager loads a pinned manager or creates a new one if pins are absent.
func LoadOrCreateManager(log *zap.SugaredLogger, pinPath string, globalCfg *types.GlobalConfig) (*xdp.Manager, error) {
	manager, err := xdp.NewManagerFromPins(pinPath, log)
	if err == nil {
		return manager, nil
	}

	log.Info("[INFO]  Creating new XDP manager...")
	manager, err = xdp.NewManager(globalCfg.Capacity, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create XDP manager: %v", err)
	}
	if err := PinManager(manager, pinPath); err != nil {
		log.Warnf("[WARN]  Failed to pin maps: %v", err)
	}
	return manager, nil
}

// PinManager pins manager maps to the provided pin path.
func PinManager(manager *xdp.Manager, pinPath string) error {
	return manager.Pin(pinPath)
}

// ResolveRuntimeInterfaces resolves interfaces from CLI override, config, or physical NIC discovery.
func ResolveRuntimeInterfaces(cliInterfaces []string, globalCfg *types.GlobalConfig, log *zap.SugaredLogger) ([]string, error) {
	if len(cliInterfaces) > 0 {
		log.Infof("[INFO]  Using CLI provided interfaces: %v", cliInterfaces)
		return cliInterfaces, nil
	}

	if len(globalCfg.Base.Interfaces) > 0 {
		log.Infof("[INFO]  Using configured interfaces: %v", globalCfg.Base.Interfaces)
		return globalCfg.Base.Interfaces, nil
	}

	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no physical interfaces found")
	}
	log.Infof("[INFO]  Auto-detected interfaces: %v", interfaces)
	return interfaces, nil
}

// DetachOrphanedInterfaces detaches XDP from interfaces no longer desired.
func DetachOrphanedInterfaces(manager *xdp.Manager, pinPath string, configuredInterfaces []string, log *zap.SugaredLogger) {
	attachedIfaces, err := xdp.GetAttachedInterfaces(pinPath)
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
func ReconcileInterfaces(manager *xdp.Manager, pinPath string, interfaces []string, log *zap.SugaredLogger, order InterfaceReconcileOrder) error {
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
