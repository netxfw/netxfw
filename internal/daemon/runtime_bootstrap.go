package daemon

import (
	"fmt"

	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// LoadOrCreateManager loads a pinned manager or creates a new one if pins are absent.
func LoadOrCreateManager(log *zap.SugaredLogger, pinPath string, globalCfg *sdk.GlobalConfig) (*datapathprograms.Handle, error) {
	return datapathprograms.LoadOrCreateManager(log, pinPath, globalCfg)
}

// PinManager pins manager maps to the provided pin path.
func PinManager(manager *datapathprograms.Handle, pinPath string) error {
	return datapathprograms.PinManager(manager, pinPath)
}

// ResolveRuntimeInterfaces resolves interfaces from CLI override, config, or physical NIC discovery.
func ResolveRuntimeInterfaces(cliInterfaces []string, globalCfg *sdk.GlobalConfig, log *zap.SugaredLogger) ([]string, error) {
	if len(cliInterfaces) > 0 {
		log.Infof("[INFO]  Using CLI provided interfaces: %v", cliInterfaces)
		return cliInterfaces, nil
	}

	if len(globalCfg.Base.Interfaces) > 0 {
		log.Infof("[INFO]  Using configured interfaces: %v", globalCfg.Base.Interfaces)
		return globalCfg.Base.Interfaces, nil
	}

	interfaces, err := datapathprograms.GetPhysicalInterfaces()
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
func DetachOrphanedInterfaces(manager *datapathprograms.Handle, pinPath string, configuredInterfaces []string, log *zap.SugaredLogger) {
	attachedIfaces, err := datapathprograms.GetAttachedInterfaces(pinPath)
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
func ReconcileInterfaces(manager *datapathprograms.Handle, pinPath string, interfaces []string, log *zap.SugaredLogger, order InterfaceReconcileOrder) error {
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
