package plugins

import (
	"context"
	"fmt"

	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
	"github.com/netxfw/netxfw/internal/utils/logger"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
)

// ExecutePinned runs a datapath plugin lifecycle command against the pinned manager.
func ExecutePinned(ctx context.Context, pinPath string, cmd domaindatapath.Command) error {
	log := logger.Get(ctx)

	manager, err := backendxdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		return fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	switch cmd.Action {
	case "load":
		if err := Load(manager, cmd.Path, cmd.Index); err != nil {
			return fmt.Errorf("failed to load plugin: %v", err)
		}
	case "remove":
		if err := Remove(manager, cmd.Index); err != nil {
			return fmt.Errorf("failed to remove plugin: %v", err)
		}
	default:
		return fmt.Errorf("unknown plugin command: %s", cmd.Action)
	}

	log.Infof("[OK] Datapath plugin command %s executed successfully", cmd.Action)
	return nil
}

// ListPinned returns the current datapath plugin slots from the pinned manager.
func ListPinned(ctx context.Context, pinPath string) ([]domaindatapath.SlotStatus, error) {
	log := logger.Get(ctx)

	manager, err := backendxdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	return ListSlots(manager)
}
