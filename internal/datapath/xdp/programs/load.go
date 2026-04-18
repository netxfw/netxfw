package programs

import (
	"fmt"

	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// LoadOrCreateManager loads pinned maps first and falls back to creating a new
// manager when the datapath is not initialized yet.
func LoadOrCreateManager(log *zap.SugaredLogger, pinPath string, globalCfg *sdk.GlobalConfig) (*backendxdp.Manager, error) {
	manager, err := backendxdp.NewManagerFromPins(pinPath, log)
	if err == nil {
		return manager, nil
	}

	log.Info("[INFO]  Creating new XDP manager...")
	manager, err = backendxdp.NewManager(globalCfg.Capacity, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create XDP manager: %v", err)
	}
	if err := PinManager(manager, pinPath); err != nil {
		log.Warnf("[WARN]  Failed to pin maps: %v", err)
	}
	return manager, nil
}

// PinManager persists manager maps under the provided pin path.
func PinManager(manager *backendxdp.Manager, pinPath string) error {
	return manager.Pin(pinPath)
}
