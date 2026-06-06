package programs

import (
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// LoadOrCreateManager loads pinned maps first and falls back to creating a new
// manager when the datapath is not initialized yet.
func LoadOrCreateManager(log *zap.SugaredLogger, pinPath string, globalCfg *sdk.GlobalConfig) (*Handle, error) {
	manager, err := OpenPinnedManager(pinPath, log)
	if err == nil {
		if globalCfg == nil || manager.MatchesCapacity(globalCfg.Capacity) {
			return manager, nil
		}

		log.Info("[DATA] Pinned XDP map capacity differs from config. Recreating maps...")
		oldManager := manager
		manager, err = CreateManager(globalCfg.Capacity, log)
		if err != nil {
			_ = oldManager.Close()
			return nil, err
		}
		if err := MigrateState(manager, oldManager); err != nil {
			log.Warnf("[WARN]  State transfer partial or failed: %v", err)
		}
		_ = oldManager.Close()
		if err := PinManager(manager, pinPath); err != nil {
			log.Warnf("[WARN]  Failed to pin maps: %v", err)
		}
		return manager, nil
	}

	log.Info("[INFO]  Creating new XDP manager...")
	manager, err = CreateManager(globalCfg.Capacity, log)
	if err != nil {
		return nil, err
	}
	if err := PinManager(manager, pinPath); err != nil {
		log.Warnf("[WARN]  Failed to pin maps: %v", err)
	}
	return manager, nil
}

// PinManager persists manager maps under the provided pin path.
func PinManager(manager *Handle, pinPath string) error {
	return manager.Pin(pinPath)
}
