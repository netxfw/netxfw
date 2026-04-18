package rule

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/datapath/xdp/backend"
)

func ClearBlacklist(ctx context.Context, dynamic bool) error {
	log := logger.Get(ctx)
	manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err != nil {
		return fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	if dynamic {
		return xdp.ClearBlacklistMap(manager.DynLockList())
	}
	return xdp.ClearBlacklistMap(manager.LockList())
}
