package rule

import (
	"context"

	datapathmaps "github.com/netxfw/netxfw/internal/datapath/xdp/maps"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

func ClearBlacklist(ctx context.Context, dynamic bool) error {
	log := logger.Get(ctx)
	return datapathmaps.ClearPinnedBlacklist(runtime.GetPinPath(), dynamic, log)
}
