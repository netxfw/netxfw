package daemon

import (
	"context"

	"github.com/livp123/netxfw/internal/utils/logger"
)

// Run starts the daemon in the specified mode.
// Run 以指定模式启动守护进程。
func Run(ctx context.Context, mode string, opts *DaemonOptions) {
	log := logger.Get(ctx)
	if opts == nil {
		opts = &DaemonOptions{}
	}

	switch mode {
	case "dp":
		runDataPlane(ctx)
	case "agent":
		runControlPlane(ctx, opts)
	default:
		log.Info("ℹ️  No mode specified, running in Unified mode")
		runUnified(ctx)
	}
}
