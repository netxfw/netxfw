package daemon

import (
	"context"
	"github.com/livp123/netxfw/internal/utils/logger"
)

// Run starts the daemon in the specified mode.
func Run(ctx context.Context, mode string) {
	log := logger.Get(ctx)
	switch mode {
	case "dp":
		runDataPlane(ctx)
	case "agent":
		runControlPlane(ctx)
	default:
		log.Info("ℹ️  No mode specified, running in Unified mode")
		runUnified(ctx)
	}
}
