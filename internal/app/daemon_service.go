package app

import (
	"context"

	"github.com/netxfw/netxfw/internal/daemon"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// TestConfiguration validates the current configuration.
func TestConfiguration(ctx context.Context) bool {
	return daemon.TestConfiguration(ctx)
}

// RunDaemon starts the background process for metrics and rule synchronization.
func RunDaemon(ctx context.Context) {
	if err := InitConfiguration(ctx); err != nil {
		logger.Get(ctx).Errorf("[ERROR] %v", err)
		return
	}
	TestConfiguration(ctx)
	daemon.Run(ctx, runtime.Mode, nil)
}

// RunDaemonWithInterfaces starts the background process with specific interfaces.
func RunDaemonWithInterfaces(ctx context.Context, interfaces []string) {
	if err := InitConfiguration(ctx); err != nil {
		logger.Get(ctx).Errorf("[ERROR] %v", err)
		return
	}
	TestConfiguration(ctx)
	opts := &daemon.DaemonOptions{Interfaces: interfaces}
	daemon.Run(ctx, runtime.Mode, opts)
}
