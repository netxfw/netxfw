package app

import (
	"context"

	"github.com/netxfw/netxfw/internal/core"
	"github.com/netxfw/netxfw/internal/daemon"
	"github.com/netxfw/netxfw/internal/runtime"
)

// InitConfiguration initializes the default configuration file if needed.
func InitConfiguration(ctx context.Context) {
	core.InitConfiguration(ctx)
}

// TestConfiguration validates the current configuration.
func TestConfiguration(ctx context.Context) {
	daemon.TestConfiguration(ctx)
}

// RunDaemon starts the background process for metrics and rule synchronization.
func RunDaemon(ctx context.Context) {
	InitConfiguration(ctx)
	TestConfiguration(ctx)
	daemon.Run(ctx, runtime.Mode, nil)
}

// RunDaemonWithInterfaces starts the background process with specific interfaces.
func RunDaemonWithInterfaces(ctx context.Context, interfaces []string) {
	InitConfiguration(ctx)
	TestConfiguration(ctx)
	opts := &daemon.DaemonOptions{Interfaces: interfaces}
	daemon.Run(ctx, runtime.Mode, opts)
}
