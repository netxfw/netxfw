// Package main provides main functionality.
package main

import (
	"os"

	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

func main() {
	ctx := app.BootstrapDaemon("agent")
	defer app.SyncLogger()

	if err := app.InitConfiguration(ctx); err != nil {
		logger.Get(ctx).Errorf("[ERROR] %v", err)
		os.Exit(1)
	}
	app.TestConfiguration(ctx)
	ctx = app.ReinitLoggerFromConfig(ctx)
	app.RunDaemon(ctx)
}
