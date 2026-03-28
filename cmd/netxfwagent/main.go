package main

import (
	"github.com/netxfw/netxfw/internal/app"
)

func main() {
	ctx := app.BootstrapDaemon("agent")
	defer app.SyncLogger()

	app.InitConfiguration(ctx)
	app.TestConfiguration(ctx)
	ctx = app.ReinitLoggerFromConfig(ctx)
	app.RunDaemon(ctx)
}
