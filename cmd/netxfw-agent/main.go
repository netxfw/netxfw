package main

import (
	"log"

	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/livp123/netxfw/internal/version"
)

func main() {
	log.Printf("Starting netxfw-agent %s (Control Plane Daemon)...", version.Version)

	// Set runtime mode
	runtime.Mode = "agent"

	// Initialize configuration
	core.InitConfiguration()
	core.TestConfiguration()

	// Run the daemon logic directly
	daemon.Run(runtime.Mode)
}
