package daemon

import "log"

// Run starts the daemon in the specified mode.
func Run(mode string) {
	switch mode {
	case "dp":
		runDataPlane()
	case "agent":
		runControlPlane()
	default:
		log.Println("ℹ️  No mode specified, running in Standalone (Hybrid) mode")
		runStandalone()
	}
}
