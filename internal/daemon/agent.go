package daemon

import (
	"context"
	"log"

	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

// runControlPlane handles API, Web, Log Engine, and high-level management.
func runControlPlane() {
	const configPath = "/etc/netxfw/config.yaml"
	const pidPath = "/var/run/netxfw-agent.pid"

	log.Println("🚀 Starting netxfw in Agent (Control Plane) mode")

	if err := managePidFile(pidPath); err != nil {
		log.Fatalf("❌ %v", err)
	}
	defer removePidFile(pidPath)

	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load global config from %s: %v", configPath, err)
	}

	if globalCfg.Base.EnablePprof {
		startPprof(globalCfg.Base.PprofPort)
	}

	// 1. Connect to Existing BPF Maps
	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to load pinned maps. Is the Data Plane (DP) running? Error: %v", err)
	}
	defer manager.Close()

	// 2. Load ALL Plugins (Agent manages everything)
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(globalCfg); err != nil {
			log.Printf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(manager); err != nil {
			log.Printf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
		defer p.Stop()
	}

	// 3. Start Web Server
	if globalCfg.Web.Enabled {
		go func() {
			if err := startWebServer(globalCfg, manager); err != nil {
				log.Printf("❌ Web server failed: %v", err)
			}
		}()
	}

	// 4. Start Cleanup Loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runCleanupLoop(ctx, globalCfg)

	log.Println("🛡️ Agent is running.")
	waitForSignal(configPath, manager, nil) // nil means reload all
}
