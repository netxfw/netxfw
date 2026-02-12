package daemon

import (
	"context"
	"log"

	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

// runStandalone runs the legacy full-stack mode.
func runStandalone() {
	const configPath = "/etc/netxfw/config.yaml"
	const pidPath = defaultPidFile

	if err := managePidFile(pidPath); err != nil {
		log.Fatalf("❌ %v", err)
	}
	defer removePidFile(pidPath)

	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	if globalCfg.Base.EnablePprof {
		startPprof(globalCfg.Base.PprofPort)
	}

	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Printf("ℹ️  Creating new XDP manager...")
		manager, err = xdp.NewManager(globalCfg.Capacity)
		if err != nil {
			log.Fatalf("❌ Failed to create XDP manager: %v", err)
		}
		if err := manager.Pin("/sys/fs/bpf/netxfw"); err != nil {
			log.Printf("⚠️  Failed to pin maps: %v", err)
		}
	}
	defer manager.Close()

	// Attach Interfaces
	var interfaces []string
	if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
	} else {
		interfaces, _ = xdp.GetPhysicalInterfaces()
	}

	if len(interfaces) > 0 {
		// Clean up removed interfaces first
		cleanupOrphanedInterfaces(manager, interfaces)
		if err := manager.Attach(interfaces); err != nil {
			log.Fatalf("❌ Failed to attach XDP: %v", err)
		}
	}

	// Load ALL Plugins
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

	if globalCfg.Web.Enabled {
		go func() {
			if err := startWebServer(globalCfg, manager); err != nil {
				log.Printf("❌ Web server failed: %v", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runCleanupLoop(ctx, globalCfg)

	log.Println("🛡️ Daemon is running (Standalone).")
	waitForSignal(configPath, manager, nil)
}
