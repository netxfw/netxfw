package daemon

import (
	"log"

	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
)

// runDataPlane handles XDP mounting, BPF map initialization, and core packet processing plugins.
func runDataPlane() {
	const configPath = "/etc/netxfw/config-dp.yaml"
	const pidPath = "/var/run/netxfw-dp.pid"

	log.Println("🚀 Starting netxfw in DP (Data Plane) mode")

	if err := managePidFile(pidPath); err != nil {
		log.Fatalf("❌ %v", err)
	}
	defer removePidFile(pidPath)

	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load global config from %s: %v", configPath, err)
	}

	// Initialize Logging
	logger.Init(globalCfg.Logging)

	// 1. Initialize Manager (Create or Load Pinned)
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

	// 2. Attach to Interfaces
	var interfaces []string
	if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
		log.Printf("ℹ️  Using configured interfaces: %v", interfaces)
	} else {
		interfaces, err = xdp.GetPhysicalInterfaces()
		if err != nil {
			log.Printf("⚠️  Failed to auto-detect interfaces: %v", err)
		}
	}

	if len(interfaces) > 0 {
		if err := manager.Attach(interfaces); err != nil {
			log.Fatalf("❌ Failed to attach XDP: %v", err)
		}
		cleanupOrphanedInterfaces(manager, interfaces)
	} else {
		log.Println("⚠️  No interfaces configured for XDP attachment")
	}

	// 3. Load DP-Specific Plugins
	// DP only runs plugins that configure BPF maps or globals.
	dpPlugins := []string{"base", "conntrack", "ratelimit", "port"}
	for _, p := range plugins.GetPlugins() {
		isDpPlugin := false
		for _, name := range dpPlugins {
			if p.Name() == name {
				isDpPlugin = true
				break
			}
		}
		if !isDpPlugin {
			continue
		}

		if err := p.Init(globalCfg); err != nil {
			log.Printf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(manager); err != nil {
			log.Printf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
		defer p.Stop()
	}

	log.Println("🛡️ Data Plane is running.")
	waitForSignal(configPath, manager, dpPlugins)
}
