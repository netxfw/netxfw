package core

import (
	"log"
	_ "net/http/pprof"
	"strconv"

	"github.com/livp123/netxfw/internal/api"
	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/livp123/netxfw/internal/xdp"
)

/**
 * InstallXDP initializes the XDP manager and mounts the program to interfaces, then exits.
 */
func InstallXDP() {
	// Load global configuration first to get interface settings
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	var interfaces []string
	if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
		log.Printf("ℹ️  Using configured interfaces: %v", interfaces)
	} else {
		// Auto-detect if no interfaces configured
		interfaces, err = xdp.GetPhysicalInterfaces()
		if err != nil {
			log.Fatalf("❌ Failed to get interfaces: %v", err)
		}
		if len(interfaces) == 0 {
			log.Fatal("❌ No physical interfaces found")
		}
		log.Printf("ℹ️  Auto-detected interfaces: %v", interfaces)
	}

	manager, err := xdp.NewManager(globalCfg.Capacity)
	if err != nil {
		log.Fatalf("❌ Failed to create XDP manager: %v", err)
	}

	if err := manager.Pin("/sys/fs/bpf/netxfw"); err != nil {
		log.Fatalf("❌ Failed to pin maps: %v", err)
	}

	if err := manager.Attach(interfaces); err != nil {
		log.Fatalf("❌ Failed to attach XDP: %v", err)
	}

	// Detach from interfaces that are not in the current configuration
	// 移除未在当前配置中的接口上的 XDP
	if attachedIfaces, err := xdp.GetAttachedInterfaces("/sys/fs/bpf/netxfw"); err == nil {
		var toDetach []string
		for _, attached := range attachedIfaces {
			found := false
			for _, configured := range interfaces {
				if attached == configured {
					found = true
					break
				}
			}
			if !found {
				toDetach = append(toDetach, attached)
			}
		}
		if len(toDetach) > 0 {
			log.Printf("ℹ️  Detaching from removed interfaces: %v", toDetach)
			if err := manager.Detach(toDetach); err != nil {
				log.Printf("⚠️  Failed to detach from removed interfaces: %v", err)
			}
		}
	}

	// Start all plugins to apply configurations
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

	log.Println("🚀 XDP program installed successfully and pinned to /sys/fs/bpf/netxfw")
}

/**
 * RunDaemon starts the background process for metrics and rule synchronization.
 */
func RunDaemon() {
	InitConfiguration()
	TestConfiguration()
	daemon.Run(runtime.Mode)
}

/**
 * HandlePluginCommand processes plugin-related CLI commands.
 */
func HandlePluginCommand(args []string) {
	if len(args) < 1 {
		log.Println("Usage: netxfw plugin <load|remove> ...")
		return
	}

	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	switch args[0] {
	case "load":
		if len(args) < 3 {
			log.Fatal("Usage: netxfw plugin load <path_to_elf> <index (2-15)>")
		}
		path := args[1]
		idx, err := strconv.Atoi(args[2])
		if err != nil {
			log.Fatalf("❌ Invalid index: %v", err)
		}
		if err := manager.LoadPlugin(path, idx); err != nil {
			log.Fatalf("❌ Failed to load plugin: %v", err)
		}
	case "remove":
		if len(args) < 2 {
			log.Fatal("Usage: netxfw plugin remove <index (2-15)>")
		}
		idx, err := strconv.Atoi(args[1])
		if err != nil {
			log.Fatalf("❌ Invalid index: %v", err)
		}
		if err := manager.RemovePlugin(idx); err != nil {
			log.Fatalf("❌ Failed to remove plugin: %v", err)
		}
	default:
		log.Printf("Unknown plugin command: %s", args[0])
	}
}

/**
 * RemoveXDP detaches the XDP program from all interfaces and unpins everything.
 */
func RemoveXDP() {
	// Collect all potential interfaces to detach from
	uniqueInterfaces := make(map[string]bool)

	// 1. Get physical interfaces
	if phyInterfaces, err := xdp.GetPhysicalInterfaces(); err == nil {
		for _, iface := range phyInterfaces {
			uniqueInterfaces[iface] = true
		}
	} else {
		log.Printf("⚠️  Failed to get physical interfaces: %v", err)
	}

	// 2. Get configured interfaces
	// Load global configuration to get max entries and interfaces
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Printf("⚠️  Failed to load global config, using default map capacity: %v", err)
		globalCfg = &types.GlobalConfig{}
	} else {
		for _, iface := range globalCfg.Base.Interfaces {
			uniqueInterfaces[iface] = true
		}
	}

	var interfaces []string
	for iface := range uniqueInterfaces {
		interfaces = append(interfaces, iface)
	}

	if len(interfaces) == 0 {
		log.Println("⚠️  No interfaces found to detach from.")
	} else {
		log.Printf("ℹ️  Detaching from interfaces: %v", interfaces)
	}

	manager, err := xdp.NewManager(globalCfg.Capacity)
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager for removal: %v", err)
	}
	defer manager.Close()

	if err := manager.Detach(interfaces); err != nil {
		log.Printf("⚠️  Some interfaces failed to detach: %v", err)
	}

	if err := manager.Unpin("/sys/fs/bpf/netxfw"); err != nil {
		log.Printf("⚠️  Unpin warning: %v", err)
	}

	log.Println("✅ XDP program removed and cleanup completed.")
}

/**
 * ReloadXDP performs a hot-reload of the XDP program.
 * It loads new objects, migrates state from old pinned maps, and swaps the program.
 * ReloadXDP 执行 XDP 程序的平滑重载：加载新对象，从旧的固定 Map 迁移状态，并切换程序。
 */
func ReloadXDP() {
	log.Println("🔄 Starting hot-reload of XDP program...")

	// 1. Load global configuration
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	var interfaces []string
	if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
		log.Printf("ℹ️  Using configured interfaces: %v", interfaces)
	} else {
		interfaces, err = xdp.GetPhysicalInterfaces()
		if err != nil {
			log.Fatalf("❌ Failed to get interfaces: %v", err)
		}
		log.Printf("ℹ️  Auto-detected interfaces: %v", interfaces)
	}

	// 2. Initialize new manager with new capacities
	newManager, err := xdp.NewManager(globalCfg.Capacity)
	if err != nil {
		log.Fatalf("❌ Failed to create new XDP manager: %v", err)
	}

	// 3. Try to load old manager from pins to migrate state
	oldManager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err == nil {
		log.Println("📦 Migrating state from old BPF maps...")
		if err := newManager.MigrateState(oldManager); err != nil {
			log.Printf("⚠️  State migration partial or failed: %v", err)
		}
		oldManager.Close()
	} else {
		log.Println("ℹ️  No existing pinned maps found, starting fresh.")
	}

	// 4. Update pins: Pin new maps (this ensures the directory exists for Attach)
	if err := newManager.Pin("/sys/fs/bpf/netxfw"); err != nil {
		log.Fatalf("❌ Failed to pin new maps: %v", err)
	}

	// 5. Atomic swap: Attach new manager to interfaces
	// This will atomically replace the program if a pinned link exists
	if err := newManager.Attach(interfaces); err != nil {
		log.Fatalf("❌ Failed to attach new XDP program: %v", err)
	}

	// Detach from interfaces that are not in the current configuration
	// 移除未在当前配置中的接口上的 XDP
	if attachedIfaces, err := xdp.GetAttachedInterfaces("/sys/fs/bpf/netxfw"); err == nil {
		var toDetach []string
		for _, attached := range attachedIfaces {
			found := false
			for _, configured := range interfaces {
				if attached == configured {
					found = true
					break
				}
			}
			if !found {
				toDetach = append(toDetach, attached)
			}
		}
		if len(toDetach) > 0 {
			log.Printf("ℹ️  Detaching from removed interfaces: %v", toDetach)
			if err := newManager.Detach(toDetach); err != nil {
				log.Printf("⚠️  Failed to detach from removed interfaces: %v", err)
			}
		}
	}

	// 6. Start all plugins to apply configurations
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(globalCfg); err != nil {
			log.Printf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(newManager); err != nil {
			log.Printf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
		// Note: We don't defer Stop() here because reload is a one-shot command
	}

	log.Println("🚀 XDP program reloaded successfully with updated configuration and capacity.")
}

/**
 * RunWebServer starts the API and UI server.
 */
func RunWebServer(port int) {
	// 1. Try to load manager from pins
	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Printf("⚠️  Could not load pinned maps (is XDP loaded?): %v", err)
		log.Fatal("❌ Web server requires netxfw XDP to be loaded. Run 'netxfw system load' first.")
	}
	defer manager.Close()

	// 2. Start API server
	server := api.NewServer(manager, port)
	if err := server.Start(); err != nil {
		log.Fatalf("❌ Failed to start web server: %v", err)
	}
}

/**
 * UnloadXDP provides instructions to unload the program.
 */
func UnloadXDP() {
	log.Println("👋 Unloading XDP and cleaning up...")
	// Cleanup is handled by the server process on exit.
	log.Println("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}
