package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/livp123/netxfw/internal/api"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

/**
 * installXDP initializes the XDP manager and mounts the program to interfaces, then exits.
 */
func installXDP() {
	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		log.Fatalf("❌ Failed to get interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		log.Fatal("❌ No physical interfaces found")
	}

	// Load global configuration
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
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
 * runDaemon starts the background process for metrics and rule synchronization.
 */
func runDaemon() {
	// Load global configuration
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	// Try to load manager from pins first, so we monitor the actual running firewall
	// 尝试先从固定路径加载管理器，以便监控实际运行的防火墙
	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Printf("⚠️  Could not load pinned maps, creating new manager: %v", err)
		manager, err = xdp.NewManager(globalCfg.Capacity)
		if err != nil {
			log.Fatalf("❌ Failed to create XDP manager: %v", err)
		}
		// Pin maps so CLI tools can interact with them
		if err := manager.Pin("/sys/fs/bpf/netxfw"); err != nil {
			log.Printf("⚠️  Failed to pin maps: %v", err)
		}
	}
	defer manager.Close()

	// Register and start plugins
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

	log.Println("🛡️ Daemon is running. Monitoring metrics and managing rules...")

	// Start rule cleanup loop if enabled
	if globalCfg.Base.EnableExpiry {
		interval, err := time.ParseDuration(globalCfg.Base.CleanupInterval)
		if err != nil {
			log.Printf("⚠️  Invalid cleanup_interval '%s', defaulting to 1m: %v", globalCfg.Base.CleanupInterval, err)
			interval = 1 * time.Minute
		}

		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			log.Printf("🧹 Rule cleanup enabled (Interval: %v)", interval)
			for range ticker.C {
				m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
				if err != nil {
					continue
				}
				// Cleanup all maps that support expiration
				// IPv4/IPv6 lock lists
				removed, _ := xdp.CleanupExpiredRules(m.LockList(), false)
				removed6, _ := xdp.CleanupExpiredRules(m.LockList6(), true)
				// IPv4/IPv6 whitelist
				removedW, _ := xdp.CleanupExpiredRules(m.Whitelist(), false)
				removedW6, _ := xdp.CleanupExpiredRules(m.Whitelist6(), true)
				// IP+Port rules
				removedP, _ := xdp.CleanupExpiredRules(m.IpPortRules(), false)
				removedP6, _ := xdp.CleanupExpiredRules(m.IpPortRules6(), true)

				total := removed + removed6 + removedW + removedW6 + removedP + removedP6
				if total > 0 {
					log.Printf("🧹 Cleanup: removed %d expired rules from BPF maps", total)
				}
				m.Close()
			}
		}()
	} else {
		log.Println("ℹ️  Rule cleanup is disabled in config")
	}

	// Wait for interrupt
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("👋 Daemon shutting down (XDP program remains in kernel)...")
}

/**
 * handlePluginCommand processes plugin-related CLI commands.
 */
func handlePluginCommand(args []string) {
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
 * removeXDP detaches the XDP program from all interfaces and unpins everything.
 */
func removeXDP() {
	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		log.Fatalf("❌ Failed to get interfaces: %v", err)
	}

	// Load global configuration to get max entries
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Printf("⚠️  Failed to load global config, using default map capacity: %v", err)
		globalCfg = &types.GlobalConfig{}
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
 * reloadXDP performs a hot-reload of the XDP program.
 * It loads new objects, migrates state from old pinned maps, and swaps the program.
 * reloadXDP 执行 XDP 程序的平滑重载：加载新对象，从旧的固定 Map 迁移状态，并切换程序。
 */
func reloadXDP() {
	log.Println("🔄 Starting hot-reload of XDP program...")

	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		log.Fatalf("❌ Failed to get interfaces: %v", err)
	}

	// 1. Load global configuration
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
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

	// 5. Detach old programs if they exist to avoid "resource busy" errors
	if oldManager != nil {
		log.Println("🔌 Detaching old XDP programs...")
		oldManager.Detach(interfaces)
	}

	// 6. Atomic swap (or sequential): Attach new manager to interfaces
	// This will replace the old program if it was attached
	if err := newManager.Attach(interfaces); err != nil {
		log.Fatalf("❌ Failed to attach new XDP program: %v", err)
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
 * runWebServer starts the API and UI server.
 */
func runWebServer(port int) {
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
 * unloadXDP provides instructions to unload the program.
 */
func unloadXDP() {
	log.Println("👋 Unloading XDP and cleaning up...")
	// Cleanup is handled by the server process on exit.
	log.Println("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}
