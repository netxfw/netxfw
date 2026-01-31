package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/livp123/netxfw/internal/plugins"
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

	manager, err := xdp.NewManager()
	if err != nil {
		log.Fatalf("❌ Failed to create XDP manager: %v", err)
	}

	if err := manager.Pin("/sys/fs/bpf/netxfw"); err != nil {
		log.Fatalf("❌ Failed to pin maps: %v", err)
	}

	if err := manager.Attach(interfaces); err != nil {
		log.Fatalf("❌ Failed to attach XDP: %v", err)
	}

	// Load global configuration
	globalCfg, err := LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
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
	manager, err := xdp.NewManager()
	if err != nil {
		log.Fatalf("❌ Failed to create XDP manager: %v", err)
	}

	// Load global configuration
	globalCfg, err := LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("👋 Daemon shutting down (XDP program remains in kernel)...")
}

/**
 * removeXDP detaches the XDP program from all interfaces and unpins everything.
 */
func removeXDP() {
	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		log.Fatalf("❌ Failed to get interfaces: %v", err)
	}

	manager, err := xdp.NewManager()
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
 * unloadXDP provides instructions to unload the program.
 */
func unloadXDP() {
	log.Println("👋 Unloading XDP and cleaning up...")
	// Cleanup is handled by the server process on exit.
	log.Println("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}
