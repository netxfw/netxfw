package daemon

import (
	"context"
	"fmt"
	"log"
	"net/http"
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

const defaultPidFile = "/var/run/netxfw.pid"

func managePidFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("PID file %s already exists. Is netxfw already running?", path)
	}
	pid := os.Getpid()
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("failed to write PID file: %v", err)
	}
	return nil
}

func removePidFile(path string) {
	if err := os.Remove(path); err != nil {
		log.Printf("⚠️  Failed to remove PID file: %v", err)
	}
}

func startPprof(port int) {
	addr := fmt.Sprintf(":%d", port)
	log.Printf("📊 Pprof enabled on %s", addr)
	go func() {
		log.Println(http.ListenAndServe(addr, nil))
	}()
}

func startWebServer(globalCfg *types.GlobalConfig, manager *xdp.Manager) error {
	// Start API server
	server := api.NewServer(manager, globalCfg.Web.Port)
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start web server: %v", err)
	}
	return nil
}

func cleanupOrphanedInterfaces(manager *xdp.Manager, configuredInterfaces []string) {
	if attachedIfaces, err := xdp.GetAttachedInterfaces("/sys/fs/bpf/netxfw"); err == nil {
		var toDetach []string
		for _, attached := range attachedIfaces {
			found := false
			for _, configured := range configuredInterfaces {
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
}

func waitForSignal(configPath string, manager *xdp.Manager, allowedPlugins []string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		s := <-sig
		if s == syscall.SIGHUP {
			log.Println("🔄 Received SIGHUP, reloading configuration...")
			globalCfg, err := types.LoadGlobalConfig(configPath)
			if err != nil {
				log.Printf("❌ Failed to reload config: %v", err)
				continue
			}

			// Reload plugins
			for _, p := range plugins.GetPlugins() {
				// Filter if allowedPlugins is set (DP mode)
				if allowedPlugins != nil {
					found := false
					for _, name := range allowedPlugins {
						if p.Name() == name {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}

				if err := p.Reload(globalCfg, manager); err != nil {
					log.Printf("⚠️  Failed to reload plugin %s: %v", p.Name(), err)
				}
			}

			// If in DP mode (allowedPlugins != nil) or Standalone, re-check interfaces
			if allowedPlugins != nil || len(allowedPlugins) == 0 {
				// Interface re-attach logic could be added here if needed
			}

			log.Println("✅ Configuration reloaded")
		} else {
			log.Println("👋 Daemon shutting down...")
			break
		}
	}
}

func runCleanupLoop(ctx context.Context, globalCfg *types.GlobalConfig) {
	if !globalCfg.Base.EnableExpiry {
		log.Println("ℹ️  Rule cleanup is disabled in config")
		return
	}

	interval, err := time.ParseDuration(globalCfg.Base.CleanupInterval)
	if err != nil {
		log.Printf("⚠️  Invalid cleanup_interval '%s', defaulting to 1m: %v", globalCfg.Base.CleanupInterval, err)
		interval = 1 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("🧹 Rule cleanup enabled (Interval: %v)", interval)

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Stopping cleanup loop")
			return
		case <-ticker.C:
			m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
			if err != nil {
				continue
			}
			// Cleanup all maps that support expiration
			removed, _ := xdp.CleanupExpiredRules(m.LockList(), false)
			removed6, _ := xdp.CleanupExpiredRules(m.LockList6(), true)
			removedW, _ := xdp.CleanupExpiredRules(m.Whitelist(), false)
			removedW6, _ := xdp.CleanupExpiredRules(m.Whitelist6(), true)
			removedP, _ := xdp.CleanupExpiredRules(m.IpPortRules(), false)
			removedP6, _ := xdp.CleanupExpiredRules(m.IpPortRules6(), true)

			total := removed + removed6 + removedW + removedW6 + removedP + removedP6
			if total > 0 {
				log.Printf("🧹 Cleanup: removed %d expired rules from BPF maps", total)
			}
			m.Close()
		}
	}
}
