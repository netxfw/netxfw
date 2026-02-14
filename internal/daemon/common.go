package daemon

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/livp123/netxfw/internal/api"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

// managePidFile ensures only one instance of the daemon is running by checking/writing a PID file.
// managePidFile 通过检查/编写 PID 文件来确保只有一个守护进程实例在运行。
func managePidFile(path string) error {
	if content, err := os.ReadFile(path); err == nil {
		pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
		if err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				if err := process.Signal(syscall.Signal(0)); err == nil {
					return fmt.Errorf("PID file %s exists and process %d is running", path, pid)
				}
			}
		}
		// PID file exists but process is dead or invalid, remove it / PID 文件存在但进程已死或无效，将其删除
		log.Printf("⚠️  Removing stale PID file: %s", path)
		_ = os.Remove(path)
	}

	pid := os.Getpid()
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("failed to write PID file: %v", err)
	}
	return nil
}

// removePidFile deletes the PID file on shutdown.
// removePidFile 在关机时删除 PID 文件。
func removePidFile(path string) {
	if err := os.Remove(path); err != nil {
		log.Printf("⚠️  Failed to remove PID file: %v", err)
	}
}

// startPprof starts the Go pprof server for profiling.
// startPprof 启动用于分析的 Go pprof 服务器。
func startPprof(port int) {
	addr := fmt.Sprintf(":%d", port)
	log.Printf("📊 Pprof enabled on %s", addr)
	go func() {
		log.Println(http.ListenAndServe(addr, nil))
	}()
}

// startWebServer launches the REST API server.
// startWebServer 启动 REST API 服务器。
func startWebServer(globalCfg *types.GlobalConfig, manager *xdp.Manager) error {
	// Start API server / 启动 API 服务器
	server := api.NewServer(manager, globalCfg.Web.Port)
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start web server: %v", err)
	}
	return nil
}

// cleanupOrphanedInterfaces detaches XDP programs from interfaces no longer in config.
// cleanupOrphanedInterfaces 从不再配置中的接口分离 XDP 程序。
func cleanupOrphanedInterfaces(manager *xdp.Manager, configuredInterfaces []string) {
	if attachedIfaces, err := xdp.GetAttachedInterfaces(config.GetPinPath()); err == nil {
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

// waitForSignal waits for OS signals like SIGINT or SIGHUP for graceful shutdown or reload.
// waitForSignal 等待 SIGINT 或 SIGHUP 等操作系统信号，以便正常关机或重新加载。
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

			// Reload plugins / 重新加载插件
			pluginCtx := &sdk.PluginContext{
				Context: context.Background(),
				Manager: manager,
				Config:  globalCfg,
			}

			for _, p := range plugins.GetPlugins() {
				// Filter if allowedPlugins is set (DP mode) / 如果设置了 allowedPlugins（DP 模式），则进行过滤
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

				if err := p.Reload(pluginCtx); err != nil {
					log.Printf("⚠️  Failed to reload plugin %s: %v", p.Name(), err)
				}
			}

			log.Println("✅ Configuration reloaded")
		} else {
			log.Println("👋 Daemon shutting down...")
			break
		}
	}
}

// runCleanupLoop periodically removes expired rules from BPF maps.
// runCleanupLoop 定期从 BPF Map 中删除过期的规则。
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
			m, err := xdp.NewManagerFromPins(config.GetPinPath())
			if err != nil {
				continue
			}
			// Cleanup all maps that support expiration / 清理所有支持过期的 Map
			removed, _ := xdp.CleanupExpiredRules(m.LockList(), false)
			removedW, _ := xdp.CleanupExpiredRules(m.Whitelist(), false)
			removedP, _ := xdp.CleanupExpiredRules(m.IpPortRules(), false)

			total := removed + removedW + removedP
			if total > 0 {
				log.Printf("🧹 Cleanup: removed %d expired rules from BPF maps", total)
			}
			m.Close()
		}
	}
}
