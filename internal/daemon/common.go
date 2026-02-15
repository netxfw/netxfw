package daemon

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
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
		logger.Get(nil).Warnf("⚠️  Removing stale PID file: %s", path)
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
		logger.Get(nil).Warnf("⚠️  Failed to remove PID file: %v", err)
	}
}

// startPprof starts the Go pprof server for profiling.
// startPprof 启动用于分析的 Go pprof 服务器。
func startPprof(port int) {
	addr := fmt.Sprintf(":%d", port)
	logger.Get(nil).Infof("📊 Pprof enabled on %s", addr)
	go func() {
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			logger.Get(nil).Errorf("❌ Pprof server error: %v", err)
		}
	}()
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
			logger.Get(nil).Infof("ℹ️  Detaching from removed interfaces: %v", toDetach)
			if err := manager.Detach(toDetach); err != nil {
				logger.Get(nil).Warnf("⚠️  Failed to detach from removed interfaces: %v", err)
			}
		}
	}
}

// waitForSignal blocks until a termination signal is received.
// waitForSignal 阻塞直到接收到终止信号。
func waitForSignal(ctx context.Context, configPath string, s *sdk.SDK, reloadFunc func() error, stopFunc func()) {

	log := logger.Get(ctx)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sigVal := <-sig
		if sigVal == syscall.SIGHUP {
			log.Info("🔄 Received SIGHUP, reloading configuration...")

			if reloadFunc != nil {
				if err := reloadFunc(); err != nil {
					log.Errorf("❌ Failed to reload: %v", err)
				} else {
					log.Info("✅ Configuration reloaded")
				}
			} else {
				log.Warn("⚠️  No reload function provided")
			}

		} else {
			log.Info("👋 Daemon shutting down...")
			if stopFunc != nil {
				stopFunc()
			}
			break
		}
	}
}

// runCleanupLoop periodically removes expired rules from BPF maps.
// runCleanupLoop 定期从 BPF Map 中删除过期的规则。
func runCleanupLoop(ctx context.Context, globalCfg *types.GlobalConfig) {
	log := logger.Get(ctx)
	if !globalCfg.Base.EnableExpiry {
		log.Info("ℹ️  Rule cleanup is disabled in config")
		return
	}

	interval, err := time.ParseDuration(globalCfg.Base.CleanupInterval)
	if err != nil {
		log.Warnf("⚠️  Invalid cleanup_interval '%s', defaulting to 1m: %v", globalCfg.Base.CleanupInterval, err)
		interval = 1 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Infof("🧹 Rule cleanup enabled (Interval: %v)", interval)

	for {
		select {
		case <-ctx.Done():
			log.Info("🛑 Stopping cleanup loop")
			return
		case <-ticker.C:
			m, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
			if err != nil {
				continue
			}
			// Cleanup all maps that support expiration / 清理所有支持过期的 Map
			removed, _ := xdp.CleanupExpiredRules(m.LockList(), false)
			removedW, _ := xdp.CleanupExpiredRules(m.Whitelist(), false)
			removedP, _ := xdp.CleanupExpiredRules(m.IPPortRules(), false)

			total := removed + removedW + removedP
			if total > 0 {
				log.Infof("🧹 Cleanup: removed %d expired rules from BPF maps", total)
			}
			m.Close()
		}
	}
}
