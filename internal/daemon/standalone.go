package daemon

import (
	"context"
	"log"

	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
)

// runStandalone runs the legacy full-stack mode.
// runStandalone 运行传统的全栈模式。
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

	// Initialize Logging / 初始化日志
	logger.Init(globalCfg.Logging)

	if globalCfg.Base.EnablePprof {
		startPprof(globalCfg.Base.PprofPort)
	}

	// 1. Initialize Manager / 初始化管理器
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

	// 2. Attach Interfaces / 附加接口
	var interfaces []string
	if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
	} else {
		interfaces, _ = xdp.GetPhysicalInterfaces()
	}

	if len(interfaces) > 0 {
		// Clean up removed interfaces first / 首先清理已删除的接口
		cleanupOrphanedInterfaces(manager, interfaces)
		if err := manager.Attach(interfaces); err != nil {
			log.Fatalf("❌ Failed to attach XDP: %v", err)
		}
	}

	// 3. Load ALL Plugins / 加载所有插件
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

	// 4. Start Web Server / 启动 Web 服务器
	if globalCfg.Web.Enabled {
		go func() {
			if err := startWebServer(globalCfg, manager); err != nil {
				log.Printf("❌ Web server failed: %v", err)
			}
		}()
	}

	// 5. Start Cleanup Loop / 启动清理循环
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runCleanupLoop(ctx, globalCfg)

	log.Println("🛡️ Daemon is running (Standalone).")
	waitForSignal(configPath, manager, nil)
}
