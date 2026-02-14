package daemon

import (
	"context"
	"log"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

// runControlPlane handles API, Web, Log Engine, and high-level management.
// runControlPlane 处理 API、Web、日志引擎和高级管理。
func runControlPlane() {
	configPath := config.GetConfigPath()
	pidPath := config.DefaultPidPath

	log.Println("🚀 Starting netxfw in Agent (Control Plane) mode")

	if err := managePidFile(pidPath); err != nil {
		log.Fatalf("❌ %v", err)
	}
	defer removePidFile(pidPath)

	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load global config from %s: %v", configPath, err)
	}

	// Initialize Logging / 初始化日志
	logger.Init(globalCfg.Logging)

	if globalCfg.Base.EnablePprof {
		startPprof(globalCfg.Base.PprofPort)
	}

	// 1. Initialize Manager (from pinned maps) / 初始化管理器（从固定 Map）
	// In Agent mode, we expect maps to be already pinned by the Daemon.
	// 在 Agent 模式下，我们期望 Map 已经被 Daemon 固定。
	pinPath := config.GetPinPath()
	manager, err := xdp.NewManagerFromPins(pinPath)
	if err != nil {
		log.Fatalf("❌ Agent requires netxfw daemon to be running and maps pinned at %s: %v", pinPath, err)
	}
	defer manager.Close()

	// 2. Load ALL Plugins (Agent manages everything) / 加载所有插件（Agent 管理一切）
	pluginCtx := &sdk.PluginContext{
		Context: context.Background(),
		Manager: manager,
		Config:  globalCfg,
	}
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Printf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(pluginCtx); err != nil {
			log.Printf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
		defer p.Stop()
	}

	// 3. Start Web Server / 启动 Web 服务器
	if globalCfg.Web.Enabled {
		go func() {
			if err := startWebServer(globalCfg, manager); err != nil {
				log.Printf("❌ Web server failed: %v", err)
			}
		}()
	}

	// 4. Start Cleanup Loop / 启动清理循环
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runCleanupLoop(ctx, globalCfg)

	log.Println("🛡️ Agent is running.")
	waitForSignal(configPath, manager, nil) // nil means reload all / nil 表示重新加载所有内容
}
