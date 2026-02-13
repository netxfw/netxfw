package daemon

import (
	"context"
	"log"

	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
)

// runControlPlane handles API, Web, Log Engine, and high-level management.
// runControlPlane 处理 API、Web、日志引擎和高级管理。
func runControlPlane() {
	const configPath = "/etc/netxfw/config.yaml"
	const pidPath = "/var/run/netxfw-agent.pid"

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

	// 1. Connect to Existing BPF Maps / 连接到现有的 BPF Map
	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to load pinned maps. Is the Data Plane (DP) running? Error: %v", err)
	}
	defer manager.Close()

	// 2. Load ALL Plugins (Agent manages everything) / 加载所有插件（Agent 管理一切）
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
