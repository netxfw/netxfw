package daemon

import (
	"context"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

// runControlPlane handles API, Web, Log Engine, and high-level management.
// runControlPlane 处理 API、Web、日志引擎和高级管理。
func runControlPlane(ctx context.Context, opts *DaemonOptions) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	pidPath := config.DefaultPidPath

	log.Info("🚀 Starting netxfw in Agent (Control Plane) mode")

	if err := managePidFile(pidPath); err != nil {
		log.Fatalf("❌ %v", err)
	}
	defer removePidFile(pidPath)

	// Use the config manager to load the configuration
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err != nil {
		log.Errorf("❌ Failed to load global config from %s: %v", configPath, err)
		return
	}

	globalCfg := cfgManager.GetConfig()
	if globalCfg == nil {
		log.Errorf("❌ Config is nil after loading from %s", configPath)
		return
	}

	// Initialize Logging / 初始化日志
	logger.Init(globalCfg.Logging)

	if globalCfg.Base.EnablePprof {
		startPprof(globalCfg.Base.PprofPort)
	}

	// 1. Initialize Manager
	var manager xdp.ManagerInterface
	if opts.Manager != nil {
		log.Info("Using injected Manager (e.g. for testing)")
		manager = opts.Manager
	} else {
		// In Agent mode, we expect maps to be already pinned by the Daemon.
		// 在 Agent 模式下，我们期望 Map 已经被 Daemon 固定。
		pinPath := config.GetPinPath()
		realMgr, err := xdp.NewManagerFromPins(pinPath, log)
		if err != nil {
			log.Fatalf("❌ Agent requires netxfw daemon to be running and maps pinned at %s: %v", pinPath, err)
		}
		defer realMgr.Close()
		// Wrap manager with Adapter for interface compliance
		manager = xdp.NewAdapter(realMgr)
	}

	// Consistency Check at startup (Ensure BPF maps match Config)
	// 启动时的一致性检查（确保 BPF Map 与配置匹配）
	if err := manager.VerifyAndRepair(globalCfg); err != nil {
		log.Warnf("⚠️  Startup consistency check failed: %v", err)
	} else {
		log.Info("✅ Startup consistency check passed (Config synced to BPF).")
	}

	// 2. Load ALL Plugins (Agent manages everything) / 加载所有插件（Agent 管理一切）
	var fw sdk.Firewall
	if adapter, ok := manager.(sdk.Firewall); ok {
		fw = adapter
	}

	s := sdk.NewSDK(manager)
	pluginCtx := &sdk.PluginContext{
		Context:  ctx,
		Firewall: fw,
		Manager:  manager,
		Config:   globalCfg,
		Logger:   log,
		SDK:      s,
	}

	var startedPlugins []sdk.Plugin
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
			continue
		}
		startedPlugins = append(startedPlugins, p)
	}

	defer func() {
		for _, p := range startedPlugins {
			_ = p.Stop()
		}
	}()

	// 4. Start Cleanup Loop / 启动清理循环
	ctxCleanup, cancel := context.WithCancel(ctx)
	defer cancel()
	go runCleanupLoop(ctxCleanup, globalCfg)

	// 5. Start Traffic Stats Loop / 启动流量统计循环
	go runTrafficStatsLoop(ctxCleanup, s)

	log.Info("🛡️ Agent is running.")
	waitForSignal(ctx, configPath, s, nil, nil) // nil means reload all / nil 表示重新加载所有内容
}
