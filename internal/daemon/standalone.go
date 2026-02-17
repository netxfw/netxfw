package daemon

import (
	"context"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/core/engine"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

// runUnified runs the unified full-stack mode.
// runUnified 运行统一的全栈模式。
func runUnified(ctx context.Context) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	pidPath := config.DefaultPidPath

	if err := managePidFile(pidPath); err != nil {
		log.Fatalf("❌ %v", err)
	}
	defer removePidFile(pidPath)

	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Errorf("❌ Failed to load global config: %v", err)
		return
	}

	// Initialize Logging / 初始化日志
	logger.Init(globalCfg.Logging)

	if globalCfg.Base.EnablePprof {
		startPprof(globalCfg.Base.PprofPort)
	}

	// 1. Initialize Manager / 初始化管理器
	pinPath := config.GetPinPath()
	manager, err := xdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		log.Info("ℹ️  Creating new XDP manager...")
		manager, err = xdp.NewManager(globalCfg.Capacity, log)
		if err != nil {
			log.Fatalf("❌ Failed to create XDP manager: %v", err)
		}
		if err := manager.Pin(pinPath); err != nil {
			log.Warnf("⚠️  Failed to pin maps: %v", err)
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

	// Consistency Check at startup (Ensure BPF maps match Config)
	// 启动时的一致性检查（确保 BPF Map 与配置匹配）
	if err := manager.VerifyAndRepair(globalCfg); err != nil {
		log.Warnf("⚠️  Startup consistency check failed: %v", err)
	} else {
		log.Info("✅ Startup consistency check passed (Config synced to BPF).")
	}

	// 3. Initialize and Start Core Modules
	// 初始化并启动核心模块
	coreModules := []engine.CoreModule{
		&engine.BaseModule{},
		&engine.ConntrackModule{},
		&engine.PortModule{},
		&engine.RateLimitModule{},
	}

	// Wrap manager with Adapter for interface compliance
	adapter := xdp.NewAdapter(manager)
	s := sdk.NewSDK(adapter)

	for _, mod := range coreModules {
		if err := mod.Init(globalCfg, s, log); err != nil {
			log.Fatalf("❌ Failed to init core module %s: %v", mod.Name(), err)
		}
		if err := mod.Start(); err != nil {
			log.Fatalf("❌ Failed to start core module %s: %v", mod.Name(), err)
		}
	}

	// 4. Load ALL Plugins / 加载所有插件
	pluginCtx := &sdk.PluginContext{
		Context:  ctx,
		Firewall: adapter,
		Manager:  adapter,
		Config:   globalCfg,
		Logger:   log,
		SDK:      s,
	}
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
		defer func() { _ = p.Stop() }()
	}

	// 5. Start Cleanup Loop / 启动清理循环
	ctxCleanup, cancel := context.WithCancel(ctx)
	defer cancel()
	go runCleanupLoop(ctxCleanup, globalCfg)

	log.Info("🛡️ NetXFW Unified is running.")

	reloadFunc := func() error {
		types.ConfigMu.RLock()
		newCfg, err := types.LoadGlobalConfig(configPath)
		types.ConfigMu.RUnlock()
		if err != nil {
			return err
		}

		// Reload Core Modules
		for _, mod := range coreModules {
			if err := mod.Reload(newCfg); err != nil {
				log.Warnf("⚠️  Failed to reload core module %s: %v", mod.Name(), err)
			}
		}

		// Reload Plugins
		pluginCtx.Config = newCfg
		for _, p := range plugins.GetPlugins() {
			if err := p.Reload(pluginCtx); err != nil {
				log.Warnf("⚠️  Failed to reload plugin %s: %v", p.Name(), err)
			}
		}
		return nil
	}

	waitForSignal(ctx, configPath, s, reloadFunc, nil)
}
