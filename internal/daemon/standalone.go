package daemon

import (
	"context"

	"go.uber.org/zap"

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

	logger.Init(globalCfg.Logging)

	if globalCfg.Base.EnablePprof {
		startPprof(globalCfg.Base.PprofPort)
	}

	manager := initXDPManager(log, config.GetPinPath(), globalCfg)
	defer manager.Close()

	attachInterfaces(manager, globalCfg, log)

	if err := manager.VerifyAndRepair(globalCfg); err != nil {
		log.Warnf("⚠️  Startup consistency check failed: %v", err)
	} else {
		log.Info("✅ Startup consistency check passed (Config synced to BPF).")
	}

	coreModules := initCoreModules(globalCfg, manager, log)
	adapter := xdp.NewAdapter(manager)
	s := sdk.NewSDK(adapter)

	pluginCtx := &sdk.PluginContext{
		Context:  ctx,
		Firewall: adapter,
		Manager:  adapter,
		Config:   globalCfg,
		Logger:   log,
		SDK:      s,
	}
	startPlugins(pluginCtx, log)

	ctxCleanup, cancel := context.WithCancel(ctx)
	defer cancel()
	go runCleanupLoop(ctxCleanup, globalCfg)
	go runTrafficStatsLoop(ctxCleanup, s)

	log.Info("🛡️ NetXFW Unified is running.")

	reloadFunc := createReloadFunc(configPath, coreModules, pluginCtx, log)
	waitForSignal(ctx, configPath, s, reloadFunc, nil)
}

// initXDPManager initializes the XDP manager.
// initXDPManager 初始化 XDP 管理器。
func initXDPManager(log *zap.SugaredLogger, pinPath string, globalCfg *types.GlobalConfig) *xdp.Manager {
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
	return manager
}

// attachInterfaces attaches XDP to network interfaces.
// attachInterfaces 将 XDP 附加到网络接口。
func attachInterfaces(manager *xdp.Manager, globalCfg *types.GlobalConfig, log *zap.SugaredLogger) {
	var interfaces []string
	if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
	} else {
		interfaces, _ = xdp.GetPhysicalInterfaces()
	}

	if len(interfaces) > 0 {
		cleanupOrphanedInterfaces(manager, interfaces)
		if err := manager.Attach(interfaces); err != nil {
			log.Fatalf("❌ Failed to attach XDP: %v", err)
		}
	}
}

// initCoreModules initializes and starts core modules.
// initCoreModules 初始化并启动核心模块。
func initCoreModules(globalCfg *types.GlobalConfig, manager *xdp.Manager, log *zap.SugaredLogger) []engine.CoreModule {
	coreModules := []engine.CoreModule{
		&engine.BaseModule{},
		&engine.ConntrackModule{},
		&engine.PortModule{},
		&engine.RateLimitModule{},
	}

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
	return coreModules
}

// startPlugins starts all plugins.
// startPlugins 启动所有插件。
func startPlugins(pluginCtx *sdk.PluginContext, log *zap.SugaredLogger) {
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
	}
}

// createReloadFunc creates a reload function for configuration changes.
// createReloadFunc 创建配置变更的重载函数。
func createReloadFunc(configPath string, coreModules []engine.CoreModule, pluginCtx *sdk.PluginContext, log *zap.SugaredLogger) func() error {
	return func() error {
		types.ConfigMu.RLock()
		newCfg, err := types.LoadGlobalConfig(configPath)
		types.ConfigMu.RUnlock()
		if err != nil {
			return err
		}

		for _, mod := range coreModules {
			if err := mod.Reload(newCfg); err != nil {
				log.Warnf("⚠️  Failed to reload core module %s: %v", mod.Name(), err)
			}
		}

		pluginCtx.Config = newCfg
		for _, p := range plugins.GetPlugins() {
			if err := p.Reload(pluginCtx); err != nil {
				log.Warnf("⚠️  Failed to reload plugin %s: %v", p.Name(), err)
			}
		}
		return nil
	}
}
