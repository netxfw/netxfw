package daemon

import (
	"context"

	"github.com/netxfw/netxfw/internal/api"
	"go.uber.org/zap"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/core/engine"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// runUnified runs the unified full-stack mode.
// runUnified 运行统一的全栈模式。
func runUnified(ctx context.Context) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	pidPath := config.DefaultPidPath

	if err := managePidFile(pidPath); err != nil {
		log.Fatalf("[ERROR] %v", err)
	}
	defer removePidFile(pidPath)

	globalCfg, err := LoadRuntimeConfigSnapshot()
	if err != nil {
		log.Errorf("[ERROR] Failed to load global config: %v", err)
		return
	}

	InitRuntimeLogging(globalCfg)

	manager, err := LoadOrCreateManager(log, config.GetPinPath(), globalCfg)
	if err != nil {
		log.Errorf("[ERROR] %v", err)
		return
	}
	defer manager.Close()

	interfaces, err := ResolveRuntimeInterfaces(nil, globalCfg, log)
	if err != nil {
		log.Errorf("[ERROR] Failed to resolve interfaces: %v", err)
		return
	}
	if len(interfaces) > 0 {
		if err := ReconcileInterfaces(manager, config.GetPinPath(), interfaces, log, DetachBeforeAttach); err != nil {
			log.Errorf("[ERROR] Failed to attach XDP: %v", err)
			return
		}
	}

	VerifyRuntimeConfigAndMaps(manager, globalCfg, log)

	coreModules := DefaultCoreModules()
	adapter := xdp.NewAdapter(manager)
	s := sdk.NewSDK(adapter)
	webHost := api.NewServer(s, globalCfg.Web.Port)
	if err := StartCoreModules(coreModules, globalCfg, s, log); err != nil {
		log.Errorf("[ERROR] %v", err)
		return
	}

	pluginCtx := BuildPluginContext(ctx, adapter, adapter, globalCfg, log, s, webHost)
	StartPlugins(pluginCtx, log)

	ctxCleanup, cancel := context.WithCancel(ctx)
	defer cancel()
	go runCleanupLoop(ctxCleanup, globalCfg)
	go runTrafficStatsLoop(ctxCleanup, s)

	log.Info("[SHIELD] NetXFW Unified is running.")

	reloadFunc := createReloadFunc(configPath, coreModules, pluginCtx, log)
	waitForSignal(ctx, configPath, s, reloadFunc, nil)
}

// createReloadFunc creates a reload function for configuration changes.
// createReloadFunc 创建配置变更的重载函数。
func createReloadFunc(_ string, coreModules []engine.CoreModule, pluginCtx *sdk.PluginContext, log *zap.SugaredLogger) func() error {
	return func() error {
		newCfg, err := config.ReloadCurrentConfig()
		if err != nil {
			return err
		}

		ReloadCoreModules(coreModules, newCfg, log)
		pluginCtx.Config = newCfg
		ReloadPlugins(pluginCtx, log)
		return nil
	}
}
