package daemon

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// runDataPlane handles XDP mounting, BPF map initialization, and core packet processing plugins.
// runDataPlane 处理 XDP 挂载、BPF Map 初始化以及核心数据包处理插件。
func runDataPlane(ctx context.Context) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	pidPath := config.DefaultPidPath

	log.Info("[START] Starting netxfw in DP (Data Plane) mode")

	if err := managePidFile(pidPath); err != nil {
		log.Fatalf("[ERROR] %v", err)
	}
	defer removePidFile(pidPath)

	globalCfg, err := LoadRuntimeConfigSnapshot()
	if err != nil {
		log.Errorf("[ERROR] Failed to load global config from %s: %v", configPath, err)
		return
	}

	// Initialize Logging (Global init might be redundant if done in main, but keeps compatibility)
	InitRuntimeLogging(globalCfg)

	// 1. Initialize Manager (Create or Load Pinned) / 初始化管理器（创建或加载固定内容）
	pinPath := config.GetPinPath()
	manager, err := LoadOrCreateManager(log, pinPath, globalCfg)
	if err != nil {
		log.Errorf("[ERROR] %v", err)
		return
	}
	defer manager.Close()

	// 2. Attach to Interfaces / 附加到接口
	interfaces, err := ResolveRuntimeInterfaces(nil, globalCfg, log)
	if err != nil {
		log.Warnf("[WARN]  Failed to auto-detect interfaces: %v", err)
	}

	if len(interfaces) > 0 {
		if err := ReconcileInterfaces(manager, pinPath, interfaces, log, DetachAfterAttach); err != nil {
			log.Errorf("[ERROR] Failed to attach XDP: %v", err)
			return
		}
	} else {
		log.Warn("[WARN]  No interfaces configured for XDP attachment")
	}

	// 3. Initialize and Start Core Modules
	// 初始化并启动核心模块
	coreModules := DefaultCoreModules()

	// Wrap manager with Adapter for interface compliance
	adapter := xdp.NewAdapter(manager)
	s := sdk.NewSDK(adapter)

	if err := StartCoreModules(coreModules, globalCfg, s, log); err != nil {
		log.Errorf("[ERROR] %v", err)
		return
	}

	// 4. Load Extension Plugins
	// 加载扩展插件
	// In DP mode, we typically only run core modules.
	// If plugins are needed, they should be initialized here using a pluginCtx.

	log.Info("[SHIELD] Data Plane is running.")

	reloadFunc := func() error {
		newCfg, err := config.ReloadCurrentConfig()
		if err != nil {
			return err
		}
		if newCfg == nil {
			return fmt.Errorf("config is nil after reloading")
		}

		ReloadCoreModules(coreModules, newCfg, log)
		return nil
	}

	waitForSignal(ctx, configPath, s, reloadFunc, nil)
}
