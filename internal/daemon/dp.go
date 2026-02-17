package daemon

import (
	"context"
	"fmt"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/core/engine"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

// runDataPlane handles XDP mounting, BPF map initialization, and core packet processing plugins.
// runDataPlane 处理 XDP 挂载、BPF Map 初始化以及核心数据包处理插件。
func runDataPlane(ctx context.Context) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	pidPath := config.DefaultPidPath

	log.Info("🚀 Starting netxfw in DP (Data Plane) mode")

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

	// Initialize Logging (Global init might be redundant if done in main, but keeps compatibility)
	logger.Init(globalCfg.Logging)

	// 1. Initialize Manager (Create or Load Pinned) / 初始化管理器（创建或加载固定内容）
	pinPath := config.GetPinPath()
	manager, err := xdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		log.Info("ℹ️  Creating new XDP manager...")
		manager, err = xdp.NewManager(globalCfg.Capacity, log)
		if err != nil {
			log.Errorf("❌ Failed to create XDP manager: %v", err)
			return
		}
		if pinErr := manager.Pin(pinPath); pinErr != nil {
			log.Warnf("⚠️  Failed to pin maps: %v", pinErr)
		}
	}
	defer manager.Close()

	// 2. Attach to Interfaces / 附加到接口
	var interfaces []string
	if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
		log.Infof("ℹ️  Using configured interfaces: %v", interfaces)
	} else {
		interfaces, err = xdp.GetPhysicalInterfaces()
		if err != nil {
			log.Warnf("⚠️  Failed to auto-detect interfaces: %v", err)
		}
	}

	if len(interfaces) > 0 {
		if err := manager.Attach(interfaces); err != nil {
			log.Fatalf("❌ Failed to attach XDP: %v", err)
		}
		cleanupOrphanedInterfaces(manager, interfaces)
	} else {
		log.Warn("⚠️  No interfaces configured for XDP attachment")
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

	// 4. Load Extension Plugins
	// 加载扩展插件
	// In DP mode, we typically only run core modules.
	// If plugins are needed, they should be initialized here using a pluginCtx.

	log.Info("🛡️ Data Plane is running.")

	reloadFunc := func() error {
		types.ConfigMu.RLock()
		// Use the config manager to reload the configuration
		err := cfgManager.LoadConfig()
		if err != nil {
			types.ConfigMu.RUnlock()
			return err
		}

		newCfg := cfgManager.GetConfig()
		types.ConfigMu.RUnlock()
		if newCfg == nil {
			return fmt.Errorf("config is nil after reloading")
		}

		// Reload Core Modules
		for _, mod := range coreModules {
			if err := mod.Reload(newCfg); err != nil {
				log.Warnf("⚠️  Failed to reload core module %s: %v", mod.Name(), err)
			}
		}
		return nil
	}

	waitForSignal(ctx, configPath, s, reloadFunc, nil)
}
