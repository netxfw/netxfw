package daemon

import (
	"context"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins"
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

	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load global config from %s: %v", configPath, err)
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
			log.Fatalf("❌ Failed to create XDP manager: %v", err)
		}
		if err := manager.Pin(pinPath); err != nil {
			log.Warnf("⚠️  Failed to pin maps: %v", err)
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

	// 3. Load DP-Specific Plugins / 加载 DP 特定的插件
	// DP only runs plugins that configure BPF maps or globals. / DP 仅运行配置 BPF Map 或全局变量的插件。
	dpPlugins := []string{"base", "conntrack", "ratelimit", "port"}

	// Wrap manager with Adapter for interface compliance
	adapter := xdp.NewAdapter(manager)

	pluginCtx := &sdk.PluginContext{
		Context: ctx,
		Manager: adapter,
		Config:  globalCfg,
		Logger:  log,
	}

	for _, p := range plugins.GetPlugins() {
		isDpPlugin := false
		for _, name := range dpPlugins {
			if p.Name() == name {
				isDpPlugin = true
				break
			}
		}
		if !isDpPlugin {
			continue
		}

		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
		defer p.Stop()
	}
	// Wait logic needs to be added here or the function exits?
	// The original code didn't seem to have a wait loop in runDataPlane?
	// Ah, I missed the bottom of the file.

	log.Info("🛡️ Data Plane is running.")
	waitForSignal(ctx, configPath, adapter, dpPlugins)
}
