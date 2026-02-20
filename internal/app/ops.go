package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	// Import pprof for HTTP endpoint profiling / 导入 pprof 用于 HTTP 端点性能分析
	// #nosec G108 // pprof is intentionally exposed for debugging in development
	_ "net/http/pprof"
	"strconv"

	"github.com/livp123/netxfw/internal/api"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/core/engine"
	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

/**
 * InstallXDP initializes the XDP manager and mounts the program to interfaces, then exits.
 * InstallXDP 初始化 XDP 管理器并将程序挂载到接口，然后退出。
 */
func InstallXDP(ctx context.Context, cliInterfaces []string) error {
	log := logger.Get(ctx)
	cfgManager := config.GetConfigManager()
	err := cfgManager.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}

	globalCfg := cfgManager.GetConfig()
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	interfaces, err := resolveInterfaces(cliInterfaces, globalCfg, log)
	if err != nil {
		return err
	}

	manager, err := xdp.NewManager(globalCfg.Capacity, log)
	if err != nil {
		return fmt.Errorf("failed to create XDP manager: %v", err)
	}

	if err := manager.Pin(config.GetPinPath()); err != nil {
		return fmt.Errorf("failed to pin maps: %v", err)
	}

	if err := manager.Attach(interfaces); err != nil {
		return fmt.Errorf("failed to attach XDP: %v", err)
	}

	detachOrphanedInterfaces(manager, interfaces, log)

	s := sdk.NewSDK(xdp.NewAdapter(manager))
	pluginCtx := &sdk.PluginContext{
		Context: ctx,
		Manager: s.GetManager(),
		Config:  globalCfg,
		Logger:  log,
		SDK:     s,
	}

	coreModules := []engine.CoreModule{
		&engine.BaseModule{},
		&engine.ConntrackModule{},
		&engine.PortModule{},
		&engine.RateLimitModule{},
	}

	for _, mod := range coreModules {
		if err := mod.Init(globalCfg, s, log); err != nil {
			return fmt.Errorf("❌ Failed to init core module %s: %v", mod.Name(), err)
		}
		if err := mod.Start(); err != nil {
			return fmt.Errorf("❌ Failed to start core module %s: %v", mod.Name(), err)
		}
	}

	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Errorf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}

		if err := p.Start(pluginCtx); err != nil {
			log.Errorf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
	}

	log.Infof("🚀 XDP program installed successfully and pinned to %s", config.GetPinPath())
	return nil
}

// resolveInterfaces resolves the interfaces to use for XDP.
// resolveInterfaces 解析用于 XDP 的接口。
func resolveInterfaces(cliInterfaces []string, globalCfg *types.GlobalConfig, log *zap.SugaredLogger) ([]string, error) {
	if len(cliInterfaces) > 0 {
		log.Infof("ℹ️  Using CLI provided interfaces: %v", cliInterfaces)
		return cliInterfaces, nil
	}

	if len(globalCfg.Base.Interfaces) > 0 {
		log.Infof("ℹ️  Using configured interfaces: %v", globalCfg.Base.Interfaces)
		return globalCfg.Base.Interfaces, nil
	}

	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no physical interfaces found")
	}
	log.Infof("ℹ️  Auto-detected interfaces: %v", interfaces)
	return interfaces, nil
}

// detachOrphanedInterfaces detaches XDP from interfaces not in the current configuration.
// detachOrphanedInterfaces 从不在当前配置中的接口分离 XDP。
func detachOrphanedInterfaces(manager *xdp.Manager, interfaces []string, log *zap.SugaredLogger) {
	attachedIfaces, err := xdp.GetAttachedInterfaces(config.GetPinPath())
	if err != nil {
		return
	}

	var toDetach []string
	for _, attached := range attachedIfaces {
		found := false
		for _, configured := range interfaces {
			if attached == configured {
				found = true
				break
			}
		}
		if !found {
			toDetach = append(toDetach, attached)
		}
	}

	if len(toDetach) > 0 {
		log.Infof("ℹ️  Detaching from removed interfaces: %v", toDetach)
		if err := manager.Detach(toDetach); err != nil {
			log.Warnf("⚠️  Failed to detach from removed interfaces: %v", err)
		}
	}
}

/**
 * RunDaemon starts the background process for metrics and rule synchronization.
 * RunDaemon 启动用于指标和规则同步的后台进程。
 */
func RunDaemon(ctx context.Context) {
	core.InitConfiguration(ctx)
	daemon.TestConfiguration(ctx)
	daemon.Run(ctx, runtime.Mode, nil)
}

/**
 * HandlePluginCommand processes plugin-related CLI commands.
 * HandlePluginCommand 处理与插件相关的 CLI 命令。
 */
func HandlePluginCommand(ctx context.Context, args []string) error {
	log := logger.Get(ctx)
	if len(args) < 1 {
		return fmt.Errorf("usage: netxfw plugin <load|remove>")
	}

	manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err != nil {
		return fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	switch args[0] {
	case "load":
		// Load a plugin ELF file into a specific slot in the prog_array
		// 将插件 ELF 文件加载到 prog_array 中的特定插槽
		if len(args) < 3 {
			return fmt.Errorf("Usage: netxfw plugin load <path_to_elf> <index (2-15)>")
		}
		path := args[1]
		idx, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("invalid index: %v", err)
		}
		if err := manager.LoadPlugin(path, idx); err != nil {
			return fmt.Errorf("failed to load plugin: %v", err)
		}
	case "remove":
		// Remove a plugin from a specific slot
		// 从特定插槽中移除插件
		if len(args) < 2 {
			return fmt.Errorf("Usage: netxfw plugin remove <index (2-15)>")
		}
		idx, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid index: %v", err)
		}
		if err := manager.RemovePlugin(idx); err != nil {
			return fmt.Errorf("failed to remove plugin: %v", err)
		}
	default:
		return fmt.Errorf("unknown plugin command: %s", args[0])
	}
	log.Infof("✅ Plugin command %s executed successfully", args[0])
	return nil
}

/**
 * RemoveXDP detaches the XDP program from all interfaces and unpins everything.
 * RemoveXDP 从所有接口分离 XDP 程序并取消所有固定。
 */
func RemoveXDP(ctx context.Context, cliInterfaces []string) error {
	log := logger.Get(ctx)
	var globalCfg *types.GlobalConfig

	// Load global configuration to get max entries (needed for NewManager)
	// 加载全局配置以获取最大条目数（NewManager 需要）
	cfgManager := config.GetConfigManager()
	err := cfgManager.LoadConfig()
	if err != nil {
		log.Warnf("⚠️  Failed to load global config, using default map capacity: %v", err)
		globalCfg = &types.GlobalConfig{}
	} else {
		globalCfg = cfgManager.GetConfig()
		if globalCfg == nil {
			globalCfg = &types.GlobalConfig{} // fallback
		}
	}

	var interfaces []string
	fullUnload := false

	if len(cliInterfaces) > 0 {
		interfaces = cliInterfaces
		log.Infof("ℹ️  Detaching from specific interfaces: %v", interfaces)
	} else {
		fullUnload = true
		// Collect all potential interfaces to detach from
		// 收集所有可能的分离接口
		uniqueInterfaces := make(map[string]bool)

		// 1. Get physical interfaces / 1. 获取物理接口
		phyInterfaces, phyErr := xdp.GetPhysicalInterfaces()
		if phyErr == nil {
			for _, iface := range phyInterfaces {
				uniqueInterfaces[iface] = true
			}
		}

		// 2. Get interfaces from config / 2. 从配置获取接口
		for _, iface := range globalCfg.Base.Interfaces {
			uniqueInterfaces[iface] = true
		}

		// 3. Get currently attached interfaces from pins / 3. 从固定路径获取当前已附加的接口
		attachedIfaces, attachErr := xdp.GetAttachedInterfaces(config.GetPinPath())
		if attachErr == nil {
			for _, iface := range attachedIfaces {
				uniqueInterfaces[iface] = true
			}
		}

		for iface := range uniqueInterfaces {
			interfaces = append(interfaces, iface)
		}
		log.Infof("ℹ️  Detaching from all detected interfaces: %v", interfaces)
	}

	manager, err := xdp.NewManager(globalCfg.Capacity, log)
	if err != nil {
		return fmt.Errorf("failed to create XDP manager: %v", err)
	}
	defer manager.Close()

	if err := manager.Detach(interfaces); err != nil {
		log.Warnf("⚠️  Some interfaces could not be detached: %v", err)
	}

	if fullUnload {
		if err := manager.Unpin(config.GetPinPath()); err != nil {
			log.Warnf("⚠️  Could not unpin all maps: %v", err)
		}
		log.Info("✅ XDP driver removed and maps unpinned.")
	} else {
		log.Infof("✅ XDP driver detached from %v", interfaces)
	}
	return nil
}

// ReloadXDP performs a hot-reload of the XDP program.
// It loads new objects, migrates state from old pinned maps, and swaps the program.
// ReloadXDP 执行 XDP 程序的平滑重载：加载新对象，从旧的固定 Map 迁移状态，并切换程序。
func ReloadXDP(ctx context.Context, cliInterfaces []string) error {
	log := logger.Get(ctx)
	log.Info("🔄 Starting hot-reload of XDP program...")

	cfgManager := config.GetConfigManager()
	err := cfgManager.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}

	globalCfg := cfgManager.GetConfig()
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	interfaces, err := resolveInterfaces(cliInterfaces, globalCfg, log)
	if err != nil {
		return err
	}

	oldManager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err != nil {
		log.Info("ℹ️  No existing XDP program found. Performing clean install...")
		return InstallXDP(ctx, cliInterfaces)
	}

	return reloadExistingManager(ctx, oldManager, globalCfg, interfaces, cfgManager, log)
}

// reloadExistingManager handles reload when an existing manager is found.
// reloadExistingManager 处理发现现有管理器时的重载。
func reloadExistingManager(ctx context.Context, oldManager *xdp.Manager, globalCfg *types.GlobalConfig, interfaces []string, cfgManager *config.ConfigManager, log *zap.SugaredLogger) error {
	defer oldManager.Close()

	oldAdapter := xdp.NewAdapter(oldManager)
	pluginCtx := &sdk.PluginContext{
		Context: ctx,
		Manager: oldAdapter,
		Config:  globalCfg,
		Logger:  log,
	}

	if oldManager.MatchesCapacity(globalCfg.Capacity) {
		return performIncrementalReload(oldManager, globalCfg, interfaces, pluginCtx, cfgManager, log)
	}

	return performFullMigration(ctx, oldManager, globalCfg, interfaces, log)
}

// performIncrementalReload performs incremental reload when capacity matches.
// performIncrementalReload 当容量匹配时执行增量重载。
func performIncrementalReload(oldManager *xdp.Manager, globalCfg *types.GlobalConfig, interfaces []string, pluginCtx *sdk.PluginContext, cfgManager *config.ConfigManager, log *zap.SugaredLogger) error {
	log.Info("⚡ Capacity unchanged. Performing incremental hot-reload...")

	oldCfg := cfgManager.GetConfig()
	updater := oldManager.IncrementalUpdater()
	if updater != nil {
		diff, diffErr := updater.ComputeDiff(oldCfg, globalCfg)
		if diffErr != nil {
			log.Warnf("⚠️  Failed to compute config diff: %v", diffErr)
		} else if diff.HasChanges() {
			log.Infof("📊 Config changes detected: %s", diff.Summary())
			if err := updater.ApplyDiff(diff); err != nil {
				log.Warnf("⚠️  Incremental update had errors: %v", err)
			} else {
				log.Info("✅ Incremental config update applied successfully")
			}
		} else {
			log.Info("ℹ️  No config changes detected")
		}
	}

	reloadPlugins(pluginCtx, log)

	if err := oldManager.Attach(interfaces); err != nil {
		log.Warnf("⚠️  Failed to update XDP program: %v", err)
	}

	log.Info("🚀 Incremental reload completed successfully.")
	return nil
}

// performFullMigration performs full state migration when capacity changes.
// performFullMigration 当容量变更时执行完整状态迁移。
func performFullMigration(ctx context.Context, oldManager *xdp.Manager, globalCfg *types.GlobalConfig, interfaces []string, log *zap.SugaredLogger) error {
	log.Info("📦 Capacity changed. Performing full state migration...")

	newManager, err := xdp.NewManager(globalCfg.Capacity, log)
	if err != nil {
		return fmt.Errorf("failed to create new XDP manager: %v", err)
	}

	if err := newManager.MigrateState(oldManager); err != nil {
		log.Warnf("⚠️  State migration partial or failed: %v", err)
	}
	oldManager.Close()

	if err := newManager.Pin(config.GetPinPath()); err != nil {
		return fmt.Errorf("failed to pin new maps: %v", err)
	}
	if err := newManager.Attach(interfaces); err != nil {
		return fmt.Errorf("failed to attach new XDP program: %v", err)
	}

	newAdapter := xdp.NewAdapter(newManager)
	newCtx := &sdk.PluginContext{
		Context: ctx,
		Manager: newAdapter,
		Config:  globalCfg,
		Logger:  log,
	}

	reloadPlugins(newCtx, log)

	log.Info("🚀 Full hot-reload with state migration completed successfully.")
	return nil
}

// reloadPlugins reloads all plugins.
// reloadPlugins 重载所有插件。
func reloadPlugins(pluginCtx *sdk.PluginContext, log *zap.SugaredLogger) {
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Reload(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to reload plugin %s: %v", p.Name(), err)
		}
	}
}

/**
 * RunWebServer starts the API and UI server.
 * RunWebServer 启动 API 和 UI 服务器。
 */
func RunWebServer(ctx context.Context, port int) error {
	log := logger.Get(ctx)
	// 1. Try to load manager from pins / 尝试从固定点加载管理器
	manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err != nil {
		log.Warnf("⚠️  Could not load pinned maps (is XDP loaded?): %v", err)
		return fmt.Errorf("web server requires netxfw XDP to be loaded. Run 'netxfw system load' first")
	}
	defer manager.Close()

	// 2. Start API server / 启动 API 服务器
	adapter := xdp.NewAdapter(manager)
	s := sdk.NewSDK(adapter)
	server := api.NewServer(s, port)

	addr := fmt.Sprintf(":%d", port)
	log.Infof("🚀 Management API and UI starting on http://localhost%s", addr)

	// Create HTTP server with timeouts for security
	// 创建带有超时的 HTTP 服务器以提高安全性
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      server.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := httpServer.ListenAndServe(); err != nil {
		return fmt.Errorf("failed to start web server: %v", err)
	}
	return nil
}

/**
 * UnloadXDP provides instructions to unload the program.
 * UnloadXDP 提供卸载程序的指令。
 */
func UnloadXDP() {
	log := logger.Get(nil)
	log.Infof("👋 Unloading XDP and cleaning up...")
	// Cleanup is handled by the server process on exit.
	// 卸载和清理通常在服务器进程退出时处理。
	log.Infof("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}
