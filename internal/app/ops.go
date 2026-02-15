package app

import (
	"context"
	"fmt"
	"log"
	_ "net/http/pprof"
	"strconv"

	"github.com/livp123/netxfw/internal/api"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

/**
 * InstallXDP initializes the XDP manager and mounts the program to interfaces, then exits.
 * InstallXDP 初始化 XDP 管理器并将程序挂载到接口，然后退出。
 */
func InstallXDP(ctx context.Context, cliInterfaces []string) error {
	log := logger.Get(ctx)
	// Load global configuration first to get interface settings / 首先加载全局配置以获取接口设置
	globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}

	var interfaces []string
	if len(cliInterfaces) > 0 {
		interfaces = cliInterfaces
		log.Infof("ℹ️  Using CLI provided interfaces: %v", interfaces)
	} else if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
		log.Infof("ℹ️  Using configured interfaces: %v", interfaces)
	} else {
		// Auto-detect if no interfaces configured / 如果未配置接口，则自动检测
		interfaces, err = xdp.GetPhysicalInterfaces()
		if err != nil {
			return fmt.Errorf("failed to get interfaces: %v", err)
		}
		if len(interfaces) == 0 {
			return fmt.Errorf("no physical interfaces found")
		}
		log.Infof("ℹ️  Auto-detected interfaces: %v", interfaces)
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

	// Detach from interfaces that are not in the current configuration
	// 移除未在当前配置中的接口上的 XDP
	if attachedIfaces, err := xdp.GetAttachedInterfaces(config.GetPinPath()); err == nil {
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

	// Start all plugins to apply configurations / 启动所有插件以应用配置
	pluginCtx := &sdk.PluginContext{
		Context: ctx,
		Manager: xdp.NewAdapter(manager),
		Config:  globalCfg,
		Logger:  log,
	}

	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(pluginCtx); err != nil {
			log.Warnf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
		defer p.Stop()
	}

	log.Infof("🚀 XDP program installed successfully and pinned to %s", config.GetPinPath())
	return nil
}

/**
 * RunDaemon starts the background process for metrics and rule synchronization.
 * RunDaemon 启动用于指标和规则同步的后台进程。
 */
func RunDaemon(ctx context.Context) {
	core.InitConfiguration(ctx)
	core.TestConfiguration(ctx)
	daemon.Run(ctx, runtime.Mode, nil)
}

/**
 * HandlePluginCommand processes plugin-related CLI commands.
 * HandlePluginCommand 处理与插件相关的 CLI 命令。
 */
func HandlePluginCommand(ctx context.Context, args []string) error {
	log := logger.Get(ctx)
	if len(args) < 1 {
		return fmt.Errorf("Usage: netxfw plugin <load|remove> ...")
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
	// Load global configuration to get max entries (needed for NewManager)
	// 加载全局配置以获取最大条目数（NewManager 需要）
	globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
	if err != nil {
		log.Warnf("⚠️  Failed to load global config, using default map capacity: %v", err)
		globalCfg = &types.GlobalConfig{}
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
		if phyInterfaces, err := xdp.GetPhysicalInterfaces(); err == nil {
			for _, iface := range phyInterfaces {
				uniqueInterfaces[iface] = true
			}
		}

		// 2. Get interfaces from config / 2. 从配置获取接口
		for _, iface := range globalCfg.Base.Interfaces {
			uniqueInterfaces[iface] = true
		}

		// 3. Get currently attached interfaces from pins / 3. 从固定路径获取当前已附加的接口
		if attachedIfaces, err := xdp.GetAttachedInterfaces(config.GetPinPath()); err == nil {
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

	// 1. Load global configuration / 加载全局配置
	globalCfg, err := types.LoadGlobalConfig(config.GetConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}

	var interfaces []string
	if len(cliInterfaces) > 0 {
		interfaces = cliInterfaces
		log.Infof("ℹ️  Using CLI provided interfaces: %v", interfaces)
	} else if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
		log.Infof("ℹ️  Using configured interfaces: %v", interfaces)
	} else {
		interfaces, err = xdp.GetPhysicalInterfaces()
		if err != nil {
			return fmt.Errorf("failed to get interfaces: %v", err)
		}
		log.Infof("ℹ️  Auto-detected interfaces: %v", interfaces)
	}

	// 2. Try to load old manager from pins to check capacity
	// 2. 尝试从固定点加载旧管理器以检查容量
	oldManager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err == nil {
		oldAdapter := xdp.NewAdapter(oldManager)
		pluginCtx := &sdk.PluginContext{
			Context: ctx,
			Manager: oldAdapter,
			Config:  globalCfg,
			Logger:  log,
		}

		// Check if the current map capacities match the requested configuration
		// 检查当前 Map 容量是否与请求的配置匹配
		if oldManager.MatchesCapacity(globalCfg.Capacity) {
			log.Info("⚡ Capacity unchanged. Performing incremental hot-reload...")

			// Apply new configurations to existing maps
			// 将新配置应用到现有 Map
			for _, p := range plugins.GetPlugins() {
				if err := p.Init(pluginCtx); err != nil {
					log.Warnf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
					continue
				}
				if err := p.Reload(pluginCtx); err != nil {
					log.Warnf("⚠️  Failed to reload plugin %s: %v", p.Name(), err)
				}
			}

			// Atomic update XDP program on interfaces
			// 在接口上原子更新 XDP 程序
			if err := oldManager.Attach(interfaces); err != nil {
				log.Warnf("⚠️  Failed to update XDP program: %v", err)
			}

			log.Info("🚀 Incremental reload completed successfully.")
			oldManager.Close()
			return nil
		}

		log.Info("📦 Capacity changed. Performing full state migration...")
		// Initialize new manager with new capacities
		// 使用新容量初始化新管理器
		newManager, err := xdp.NewManager(globalCfg.Capacity, log)
		if err != nil {
			return fmt.Errorf("failed to create new XDP manager: %v", err)
		}

		// Migrate state from old maps to new maps / 将状态从旧 Map 迁移到新 Map
		if err := newManager.MigrateState(oldManager); err != nil {
			log.Warnf("⚠️  State migration partial or failed: %v", err)
		}
		oldManager.Close()

		// Update pins and attach / 更新固定路径并附加
		if err := newManager.Pin(config.GetPinPath()); err != nil {
			return fmt.Errorf("failed to pin new maps: %v", err)
		}
		if err := newManager.Attach(interfaces); err != nil {
			return fmt.Errorf("failed to attach new XDP program: %v", err)
		}

		// Sync plugins to new manager / 将插件同步到新管理器
		newAdapter := xdp.NewAdapter(newManager)
		newCtx := &sdk.PluginContext{
			Context: ctx,
			Manager: newAdapter,
			Config:  globalCfg,
			Logger:  log,
		}

		for _, p := range plugins.GetPlugins() {
			if err := p.Init(newCtx); err != nil {
				log.Warnf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			}
			if err := p.Reload(newCtx); err != nil {
				log.Warnf("⚠️  Failed to reload plugin %s: %v", p.Name(), err)
			}
		}

		log.Info("🚀 Full hot-reload with state migration completed successfully.")
		return nil
	}

	// 3. Fallback: If no old manager found, perform a clean install
	// 3. 回退方案：如果未发现旧管理器，则执行全新安装
	log.Info("ℹ️  No existing XDP program found. Performing clean install...")
	return InstallXDP(ctx, cliInterfaces)
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
	server := api.NewServer(adapter, port)
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start web server: %v", err)
	}
	return nil
}

/**
 * UnloadXDP provides instructions to unload the program.
 * UnloadXDP 提供卸载程序的指令。
 */
func UnloadXDP() {
	log.Println("👋 Unloading XDP and cleaning up...")
	// Cleanup is handled by the server process on exit.
	// 卸载和清理通常在服务器进程退出时处理。
	log.Println("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}
