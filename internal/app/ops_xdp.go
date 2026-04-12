package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/netxfw/netxfw/internal/api"
	"github.com/netxfw/netxfw/internal/daemon"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// IsXDPLoaded returns true if XDP is attached to any interface.
func IsXDPLoaded() bool {
	ifaces, err := xdp.GetAttachedInterfaces(GetPinPath())
	return err == nil && len(ifaces) > 0
}

/**
 * InstallXDP initializes the XDP manager and mounts the program to interfaces, then exits.
 * InstallXDP 初始化 XDP 管理器并将程序挂载到接口，然后退出。
 *
 * 功能说明 / Function Description:
 * 1. 加载全局配置文件 / Load global configuration file
 * 2. 解析网络接口 / Resolve network interfaces
 * 3. 创建 XDP 管理器 / Create XDP manager
 * 4. 固定 BPF maps 到文件系统 / Pin BPF maps to filesystem
 * 5. 同步配置和规则到 BPF maps / Sync configuration and rules to BPF maps
 * 6. 挂载 XDP 程序到网络接口 / Attach XDP program to network interfaces
 * 7. 初始化并启动核心模块 / Initialize and start core modules
 * 8. 初始化并启动插件 / Initialize and start plugins
 *
 * 参数 / Parameters:
 * - ctx: 上下文 / Context
 * - cliInterfaces: 命令行指定的接口列表，为空则使用配置文件 / CLI specified interfaces, use config if empty
 *
 * 返回值 / Returns:
 * - error: 错误信息 / Error message
 */
func InstallXDP(ctx context.Context, cliInterfaces []string) error {
	log := logger.Get(ctx)

	globalCfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	interfaces, err := daemon.ResolveRuntimeInterfaces(cliInterfaces, globalCfg, log)
	if err != nil {
		return err
	}

	manager, err := daemon.LoadOrCreateManager(log, GetPinPath(), globalCfg)
	if err != nil {
		return err
	}

	err = daemon.PinManager(manager, GetPinPath())
	if err != nil {
		return fmt.Errorf("failed to pin maps: %v", err)
	}

	log.Infof("[SYNC] Syncing global config and loading persisted rules...")
	err = manager.SyncFromFiles(globalCfg, false)
	if err != nil {
		log.Warnf("[WARN]  Failed to sync config and load rules: %v (continuing anyway)", err)
	}

	err = daemon.ReconcileInterfaces(manager, GetPinPath(), interfaces, log, daemon.DetachAfterAttach)
	if err != nil {
		return fmt.Errorf("failed to attach XDP: %v", err)
	}

	err = loadBPFPlugins(manager, globalCfg, log)
	if err != nil {
		log.Warnf("[WARN]  Failed to load BPF plugins: %v (continuing anyway)", err)
	}

	s := sdk.NewSDK(xdp.NewAdapter(manager))
	webHost := api.NewServer(s, globalCfg.Web.Port)
	_, err = daemon.StartDefaultRuntimeCore(globalCfg, s, log)
	if err != nil {
		return fmt.Errorf("[ERROR] %v", err)
	}
	_, _ = daemon.StartRuntimePlugins(ctx, nil, s.GetManager(), globalCfg, log, s, webHost)

	log.Infof("[START] XDP program installed successfully and pinned to %s", GetPinPath())
	return nil
}

// loadBPFPlugins loads BPF plugins configured in the global config.
// loadBPFPlugins 加载全局配置中配置的 BPF 插件。
func loadBPFPlugins(manager *xdp.Manager, globalCfg *types.GlobalConfig, log *zap.SugaredLogger) error {

	if !globalCfg.BPFPlugin.Enabled {
		log.Infof("[INFO]  BPF plugin auto-loading is disabled")
		return nil
	}

	plugins := globalCfg.BPFPlugin.Plugins
	if len(plugins) == 0 {
		log.Infof("[INFO]  No BPF plugins configured")
		return nil
	}

	log.Infof("[INFO]  Loading %d BPF plugin(s)...", len(plugins))

	var loadErrors []string
	loadedCount := 0

	for _, plugin := range plugins {

		if !plugin.Enabled {
			log.Infof("[INFO]  Skipping disabled plugin: %s (index %d)", plugin.Path, plugin.Index)
			continue
		}

		if plugin.Index < xdp.ProgramIndexPluginStart || plugin.Index > xdp.ProgramIndexPluginEnd {
			log.Warnf("[WARN]  Invalid plugin index %d for %s (must be %d-%d)",
				plugin.Index, plugin.Path, xdp.ProgramIndexPluginStart, xdp.ProgramIndexPluginEnd)
			loadErrors = append(loadErrors, fmt.Sprintf("%s: invalid index %d", plugin.Path, plugin.Index))
			continue
		}

		if err := manager.LoadPlugin(plugin.Path, plugin.Index); err != nil {
			log.Warnf("[WARN]  Failed to load BPF plugin %s: %v", plugin.Path, err)
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", plugin.Path, err))
			continue
		}

		loadedCount++
		desc := plugin.Description
		if desc == "" {
			desc = "no description"
		}
		log.Infof("[OK] BPF plugin loaded: %s at index %d (%s)", plugin.Path, plugin.Index, desc)
	}

	if len(loadErrors) > 0 {
		return fmt.Errorf("failed to load %d plugin(s): %s", len(loadErrors), strings.Join(loadErrors, "; "))
	}

	log.Infof("[OK] Successfully loaded %d/%d BPF plugin(s)", loadedCount, len(plugins))
	return nil
}

// ValidateAndAttachXDP validates the requested attach mode and attaches XDP.
func ValidateAndAttachXDP(ctx context.Context, interfaces []string, mode string) ([]string, error) {
	switch mode {
	case "offload", "drv", "skb":
		return AttachXDPWithMode(ctx, interfaces, mode)
	default:
		return nil, fmt.Errorf("invalid mode. must be one of: offload, drv, skb")
	}
}

/**
 * RemoveXDP detaches the XDP program from all interfaces and unpins everything.
 * RemoveXDP 从所有接口分离 XDP 程序并取消所有固定。
 */
func RemoveXDP(ctx context.Context, cliInterfaces []string) error {
	log := logger.Get(ctx)
	globalCfg, err := LoadConfig()
	if err != nil {
		log.Warnf("[WARN]  Failed to load global config, using default map capacity: %v", err)
		globalCfg = &types.GlobalConfig{}
	}
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	var interfaces []string
	fullUnload := false

	if len(cliInterfaces) > 0 {
		interfaces = cliInterfaces
		log.Infof("[INFO]  Detaching from specific interfaces: %v", interfaces)
	} else {
		fullUnload = true

		uniqueInterfaces := make(map[string]bool)

		phyInterfaces, phyErr := xdp.GetPhysicalInterfaces()
		if phyErr == nil {
			for _, iface := range phyInterfaces {
				uniqueInterfaces[iface] = true
			}
		}

		for _, iface := range globalCfg.Base.Interfaces {
			uniqueInterfaces[iface] = true
		}

		attachedIfaces, attachErr := xdp.GetAttachedInterfaces(GetPinPath())
		if attachErr == nil {
			for _, iface := range attachedIfaces {
				uniqueInterfaces[iface] = true
			}
		}

		for iface := range uniqueInterfaces {
			interfaces = append(interfaces, iface)
		}
		log.Infof("[INFO]  Detaching from all detected interfaces: %v", interfaces)
	}

	manager, err := xdp.NewManager(globalCfg.Capacity, log)
	if err != nil {
		return fmt.Errorf("failed to create XDP manager: %v", err)
	}
	defer manager.Close()

	if err := manager.Detach(interfaces); err != nil {
		log.Warnf("[WARN]  Some interfaces could not be detached: %v", err)
	}

	if fullUnload {
		if err := manager.Unpin(GetPinPath()); err != nil {
			log.Warnf("[WARN]  Could not unpin all maps: %v", err)
		}
		log.Info("[OK] XDP driver removed and maps unpinned.")
	} else {
		log.Infof("[OK] XDP driver detached from %v", interfaces)
	}
	return nil
}

func ReloadXDP(ctx context.Context, cliInterfaces []string) error {
	log := logger.Get(ctx)
	log.Info("[RELOAD] Starting hot-reload of XDP program...")

	globalCfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	interfaces, err := daemon.ResolveRuntimeInterfaces(cliInterfaces, globalCfg, log)
	if err != nil {
		return err
	}

	oldManager, err := xdp.NewManagerFromPins(GetPinPath(), log)
	if err != nil {
		log.Info("[INFO]  No existing XDP program found. Performing clean install...")
		return InstallXDP(ctx, cliInterfaces)
	}

	return reloadExistingManager(ctx, oldManager, globalCfg, interfaces, globalCfg, log)
}

// reloadExistingManager handles reload when an existing manager is found.
// reloadExistingManager 处理发现现有管理器时的重载。
func reloadExistingManager(ctx context.Context, oldManager *xdp.Manager, globalCfg *types.GlobalConfig, interfaces []string, oldCfg *types.GlobalConfig, log *zap.SugaredLogger) error {
	defer oldManager.Close()

	oldAdapter := xdp.NewAdapter(oldManager)
	pluginCtx := &sdk.PluginContext{
		Context: ctx,
		Manager: oldAdapter,
		Config:  globalCfg,
		Logger:  log,
	}

	if oldManager.MatchesCapacity(globalCfg.Capacity) {
		return performIncrementalReload(oldManager, globalCfg, interfaces, pluginCtx, oldCfg, log)
	}

	return performFullMigration(ctx, oldManager, globalCfg, interfaces, log)
}

// performIncrementalReload performs incremental reload when capacity matches.
// performIncrementalReload 当容量匹配时执行增量重载。
func performIncrementalReload(oldManager *xdp.Manager, globalCfg *types.GlobalConfig, interfaces []string, pluginCtx *sdk.PluginContext, oldCfg *types.GlobalConfig, log *zap.SugaredLogger) error {
	log.Info("⚡ Capacity unchanged. Performing incremental hot-reload...")

	updater := oldManager.IncrementalUpdater()
	if updater != nil {
		diff, diffErr := updater.ComputeDiff(oldCfg, globalCfg)
		if diffErr != nil {
			log.Warnf("[WARN]  Failed to compute config diff: %v", diffErr)
		} else if diff.HasChanges() {
			log.Infof("[STATS] Config changes detected: %s", diff.Summary())
			if err := updater.ApplyDiff(diff); err != nil {
				log.Warnf("[WARN]  Incremental update had errors: %v", err)
			} else {
				log.Info("[OK] Incremental config update applied successfully")
			}
		} else {
			log.Info("[INFO]  No config changes detected")
		}
	}

	daemon.ReloadPlugins(pluginCtx, log)

	if err := oldManager.Attach(interfaces); err != nil {
		log.Warnf("[WARN]  Failed to update XDP program: %v", err)
	}

	log.Info("[START] Incremental reload completed successfully.")
	return nil
}

// performFullMigration performs full state migration when capacity changes.
// performFullMigration 当容量变更时执行完整状态迁移。
func performFullMigration(ctx context.Context, oldManager *xdp.Manager, globalCfg *types.GlobalConfig, interfaces []string, log *zap.SugaredLogger) error {
	log.Info("[DATA] Capacity changed. Performing full state migration...")

	newManager, err := xdp.NewManager(globalCfg.Capacity, log)
	if err != nil {
		return fmt.Errorf("failed to create new XDP manager: %v", err)
	}

	if err := newManager.MigrateState(oldManager); err != nil {
		log.Warnf("[WARN]  State migration partial or failed: %v", err)
	}
	oldManager.Close()

	if err := newManager.Pin(GetPinPath()); err != nil {
		return fmt.Errorf("failed to pin new maps: %v", err)
	}
	if err := newManager.Attach(interfaces); err != nil {
		return fmt.Errorf("failed to attach new XDP program: %v", err)
	}

	newAdapter := xdp.NewAdapter(newManager)
	newSDK := sdk.NewSDK(newAdapter)
	webHost := api.NewServer(newSDK, globalCfg.Web.Port)
	newCtx := daemon.BuildPluginContext(ctx, nil, newAdapter, globalCfg, log, newSDK, webHost)

	daemon.ReloadPlugins(newCtx, log)

	log.Info("[START] Full hot-reload with state migration completed successfully.")
	return nil
}

/**
 * RunWebServer starts the API and UI server.
 * RunWebServer 启动 API 和 UI 服务器。
 */
func AttachXDPWithMode(ctx context.Context, interfaces []string, mode string) ([]string, error) {
	globalCfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if globalCfg == nil {
		return nil, fmt.Errorf("config is nil after loading")
	}

	log := logger.Get(ctx)
	manager, err := xdp.NewManager(globalCfg.Capacity, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create XDP manager: %w", err)
	}
	defer manager.Close()

	if err := manager.Pin(GetPinPath()); err != nil {
		return nil, fmt.Errorf("failed to pin maps: %w", err)
	}

	var attachMode link.XDPAttachFlags
	var attachModeName string
	switch mode {
	case "offload":
		attachMode = link.XDPOffloadMode
		attachModeName = "Offload"
	case "drv":
		attachMode = link.XDPDriverMode
		attachModeName = "Native"
	case "skb":
		attachMode = link.XDPGenericMode
		attachModeName = "Generic"
	default:
		return nil, fmt.Errorf("invalid mode: %s", mode)
	}

	attached := make([]string, 0, len(interfaces))
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Warnf("[WARN]  Skip interface %s: %v", name, err)
			continue
		}

		log.Infof("[INFO]  Attempting to attach XDP on %s with mode: %s", name, attachModeName)
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   manager.XdpFirewall(),
			Interface: iface.Index,
			Flags:     attachMode,
		})
		if err != nil {
			log.Warnf("[WARN]  Failed to attach XDP on %s using %s mode: %v", name, attachModeName, err)
			continue
		}

		linkPath := filepath.Join(GetPinPath(), fmt.Sprintf("link_%s", name))
		_ = os.Remove(linkPath)
		if pinErr := l.Pin(linkPath); pinErr != nil {
			log.Warnf("[WARN]  Failed to pin link on %s: %v", name, pinErr)
			l.Close()
			continue
		}
		log.Infof("[OK] Attached XDP on %s (Mode: %s) and pinned link", name, attachModeName)
		attached = append(attached, name)
	}

	if len(attached) == 0 {
		return nil, fmt.Errorf("failed to attach XDP on any interface")
	}

	return attached, nil
}

/**
 * UnloadXDP provides instructions to unload the program.
 * UnloadXDP 提供卸载程序的指令。
 */
func UnloadXDP() {
	log := logger.Get(nil)
	log.Infof("[BYE] Unloading XDP and cleaning up...")

	log.Infof("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}
