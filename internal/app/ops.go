package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Import pprof for HTTP endpoint profiling / 导入 pprof 用于 HTTP 端点性能分析
	// #nosec G108 // pprof is intentionally exposed for debugging in development
	_ "net/http/pprof"
	"strconv"

	"github.com/cilium/ebpf/link"

	"github.com/netxfw/netxfw/internal/api"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/core"
	"github.com/netxfw/netxfw/internal/core/engine"
	"github.com/netxfw/netxfw/internal/daemon"
	"github.com/netxfw/netxfw/internal/plugins"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// TrafficStats is the app-layer alias for shared runtime traffic statistics.
type TrafficStats = xdp.TrafficStats

// PerformanceStats is the app-layer alias for performance statistics.
type PerformanceStats = xdp.PerformanceStats

// OperationStats is the app-layer alias for per-operation stats.
type OperationStats = xdp.OperationStats

// PluginSlot describes a loaded BPF plugin slot.
type PluginSlot struct {
	Index   int
	Program uint32
}

// IsXDPLoaded returns true if XDP is attached to any interface.
func IsXDPLoaded() bool {
	ifaces, err := xdp.GetAttachedInterfaces(config.GetPinPath())
	return err == nil && len(ifaces) > 0
}

// LoadPerformanceStats returns performance statistics from the manager if available.
func LoadPerformanceStats(mgr sdk.ManagerInterface) (*PerformanceStats, error) {
	if mgr == nil {
		return nil, fmt.Errorf("manager not available")
	}

	perfInterface := mgr.PerfStats()
	if perfInterface == nil {
		return nil, fmt.Errorf("performance statistics not available")
	}

	perfStats, ok := perfInterface.(*xdp.PerformanceStats)
	if !ok {
		return nil, fmt.Errorf("invalid performance statistics type")
	}

	return perfStats, nil
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

	// 1. 加载全局配置 / Load global configuration
	cfgManager := config.GetConfigManager()
	err := cfgManager.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}

	globalCfg := cfgManager.GetConfig()
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	// 2. 解析网络接口 / Resolve network interfaces
	interfaces, err := resolveInterfaces(cliInterfaces, globalCfg, log)
	if err != nil {
		return err
	}

	// 3. 创建 XDP 管理器 / Create XDP manager
	// 检查是否已有固定的 maps，如果有则加载现有的管理器
	// Check if maps are already pinned, if so load existing manager
	manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err != nil {
		// No pinned maps found, create new manager
		// 未找到固定的 maps，创建新的管理器
		manager, err = xdp.NewManager(globalCfg.Capacity, log)
		if err != nil {
			return fmt.Errorf("failed to create XDP manager: %v", err)
		}
	} else {
		log.Infof("[INFO]  Loaded existing manager from pinned maps")
	}

	// 4. 固定 BPF maps 到文件系统 / Pin BPF maps to filesystem
	if err := manager.Pin(config.GetPinPath()); err != nil {
		return fmt.Errorf("failed to pin maps: %v", err)
	}

	// 5. 同步配置和规则到 BPF maps / Sync configuration and rules to BPF maps
	log.Infof("[SYNC] Syncing global config and loading persisted rules...")
	if err := manager.SyncFromFiles(globalCfg, false); err != nil {
		log.Warnf("[WARN]  Failed to sync config and load rules: %v (continuing anyway)", err)
	}

	// 6. 挂载 XDP 程序到网络接口 / Attach XDP program to network interfaces
	if err := manager.Attach(interfaces); err != nil {
		return fmt.Errorf("failed to attach XDP: %v", err)
	}
	// 分离孤立接口 / Detach orphaned interfaces
	detachOrphanedInterfaces(manager, interfaces, log)

	// 加载 BPF 插件 / Load BPF plugins
	if err := loadBPFPlugins(manager, globalCfg, log); err != nil {
		log.Warnf("[WARN]  Failed to load BPF plugins: %v (continuing anyway)", err)
	}

	// 7. 初始化 SDK 和插件上下文 / Initialize SDK and plugin context
	s := sdk.NewSDK(xdp.NewAdapter(manager))
	pluginCtx := &sdk.PluginContext{
		Context: ctx,
		Manager: s.GetManager(),
		Config:  globalCfg,
		Logger:  log,
		SDK:     s,
	}

	// 8. 初始化并启动核心模块 / Initialize and start core modules
	coreModules := []engine.CoreModule{
		&engine.BaseModule{},      // 基础模块：默认策略、ICMP 速率限制 / Base module: default policy, ICMP rate limit
		&engine.ConntrackModule{}, // 连接跟踪模块 / Connection tracking module
		&engine.PortModule{},      // 端口管理模块 / Port management module
		&engine.RateLimitModule{}, // 速率限制模块 / Rate limit module
	}

	for _, mod := range coreModules {
		if err := mod.Init(globalCfg, s, log); err != nil {
			return fmt.Errorf("[ERROR] Failed to init core module %s: %v", mod.Name(), err)
		}
		if err := mod.Start(); err != nil {
			return fmt.Errorf("[ERROR] Failed to start core module %s: %v", mod.Name(), err)
		}
	}

	// 9. 初始化并启动插件 / Initialize and start plugins
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Errorf("[WARN]  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}

		if err := p.Start(pluginCtx); err != nil {
			log.Errorf("[WARN]  Failed to start plugin %s: %v", p.Name(), err)
		}
	}

	log.Infof("[START] XDP program installed successfully and pinned to %s", config.GetPinPath())
	return nil
}

// resolveInterfaces resolves the interfaces to use for XDP.
// resolveInterfaces 解析用于 XDP 的接口。
func resolveInterfaces(cliInterfaces []string, globalCfg *types.GlobalConfig, log *zap.SugaredLogger) ([]string, error) {
	if len(cliInterfaces) > 0 {
		log.Infof("[INFO]  Using CLI provided interfaces: %v", cliInterfaces)
		return cliInterfaces, nil
	}

	if len(globalCfg.Base.Interfaces) > 0 {
		log.Infof("[INFO]  Using configured interfaces: %v", globalCfg.Base.Interfaces)
		return globalCfg.Base.Interfaces, nil
	}

	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no physical interfaces found")
	}
	log.Infof("[INFO]  Auto-detected interfaces: %v", interfaces)
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
		log.Infof("[INFO]  Detaching from removed interfaces: %v", toDetach)
		if err := manager.Detach(toDetach); err != nil {
			log.Warnf("[WARN]  Failed to detach from removed interfaces: %v", err)
		}
	}
}

// GetAttachedInterfaceInfos returns detailed XDP attachment information.
func GetAttachedInterfaceInfos() ([]xdp.InterfaceXDPInfo, error) {
	return xdp.GetAttachedInterfacesWithInfo(config.GetPinPath())
}

// LoadTrafficStats returns shared runtime traffic statistics.
func LoadTrafficStats() (xdp.TrafficStats, error) {
	return xdp.LoadTrafficStats()
}

// GetConntrackMax returns configured conntrack capacity with a default fallback.
func GetConntrackMax() int {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err == nil {
		if cfg := cfgManager.GetCapacityConfig(); cfg != nil && cfg.Conntrack > 0 {
			return cfg.Conntrack
		}
	}
	return 100000
}

// loadBPFPlugins loads BPF plugins configured in the global config.
// loadBPFPlugins 加载全局配置中配置的 BPF 插件。
func loadBPFPlugins(manager *xdp.Manager, globalCfg *types.GlobalConfig, log *zap.SugaredLogger) error {
	// Check if BPF plugin loading is enabled / 检查是否启用 BPF 插件加载
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
		// Skip disabled plugins / 跳过已禁用的插件
		if !plugin.Enabled {
			log.Infof("[INFO]  Skipping disabled plugin: %s (index %d)", plugin.Path, plugin.Index)
			continue
		}

		// Validate plugin index / 验证插件索引
		if plugin.Index < xdp.ProgIdxPluginStart || plugin.Index > xdp.ProgIdxPluginEnd {
			log.Warnf("[WARN]  Invalid plugin index %d for %s (must be %d-%d)",
				plugin.Index, plugin.Path, xdp.ProgIdxPluginStart, xdp.ProgIdxPluginEnd)
			loadErrors = append(loadErrors, fmt.Sprintf("%s: invalid index %d", plugin.Path, plugin.Index))
			continue
		}

		// Load the plugin / 加载插件
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

// InitConfiguration initializes the default configuration file if needed.
func InitConfiguration(ctx context.Context) {
	core.InitConfiguration(ctx)
}

// TestConfiguration validates the current configuration.
func TestConfiguration(ctx context.Context) {
	daemon.TestConfiguration(ctx)
}

/**
 * RunDaemon starts the background process for metrics and rule synchronization.
 * RunDaemon 启动用于指标和规则同步的后台进程。
 */
func RunDaemon(ctx context.Context) {
	InitConfiguration(ctx)
	TestConfiguration(ctx)
	daemon.Run(ctx, runtime.Mode, nil)
}

/**
 * RunDaemonWithInterfaces starts the background process for metrics and rule synchronization with specific interfaces.
 * RunDaemonWithInterfaces 启动用于指标和规则同步的后台进程，支持指定接口。
 */
func RunDaemonWithInterfaces(ctx context.Context, interfaces []string) {
	InitConfiguration(ctx)
	TestConfiguration(ctx)
	opts := &daemon.DaemonOptions{
		Interfaces: interfaces,
	}
	daemon.Run(ctx, runtime.Mode, opts)
}

// LoadConfig loads the current configuration using the configured path.
func LoadConfig() (*sdk.GlobalConfig, error) {
	cfgPath := config.GetConfigPath()
	cfg, err := types.LoadGlobalConfig(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	return cfg, nil
}

// SaveConfigWithBackup persists configuration using the configured backup policy.
func SaveConfigWithBackup(cfg *sdk.GlobalConfig) error {
	return types.SaveGlobalConfigWithBackup(config.GetConfigPath(), cfg, config.GetBackupKeep())
}

// WithConfigLock runs fn while holding the shared config persistence mutex.
func WithConfigLock(fn func() error) error {
	types.ConfigMu.Lock()
	defer types.ConfigMu.Unlock()
	return fn()
}

// SyncRuntimeToConfig dumps runtime BPF state into configuration files.
func SyncRuntimeToConfig(s *sdk.SDK) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	return s.Sync.ToConfig(cfg)
}

// SyncConfigToRuntime applies configuration files to runtime BPF maps.
func SyncConfigToRuntime(s *sdk.SDK, overwrite bool) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	return s.Sync.ToMap(cfg, overwrite)
}

// SyncConfigToRuntimeOverwrite applies configuration files to runtime BPF maps with overwrite enabled.
func SyncConfigToRuntimeOverwrite(s *sdk.SDK) error {
	return SyncConfigToRuntime(s, true)
}

/**
 * HandlePluginCommand processes plugin-related CLI commands.
 * HandlePluginCommand 处理与插件相关的 CLI 命令。
 */
func HandlePluginCommand(ctx context.Context, args []string) error {
	log := logger.Get(ctx)
	if len(args) < 1 {
		return fmt.Errorf("usage: netxfw plugin <load|remove|list>")
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
	case "list":
		return nil
	default:
		return fmt.Errorf("unknown plugin command: %s", args[0])
	}
	log.Infof("[OK] Plugin command %s executed successfully", args[0])
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
		log.Warnf("[WARN]  Failed to load global config, using default map capacity: %v", err)
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
		log.Infof("[INFO]  Detaching from specific interfaces: %v", interfaces)
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
		if err := manager.Unpin(config.GetPinPath()); err != nil {
			log.Warnf("[WARN]  Could not unpin all maps: %v", err)
		}
		log.Info("[OK] XDP driver removed and maps unpinned.")
	} else {
		log.Infof("[OK] XDP driver detached from %v", interfaces)
	}
	return nil
}

// ReloadXDP performs a hot-reload of the XDP program.
// It loads new objects, migrates state from old pinned maps, and swaps the program.
// ReloadXDP 执行 XDP 程序的平滑重载：加载新对象，从旧的固定 Map 迁移状态，并切换程序。
func ListLoadedPlugins(ctx context.Context) ([]PluginSlot, error) {
	log := logger.Get(ctx)
	manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	var slots []PluginSlot
	for i := xdp.ProgIdxPluginStart; i <= xdp.ProgIdxPluginEnd; i++ {
		var progID uint32
		if err := manager.JmpTable().Lookup(uint32(i), &progID); err == nil {
			slots = append(slots, PluginSlot{Index: i, Program: progID})
		}
	}
	return slots, nil
}

func ClearBlacklist(ctx context.Context, dynamic bool) error {
	log := logger.Get(ctx)
	manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err != nil {
		return fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	if dynamic {
		return xdp.ClearBlacklistMap(manager.DynLockList())
	}
	return xdp.ClearBlacklistMap(manager.LockList())
}

func ReloadPinnedMaps(ctx context.Context) error {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}

	globalCfg := cfgManager.GetConfig()
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	log := logger.Get(ctx)
	manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err != nil {
		return fmt.Errorf("failed to load XDP manager: %v", err)
	}
	defer manager.Close()

	if err := manager.SyncFromFiles(globalCfg, false); err != nil {
		return fmt.Errorf("failed to sync configuration to BPF maps: %v", err)
	}

	return nil
}

func ReloadXDP(ctx context.Context, cliInterfaces []string) error {
	log := logger.Get(ctx)
	log.Info("[RELOAD] Starting hot-reload of XDP program...")

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
		log.Info("[INFO]  No existing XDP program found. Performing clean install...")
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

	reloadPlugins(pluginCtx, log)

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

	log.Info("[START] Full hot-reload with state migration completed successfully.")
	return nil
}

// reloadPlugins reloads all plugins.
// reloadPlugins 重载所有插件。
func reloadPlugins(pluginCtx *sdk.PluginContext, log *zap.SugaredLogger) {
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(pluginCtx); err != nil {
			log.Warnf("[WARN]  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Reload(pluginCtx); err != nil {
			log.Warnf("[WARN]  Failed to reload plugin %s: %v", p.Name(), err)
		}
	}
}

/**
 * RunWebServer starts the API and UI server.
 * RunWebServer 启动 API 和 UI 服务器。
 */
func AttachXDPWithMode(ctx context.Context, interfaces []string, mode string) ([]string, error) {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	globalCfg := cfgManager.GetConfig()
	if globalCfg == nil {
		return nil, fmt.Errorf("config is nil after loading")
	}

	log := logger.Get(ctx)
	manager, err := xdp.NewManager(globalCfg.Capacity, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create XDP manager: %w", err)
	}
	defer manager.Close()

	if err := manager.Pin(config.GetPinPath()); err != nil {
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

		linkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("link_%s", name))
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

func RunWebServer(ctx context.Context, port int) error {
	log := logger.Get(ctx)
	// 1. Try to load manager from pins / 尝试从固定点加载管理器
	manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
	if err != nil {
		log.Warnf("[WARN]  Could not load pinned maps (is XDP loaded?): %v", err)
		return fmt.Errorf("web server requires netxfw XDP to be loaded. Run 'netxfw system load' first")
	}
	defer manager.Close()

	// 2. Start API server / 启动 API 服务器
	adapter := xdp.NewAdapter(manager)
	s := sdk.NewSDK(adapter)
	server := api.NewServer(s, port)

	addr := fmt.Sprintf(":%d", port)
	log.Infof("[START] Management API and UI starting on http://localhost%s", addr)

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
	log.Infof("[BYE] Unloading XDP and cleaning up...")
	// Cleanup is handled by the server process on exit.
	// 卸载和清理通常在服务器进程退出时处理。
	log.Infof("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}
