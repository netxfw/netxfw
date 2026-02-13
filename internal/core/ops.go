package core

import (
	"log"
	_ "net/http/pprof"
	"strconv"

	"github.com/livp123/netxfw/internal/api"
	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/livp123/netxfw/internal/xdp"
)

/**
 * InstallXDP initializes the XDP manager and mounts the program to interfaces, then exits.
 * InstallXDP 初始化 XDP 管理器并将程序挂载到接口，然后退出。
 */
func InstallXDP(cliInterfaces []string) {
	// Load global configuration first to get interface settings / 首先加载全局配置以获取接口设置
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	var interfaces []string
	if len(cliInterfaces) > 0 {
		interfaces = cliInterfaces
		log.Printf("ℹ️  Using CLI provided interfaces: %v", interfaces)
	} else if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
		log.Printf("ℹ️  Using configured interfaces: %v", interfaces)
	} else {
		// Auto-detect if no interfaces configured / 如果未配置接口，则自动检测
		interfaces, err = xdp.GetPhysicalInterfaces()
		if err != nil {
			log.Fatalf("❌ Failed to get interfaces: %v", err)
		}
		if len(interfaces) == 0 {
			log.Fatal("❌ No physical interfaces found")
		}
		log.Printf("ℹ️  Auto-detected interfaces: %v", interfaces)
	}

	manager, err := xdp.NewManager(globalCfg.Capacity)
	if err != nil {
		log.Fatalf("❌ Failed to create XDP manager: %v", err)
	}

	if err := manager.Pin("/sys/fs/bpf/netxfw"); err != nil {
		log.Fatalf("❌ Failed to pin maps: %v", err)
	}

	if err := manager.Attach(interfaces); err != nil {
		log.Fatalf("❌ Failed to attach XDP: %v", err)
	}

	// Detach from interfaces that are not in the current configuration
	// 移除未在当前配置中的接口上的 XDP
	if attachedIfaces, err := xdp.GetAttachedInterfaces("/sys/fs/bpf/netxfw"); err == nil {
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
			log.Printf("ℹ️  Detaching from removed interfaces: %v", toDetach)
			if err := manager.Detach(toDetach); err != nil {
				log.Printf("⚠️  Failed to detach from removed interfaces: %v", err)
			}
		}
	}

	// Start all plugins to apply configurations / 启动所有插件以应用配置
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(globalCfg); err != nil {
			log.Printf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(manager); err != nil {
			log.Printf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
		defer p.Stop()
	}

	log.Println("🚀 XDP program installed successfully and pinned to /sys/fs/bpf/netxfw")
}

/**
 * RunDaemon starts the background process for metrics and rule synchronization.
 * RunDaemon 启动用于指标和规则同步的后台进程。
 */
func RunDaemon() {
	InitConfiguration()
	TestConfiguration()
	daemon.Run(runtime.Mode)
}

/**
 * HandlePluginCommand processes plugin-related CLI commands.
 * HandlePluginCommand 处理与插件相关的 CLI 命令。
 */
func HandlePluginCommand(args []string) {
	if len(args) < 1 {
		log.Println("Usage: netxfw plugin <load|remove> ...")
		return
	}

	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	switch args[0] {
	case "load":
		if len(args) < 3 {
			log.Fatal("Usage: netxfw plugin load <path_to_elf> <index (2-15)>")
		}
		path := args[1]
		idx, err := strconv.Atoi(args[2])
		if err != nil {
			log.Fatalf("❌ Invalid index: %v", err)
		}
		if err := manager.LoadPlugin(path, idx); err != nil {
			log.Fatalf("❌ Failed to load plugin: %v", err)
		}
	case "remove":
		if len(args) < 2 {
			log.Fatal("Usage: netxfw plugin remove <index (2-15)>")
		}
		idx, err := strconv.Atoi(args[1])
		if err != nil {
			log.Fatalf("❌ Invalid index: %v", err)
		}
		if err := manager.RemovePlugin(idx); err != nil {
			log.Fatalf("❌ Failed to remove plugin: %v", err)
		}
	default:
		log.Printf("Unknown plugin command: %s", args[0])
	}
}

/**
 * RemoveXDP detaches the XDP program from all interfaces and unpins everything.
 * RemoveXDP 从所有接口分离 XDP 程序并取消所有固定。
 */
func RemoveXDP(cliInterfaces []string) {
	// Load global configuration to get max entries (needed for NewManager)
	// 加载全局配置以获取最大条目数（NewManager 需要）
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Printf("⚠️  Failed to load global config, using default map capacity: %v", err)
		globalCfg = &types.GlobalConfig{}
	}

	var interfaces []string
	fullUnload := false

	if len(cliInterfaces) > 0 {
		interfaces = cliInterfaces
		log.Printf("ℹ️  Detaching from specific interfaces: %v", interfaces)
	} else {
		fullUnload = true
		// Collect all potential interfaces to detach from / 收集所有可能的分离接口
		uniqueInterfaces := make(map[string]bool)

		// 1. Get physical interfaces / 获取物理接口
		if phyInterfaces, err := xdp.GetPhysicalInterfaces(); err == nil {
			for _, iface := range phyInterfaces {
				uniqueInterfaces[iface] = true
			}
		}

		// 2. Get configured interfaces / 获取已配置的接口
		for _, iface := range globalCfg.Base.Interfaces {
			uniqueInterfaces[iface] = true
		}

		for iface := range uniqueInterfaces {
			interfaces = append(interfaces, iface)
		}

		if len(interfaces) == 0 {
			log.Println("⚠️  No interfaces found to detach from.")
		} else {
			log.Printf("ℹ️  Detaching from all detected interfaces: %v", interfaces)
		}
	}

	manager, err := xdp.NewManager(globalCfg.Capacity)
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager for removal: %v", err)
	}
	defer manager.Close()

	if err := manager.Detach(interfaces); err != nil {
		log.Printf("⚠️  Some interfaces failed to detach: %v", err)
	}

	if fullUnload {
		if err := manager.Unpin("/sys/fs/bpf/netxfw"); err != nil {
			log.Printf("⚠️  Unpin warning: %v", err)
		}
		log.Println("✅ XDP program removed and cleanup completed.")
	} else {
		log.Println("✅ XDP program detached from specified interfaces.")
	}
}

/**
 * ReloadXDP performs a hot-reload of the XDP program.
 * It loads new objects, migrates state from old pinned maps, and swaps the program.
 * ReloadXDP 执行 XDP 程序的平滑重载：加载新对象，从旧的固定 Map 迁移状态，并切换程序。
 **/

func ReloadXDP(cliInterfaces []string) {
	log.Println("🔄 Starting hot-reload of XDP program...")

	// 1. Load global configuration / 加载全局配置
	globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	var interfaces []string
	if len(cliInterfaces) > 0 {
		interfaces = cliInterfaces
		log.Printf("ℹ️  Using CLI provided interfaces: %v", interfaces)
	} else if len(globalCfg.Base.Interfaces) > 0 {
		interfaces = globalCfg.Base.Interfaces
		log.Printf("ℹ️  Using configured interfaces: %v", interfaces)
	} else {
		interfaces, err = xdp.GetPhysicalInterfaces()
		if err != nil {
			log.Fatalf("❌ Failed to get interfaces: %v", err)
		}
		log.Printf("ℹ️  Auto-detected interfaces: %v", interfaces)
	}

	// 2. Initialize new manager with new capacities / 使用新容量初始化新管理器
	newManager, err := xdp.NewManager(globalCfg.Capacity)
	if err != nil {
		log.Fatalf("❌ Failed to create new XDP manager: %v", err)
	}

	// 3. Try to load old manager from pins to migrate state / 尝试从固定点加载旧管理器以迁移状态
	oldManager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err == nil {
		log.Println("📦 Migrating state from old BPF maps...")
		if err := newManager.MigrateState(oldManager); err != nil {
			log.Printf("⚠️  State migration partial or failed: %v", err)
		}
		oldManager.Close()
	} else {
		log.Println("ℹ️  No existing pinned maps found, starting fresh.")
	}

	// 4. Update pins: Pin new maps (this ensures the directory exists for Attach)
	// 更新固定：固定新 Map（这确保了 Attach 的目录存在）
	if err := newManager.Pin("/sys/fs/bpf/netxfw"); err != nil {
		log.Fatalf("❌ Failed to pin new maps: %v", err)
	}

	// 5. Atomic swap: Attach new manager to interfaces
	// This will atomically replace the program if a pinned link exists
	// 原子交换：将新管理器附加到接口。如果存在固定的 link，这将原子地替换程序。
	if err := newManager.Attach(interfaces); err != nil {
		log.Fatalf("❌ Failed to attach new XDP program: %v", err)
	}

	// Detach from interfaces that are not in the current configuration
	// 移除未在当前配置中的接口上的 XDP
	if attachedIfaces, err := xdp.GetAttachedInterfaces("/sys/fs/bpf/netxfw"); err == nil {
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
			log.Printf("ℹ️  Detaching from removed interfaces: %v", toDetach)
			if err := newManager.Detach(toDetach); err != nil {
				log.Printf("⚠️  Failed to detach from removed interfaces: %v", err)
			}
		}
	}

	// 6. Start all plugins to apply configurations / 启动所有插件以应用配置
	for _, p := range plugins.GetPlugins() {
		if err := p.Init(globalCfg); err != nil {
			log.Printf("⚠️  Failed to init plugin %s: %v", p.Name(), err)
			continue
		}
		if err := p.Start(newManager); err != nil {
			log.Printf("⚠️  Failed to start plugin %s: %v", p.Name(), err)
		}
		// Note: We don't defer Stop() here because reload is a one-shot command
	}

	log.Println("🚀 XDP program reloaded successfully with updated configuration and capacity.")
}

/**
 * RunWebServer starts the API and UI server.
 * RunWebServer 启动 API 和 UI 服务器。
 */
func RunWebServer(port int) {
	// 1. Try to load manager from pins / 尝试从固定点加载管理器
	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Printf("⚠️  Could not load pinned maps (is XDP loaded?): %v", err)
		log.Fatal("❌ Web server requires netxfw XDP to be loaded. Run 'netxfw system load' first.")
	}
	defer manager.Close()

	// 2. Start API server / 启动 API 服务器
	server := api.NewServer(manager, port)
	if err := server.Start(); err != nil {
		log.Fatalf("❌ Failed to start web server: %v", err)
	}
}

/**
 * UnloadXDP provides instructions to unload the program.
 * UnloadXDP 提供卸载程序的指令。
 */
func UnloadXDP() {
	log.Println("👋 Unloading XDP and cleaning up...")
	// Cleanup is handled by the server process on exit.
	log.Println("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}
