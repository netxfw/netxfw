package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"gopkg.in/yaml.v3"

	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

/**
 * isIPv6 checks if the given IP string (or CIDR) is IPv6.
 * isIPv6 检查给定的 IP 字符串（或 CIDR）是否为 IPv6。
 */
func isIPv6(ipStr string) bool {
	ip, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		ip = net.ParseIP(ipStr)
	}
	return ip != nil && ip.To4() == nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	command := os.Args[1]
	switch command {
	case "init":
		// Initialize configuration / 初始化配置
		initConfiguration()
	case "test":
		// Test configuration / 测试配置
		testConfiguration()
	case "load":
		// Load XDP program / 加载 XDP 程序
		if len(os.Args) < 3 || os.Args[2] != "xdp" {
			usage()
			return
		}
		// Automatically run init to ensure directory and configs exist
		initConfiguration()
		installXDP()
	case "daemon":
		// Start daemon for metrics and sync / 启动常驻进程
		runDaemon()
	case "lock":
		// Block an IP or CIDR / 封禁 IP 或网段
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing IP address")
		}
		syncLockMap(os.Args[2], true)
	case "unlock":
		// Unblock an IP or CIDR / 解封 IP 或网段
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing IP address")
		}
		syncLockMap(os.Args[2], false)
	case "allow-port":
		// Allow a port globally / 全局允许端口
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing port number")
		}
		var port uint16
		fmt.Sscanf(os.Args[2], "%d", &port)
		syncAllowedPort(port, true)
	case "disallow-port":
		// Remove port from global allow list / 从全局允许列表移除端口
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing port number")
		}
		var port uint16
		fmt.Sscanf(os.Args[2], "%d", &port)
		syncAllowedPort(port, false)
	case "add-rule":
		// Add IP+Port rule / 添加 IP+端口规则
		if len(os.Args) < 5 {
			log.Fatal("Usage: ./netxfw add-rule <IP/CIDR> <PORT> <ACTION: 1=allow, 2=deny>")
		}
		var port uint16
		var action uint8
		fmt.Sscanf(os.Args[3], "%d", &port)
		fmt.Sscanf(os.Args[4], "%d", &action)
		syncIPPortRule(os.Args[2], port, action, true)
	case "remove-rule":
		// Remove IP+Port rule / 移除 IP+端口规则
		if len(os.Args) < 4 {
			log.Fatal("Usage: ./netxfw remove-rule <IP/CIDR> <PORT>")
		}
		var port uint16
		fmt.Sscanf(os.Args[3], "%d", &port)
		syncIPPortRule(os.Args[2], port, 0, false)
	case "set-default-deny":
		// Enable/disable default deny / 启用/禁用默认拒绝
		if len(os.Args) < 3 {
			log.Fatal("Usage: ./netxfw set-default-deny <true/false>")
		}
		enable := os.Args[2] == "true"
		syncDefaultDeny(enable)
	case "allow":
		// Whitelist an IP or CIDR / 将 IP 或网段加入白名单
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing IP address")
		}
		syncWhitelistMap(os.Args[2], true)
	case "unallow":
		// Remove an IP or CIDR from whitelist / 将 IP 或网段从白名单移除
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing IP address")
		}
		syncWhitelistMap(os.Args[2], false)
	case "list":
		// List blocked ranges / 查看封禁列表
		showLockList()
	case "allow-list":
		// List whitelisted ranges / 查看白名单列表
		showWhitelist()
	case "import":
		// Import list from file / 从文件导入列表
		if len(os.Args) < 4 {
			usage()
			return
		}
		subCommand := os.Args[2]
		filePath := os.Args[3]
		switch subCommand {
		case "lock":
			importLockListFromFile(filePath)
		case "allow":
			importWhitelistFromFile(filePath)
		case "rules":
			importIPPortRulesFromFile(filePath)
		default:
			usage()
		}
	case "list-rules":
		// List IP+Port rules / 查看 IP+端口规则列表
		showIPPortRules()
	case "unload":
		// Unload XDP program / 卸载 XDP 程序
		if len(os.Args) < 3 || os.Args[2] != "xdp" {
			usage()
			return
		}
		removeXDP()
	default:
		usage()
	}
}

/**
 * usage prints command line help.
 * usage 打印命令行帮助信息。
 */
func usage() {
	fmt.Println("Usage:")
	fmt.Println("  ./netxfw init            # 初始化 /etc/netxfw 目录及默认配置文件")
	fmt.Println("  ./netxfw test            # 测试配置文件是否有错误")
	fmt.Println("  ./netxfw load xdp        # 安装 XDP 程序到内核 (安装即退出)")
	fmt.Println("  ./netxfw daemon          # 启动后台进程 (监控指标与同步规则)")
	fmt.Println("  ./netxfw lock 1.2.3.4    # 封禁 IP 或网段 (如 192.168.1.0/24)")
	fmt.Println("  ./netxfw unlock 1.2.3.4  # 解封 IP 或网段")
	fmt.Println("  ./netxfw allow 1.2.3.4   # 将 IP 或网段加入白名单")
	fmt.Println("  ./netxfw unallow 1.2.3.4 # 将 IP 或网段从白名单移除")
	fmt.Println("  ./netxfw list                  # 查看封禁 IP 列表及拦截统计")
	fmt.Println("  ./netxfw allow-list            # 查看白名单 IP 列表")
	fmt.Println("  ./netxfw list-rules            # 查看 IP+端口规则列表")
	fmt.Println("  ./netxfw allow-port 80         # 全局允许 80 端口")
	fmt.Println("  ./netxfw disallow-port 80      # 从全局允许列表移除 80 端口")
	fmt.Println("  ./netxfw add-rule 1.2.3.4 80 1 # 允许特定 IP 访问特定端口 (1:allow, 2:deny)")
	fmt.Println("  ./netxfw remove-rule 1.2.3.4 80 # 移除特定 IP+端口规则")
	fmt.Println("  ./netxfw set-default-deny true # 开启默认拒绝策略")
	fmt.Println("  ./netxfw import lock file.txt  # 从文件批量导入封禁列表")
	fmt.Println("  ./netxfw import allow file.txt # 从文件批量导入白名单列表")
	fmt.Println("  ./netxfw import rules file.txt # 从文件批量导入 IP+端口规则 (格式: ip port action)")
	fmt.Println("  ./netxfw unload xdp            # 从网卡卸载 XDP 程序")
}

func initConfiguration() {
	configDir := "/etc/netxfw"
	configPath := configDir + "/config.yaml"

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("❌ Failed to create config directory %s: %v", configDir, err)
		}
		log.Printf("📂 Created config directory: %s", configDir)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		globalCfg := types.GlobalConfig{}
		// Get default configs from plugins
		for _, p := range plugins.GetPlugins() {
			switch p.Name() {
			case "base":
				globalCfg.Base = p.DefaultConfig().(types.BaseConfig)
			case "port":
				globalCfg.Port = p.DefaultConfig().(types.PortConfig)
			case "metrics":
				globalCfg.Metrics = p.DefaultConfig().(types.MetricsConfig)
			}
		}

		data, _ := yaml.Marshal(globalCfg)
		if err := os.WriteFile(configPath, data, 0644); err != nil {
			log.Fatalf("❌ Failed to create config.yaml: %v", err)
		}
		log.Printf("📄 Created default global config: %s", configPath)
	} else {
		log.Printf("ℹ️  Config file already exists: %s", configPath)
	}
}

/**
 * testConfiguration validates the syntax and values of configuration files.
 */
func testConfiguration() {
	configPath := "/etc/netxfw/config.yaml"
	fmt.Printf("🔍 Testing global configuration in %s...\n", configPath)

	cfg, err := LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Error loading config.yaml: %v", err)
	}

	allValid := true
	for _, p := range plugins.GetPlugins() {
		if err := p.Validate(cfg); err != nil {
			fmt.Printf("❌ Validation failed for plugin %s: %v\n", p.Name(), err)
			allValid = false
			continue
		}
		fmt.Printf("✅ Plugin %s configuration is valid\n", p.Name())
	}

	if allValid {
		fmt.Println("🎉 All configurations are valid!")
	} else {
		os.Exit(1)
	}
}

/**
 * installXDP initializes the XDP manager and mounts the program to interfaces, then exits.
 */
func installXDP() {
	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		log.Fatalf("❌ Failed to get interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		log.Fatal("❌ No physical interfaces found")
	}

	manager, err := xdp.NewManager()
	if err != nil {
		log.Fatalf("❌ Failed to create XDP manager: %v", err)
	}

	if err := manager.Pin("/sys/fs/bpf/netxfw"); err != nil {
		log.Fatalf("❌ Failed to pin maps: %v", err)
	}

	if err := manager.Attach(interfaces); err != nil {
		log.Fatalf("❌ Failed to attach XDP: %v", err)
	}

	// Load global configuration
	globalCfg, err := LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	// Start all plugins to apply configurations
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
 * runDaemon starts the background process for metrics and rule synchronization.
 */
func runDaemon() {
	manager, err := xdp.NewManager()
	if err != nil {
		log.Fatalf("❌ Failed to create XDP manager: %v", err)
	}

	// Load global configuration
	globalCfg, err := LoadGlobalConfig("/etc/netxfw/config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	// Register and start plugins
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

	log.Println("🛡️ Daemon is running. Monitoring metrics and managing rules...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("👋 Daemon shutting down (XDP program remains in kernel)...")
}

/**
 * removeXDP detaches the XDP program from all interfaces and unpins everything.
 */
func removeXDP() {
	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		log.Fatalf("❌ Failed to get interfaces: %v", err)
	}

	manager, err := xdp.NewManager()
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager for removal: %v", err)
	}
	defer manager.Close()

	if err := manager.Detach(interfaces); err != nil {
		log.Printf("⚠️  Some interfaces failed to detach: %v", err)
	}

	if err := manager.Unpin("/sys/fs/bpf/netxfw"); err != nil {
		log.Printf("⚠️  Unpin warning: %v", err)
	}

	log.Println("✅ XDP program removed and cleanup completed.")
}

/**
 * syncLockMap interacts with pinned BPF maps to block/unblock ranges.
 * syncLockMap 通过操作固定的 BPF Map 来封禁或解封网段。
 */
func syncLockMap(cidrStr string, lock bool) {
	mapPath := "/sys/fs/bpf/netxfw/lock_list"
	if isIPv6(cidrStr) {
		mapPath = "/sys/fs/bpf/netxfw/lock_list6"
	}

	// Load map from filesystem / 从文件系统加载 Map
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the daemon running?): %v", err)
	}
	defer m.Close()

	if lock {
		if err := xdp.LockIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to lock %s: %v", cidrStr, err)
		}
		log.Printf("🛡️ Locked: %s", cidrStr)
	} else {
		if err := xdp.UnlockIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to unlock %s: %v", cidrStr, err)
		}
		log.Printf("🔓 Unlocked: %s", cidrStr)
	}
}

/**
 * syncWhitelistMap interacts with pinned BPF maps to allow/unallow ranges.
 * syncWhitelistMap 通过操作固定的 BPF Map 来允许或移除白名单网段。
 */
func syncWhitelistMap(cidrStr string, allow bool) {
	mapPath := "/sys/fs/bpf/netxfw/whitelist"
	if isIPv6(cidrStr) {
		mapPath = "/sys/fs/bpf/netxfw/whitelist6"
	}

	// Load map from filesystem
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the daemon running?): %v", err)
	}
	defer m.Close()

	// Update config
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := LoadGlobalConfig(configPath)

	if allow {
		if err := xdp.AllowIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to allow %s: %v", cidrStr, err)
		}
		log.Printf("⚪ Whitelisted: %s", cidrStr)

		if err == nil {
			found := false
			for _, ip := range globalCfg.Base.Whitelist {
				if ip == cidrStr {
					found = true
					break
				}
			}
			if !found {
				globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, cidrStr)
				if err := SaveGlobalConfig(configPath, globalCfg); err != nil {
					log.Printf("⚠️  Failed to save whitelist to config: %v", err)
				}
			}
		}
	} else {
		if err := xdp.UnlockIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to unallow %s: %v", cidrStr, err)
		}
		log.Printf("❌ Removed from whitelist: %s", cidrStr)

		if err == nil {
			newWhitelist := []string{}
			for _, ip := range globalCfg.Base.Whitelist {
				if ip != cidrStr {
					newWhitelist = append(newWhitelist, ip)
				}
			}
			globalCfg.Base.Whitelist = newWhitelist
			if err := SaveGlobalConfig(configPath, globalCfg); err != nil {
				log.Printf("⚠️  Failed to save whitelist to config: %v", err)
			}
		}
	}
}

/**
 * showWhitelist reads and prints all whitelisted ranges.
 * showWhitelist 读取并打印所有白名单中的网段。
 */
func showWhitelist() {
	// List IPv4 whitelist / 列出 IPv4 白名单
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 whitelist: %v", err)
	}
	defer m4.Close()

	ips4, err := xdp.ListWhitelistedIPs(m4, false)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv4 whitelisted IPs: %v", err)
	}

	// List IPv6 whitelist / 列出 IPv6 白名单
	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 whitelist: %v", err)
	}
	defer m6.Close()

	ips6, err := xdp.ListWhitelistedIPs(m6, true)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv6 whitelisted IPs: %v", err)
	}

	if len(ips4) == 0 && len(ips6) == 0 {
		fmt.Println("Empty whitelist.")
		return
	}

	fmt.Println("⚪ Currently whitelisted IPs/ranges:")
	for _, ip := range ips4 {
		fmt.Printf(" - [IPv4] %s\n", ip)
	}
	for _, ip := range ips6 {
		fmt.Printf(" - [IPv6] %s\n", ip)
	}
}

/**
 * showLockList reads and prints all blocked ranges and their stats.
 * showLockList 读取并打印所有已封禁的网段及其统计信息。
 */
func showLockList() {
	// List IPv4 lock list / 列出 IPv4 锁定列表
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 lock list: %v", err)
	}
	defer m4.Close()

	ips4, err := xdp.ListBlockedIPs(m4, false)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv4 locked IPs: %v", err)
	}

	// List IPv6 lock list / 列出 IPv6 锁定列表
	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 lock list: %v", err)
	}
	defer m6.Close()

	ips6, err := xdp.ListBlockedIPs(m6, true)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv6 locked IPs: %v", err)
	}

	if len(ips4) == 0 && len(ips6) == 0 {
		fmt.Println("Empty lock list.")
		return
	}

	fmt.Println("🛡️ Currently locked IPs/ranges and drop counts:")
	for ip, count := range ips4 {
		fmt.Printf(" - [IPv4] %s: %d drops\n", ip, count)
	}
	for ip, count := range ips6 {
		fmt.Printf(" - [IPv6] %s: %d drops\n", ip, count)
	}
}

/**
 * showIPPortRules reads and prints all IP+Port rules.
 */
func showIPPortRules() {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	rules4, err := m.ListIPPortRules(false)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv4 IP+Port rules: %v", err)
	}

	rules6, err := m.ListIPPortRules(true)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv6 IP+Port rules: %v", err)
	}

	ports, err := m.ListAllowedPorts()
	if err != nil {
		log.Fatalf("❌ Failed to list allowed ports: %v", err)
	}

	fmt.Println("🛡️ Current IP+Port Rules:")
	if len(rules4) == 0 && len(rules6) == 0 {
		fmt.Println(" - No IP+Port rules.")
	} else {
		for target, action := range rules4 {
			fmt.Printf(" - [IPv4] %s -> %s\n", target, action)
		}
		for target, action := range rules6 {
			fmt.Printf(" - [IPv6] %s -> %s\n", target, action)
		}
	}

	fmt.Println("\n🔓 Globally Allowed Ports:")
	if len(ports) == 0 {
		fmt.Println(" - No ports globally allowed.")
	} else {
		for _, port := range ports {
			fmt.Printf(" - Port %d\n", port)
		}
	}
}

/**
 * unloadXDP provides instructions to unload the program.
 * unloadXDP 提供卸载程序的指令。
 */
func unloadXDP() {
	log.Println("👋 Unloading XDP and cleaning up...")
	// Cleanup is handled by the server process on exit.
	// 卸载由服务器进程退出时自动处理。
	fmt.Println("Please stop the running 'load xdp' server (e.g., Ctrl+C) to trigger cleanup.")
}

/**
 * loadLockListFromFile reads IPs/CIDRs from a file and loads them into the BPF map.
 * loadLockListFromFile 从文件中读取 IP/CIDR 并加载到 BPF Map 中。
 */
func syncDefaultDeny(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetDefaultDeny(enable); err != nil {
		log.Fatalf("❌ Failed to set default deny: %v", err)
	}

	// Update config
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.DefaultDeny = enable
		if err := SaveGlobalConfig(configPath, globalCfg); err != nil {
			log.Printf("⚠️  Failed to save default_deny to config: %v", err)
		}
	}

	log.Printf("🛡️ Default deny policy set to: %v", enable)
}

func syncAllowedPort(port uint16, allow bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	if allow {
		// Check if already allowed in map
		mapFound := false
		ports, _ := m.ListAllowedPorts()
		for _, p := range ports {
			if p == port {
				mapFound = true
				break
			}
		}

		// Check if already in config
		cfgFound := false
		for _, p := range globalCfg.Port.AllowedPorts {
			if p == port {
				cfgFound = true
				break
			}
		}

		if mapFound && cfgFound {
			log.Printf("ℹ️  Port %d is already globally allowed in both BPF and config.", port)
			return
		}

		if !mapFound {
			if err := m.AllowPort(port, nil); err != nil {
				log.Fatalf("❌ Failed to allow port %d: %v", port, err)
			}
		}

		if !cfgFound {
			globalCfg.Port.AllowedPorts = append(globalCfg.Port.AllowedPorts, port)
			if err := SaveGlobalConfig(configPath, globalCfg); err != nil {
				log.Fatalf("❌ Failed to save config: %v", err)
			}
			log.Printf("📄 Added port %d to config", port)
		}

		if !mapFound || !cfgFound {
			log.Printf("🔓 Port allowed globally: %d (Updated BPF: %v, Updated Config: %v)", port, !mapFound, !cfgFound)
		}
	} else {
		if err := m.RemovePort(port); err != nil {
			log.Fatalf("❌ Failed to disallow port %d: %v", port, err)
		}

		// Update config
		newPorts := []uint16{}
		for _, p := range globalCfg.Port.AllowedPorts {
			if p != port {
				newPorts = append(newPorts, p)
			}
		}
		globalCfg.Port.AllowedPorts = newPorts
		if err := SaveGlobalConfig(configPath, globalCfg); err != nil {
			log.Fatalf("❌ Failed to save config: %v", err)
		}
		log.Printf("🔒 Port removed from global allow list: %d", port)
	}
}

func syncIPPortRule(cidrStr string, port uint16, action uint8, add bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			log.Fatalf("❌ Invalid IP address: %s", cidrStr)
		}
		mask := net.CIDRMask(32, 32)
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		}
		ipNet = &net.IPNet{IP: ip, Mask: mask}
	}

	if add {
		// Check if rule already exists in map
		isIPv6 := ipNet.IP.To4() == nil
		existingRules, _ := m.ListIPPortRules(isIPv6)
		targetKey := fmt.Sprintf("%s:%d", cidrStr, port)
		// Handle potential CIDR normalization (e.g. 1.2.3.4 -> 1.2.3.4/32)
		if !strings.Contains(cidrStr, "/") {
			if isIPv6 {
				targetKey = fmt.Sprintf("%s/128:%d", ipNet.IP.String(), port)
			} else {
				targetKey = fmt.Sprintf("%s/32:%d", ipNet.IP.String(), port)
			}
		}

		mapAction := uint8(0) // 0 means not found
		for k, v := range existingRules {
			if k == targetKey {
				if v == "allow" {
					mapAction = 1
				} else {
					mapAction = 2
				}
				break
			}
		}

		// Check if already in config
		cfgAction := uint8(0)
		cfgIdx := -1
		for i, r := range globalCfg.Port.IPPortRules {
			if r.IP == cidrStr && r.Port == port {
				cfgAction = r.Action
				cfgIdx = i
				break
			}
		}

		if mapAction == action && cfgAction == action {
			actionStr := "allow"
			if action == 2 {
				actionStr = "deny"
			}
			fmt.Printf("ℹ️  Rule already exists: %s:%d -> %s\n", cidrStr, port, actionStr)
			return
		}

		// Update BPF Map if needed
		if mapAction != action {
			if err := m.AddIPPortRule(ipNet, port, action, nil); err != nil {
				log.Fatalf("❌ Failed to add IP+Port rule: %v", err)
			}
		}

		// Update config if needed
		if cfgAction != action {
			if cfgIdx >= 0 {
				globalCfg.Port.IPPortRules[cfgIdx].Action = action
			} else {
				globalCfg.Port.IPPortRules = append(globalCfg.Port.IPPortRules, types.IPPortRule{
					IP:     cidrStr,
					Port:   port,
					Action: action,
				})
			}
			if err := SaveGlobalConfig(configPath, globalCfg); err != nil {
				log.Fatalf("❌ Failed to save config: %v", err)
			}
			log.Printf("📄 Updated IP+Port rule in config: %s:%d", cidrStr, port)
		}

		if mapAction != action || cfgAction != action {
			actionStr := "allow"
			if action == 2 {
				actionStr = "deny"
			}
			log.Printf("🛡️ Rule added: %s:%d -> %s (Updated BPF: %v, Updated Config: %v)",
				cidrStr, port, actionStr, mapAction != action, cfgAction != action)
		}
	} else {
		if err := m.RemoveIPPortRule(ipNet, port); err != nil {
			log.Fatalf("❌ Failed to remove IP+Port rule: %v", err)
		}

		// Update config
		newRules := []types.IPPortRule{}
		for _, r := range globalCfg.Port.IPPortRules {
			if r.IP != cidrStr || r.Port != port {
				newRules = append(newRules, r)
			}
		}
		globalCfg.Port.IPPortRules = newRules
		if err := SaveGlobalConfig(configPath, globalCfg); err != nil {
			log.Fatalf("❌ Failed to save config: %v", err)
		}
		log.Printf("🛡️ Rule removed: %s:%d", cidrStr, port)
	}
}

func importIPPortRulesFromFile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open rules file: %v", err)
	}
	defer file.Close()

	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	// Pre-load existing rules for comparison
	existingRules4, _ := m.ListIPPortRules(false)
	existingRules6, _ := m.ListIPPortRules(true)

	scanner := bufio.NewScanner(file)
	count := 0
	updatedCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			log.Printf("⚠️  Skipping invalid line: %s", line)
			continue
		}

		cidrStr := parts[0]
		pVal, _ := strconv.ParseUint(parts[1], 10, 16)
		port := uint16(pVal)
		aVal, _ := strconv.ParseUint(parts[2], 10, 8)
		action := uint8(aVal)

		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			ip := net.ParseIP(cidrStr)
			if ip == nil {
				log.Printf("⚠️  Invalid IP: %s", cidrStr)
				continue
			}
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}

		// Check if rule already exists in BPF with same action
		isIPv6 := ipNet.IP.To4() == nil
		targetKey := ""
		if !strings.Contains(cidrStr, "/") {
			if isIPv6 {
				targetKey = fmt.Sprintf("%s/128:%d", ipNet.IP.String(), port)
			} else {
				targetKey = fmt.Sprintf("%s/32:%d", ipNet.IP.String(), port)
			}
		} else {
			targetKey = fmt.Sprintf("%s:%d", cidrStr, port)
		}

		mapAction := uint8(0)
		existingMap := existingRules4
		if isIPv6 {
			existingMap = existingRules6
		}
		if v, ok := existingMap[targetKey]; ok {
			if v == "allow" {
				mapAction = 1
			} else {
				mapAction = 2
			}
		}

		if mapAction != action {
			if err := m.AddIPPortRule(ipNet, port, action, nil); err != nil {
				log.Printf("⚠️  Failed to add rule %s:%d: %v", cidrStr, port, err)
				continue
			}
			updatedCount++
		}

		// Update global config data structure
		found := false
		for i, r := range globalCfg.Port.IPPortRules {
			if r.IP == cidrStr && r.Port == port {
				if globalCfg.Port.IPPortRules[i].Action != action {
					globalCfg.Port.IPPortRules[i].Action = action
					updatedCount++
				}
				found = true
				break
			}
		}
		if !found {
			globalCfg.Port.IPPortRules = append(globalCfg.Port.IPPortRules, types.IPPortRule{
				IP:     cidrStr,
				Port:   port,
				Action: action,
			})
			updatedCount++
		}
		count++
	}

	if updatedCount > 0 {
		SaveGlobalConfig(configPath, globalCfg)
	}
	log.Printf("🚀 Successfully processed %d IP+Port rules (New/Updated: %d).", count, updatedCount)
}

/**
 * importLockListFromFile reads IPs/CIDRs from a file and loads them into pinned BPF maps.
 */
func importLockListFromFile(filePath string) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 lock list (is the daemon running?): %v", err)
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 lock list (is the daemon running?): %v", err)
	}
	defer m6.Close()

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open lock list file %s: %v", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var targetMap *ebpf.Map
		if !isIPv6(line) {
			targetMap = m4
		} else {
			targetMap = m6
		}

		if err := xdp.LockIP(targetMap, line); err != nil {
			log.Printf("❌ Failed to import %s to lock list: %v", line, err)
		} else {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("❌ Error reading lock list file %s: %v", filePath, err)
	}

	log.Printf("🛡️ Imported %d IPs/ranges from %s to lock list", count, filePath)
}

/**
 * importWhitelistFromFile reads IPs/CIDRs from a file and loads them into pinned BPF maps.
 */
func importWhitelistFromFile(filePath string) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 whitelist (is the daemon running?): %v", err)
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 whitelist (is the daemon running?): %v", err)
	}
	defer m6.Close()

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open whitelist file %s: %v", filePath, err)
	}
	defer file.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	scanner := bufio.NewScanner(file)
	count := 0
	updatedConfig := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var targetMap *ebpf.Map
		if !isIPv6(line) {
			targetMap = m4
		} else {
			targetMap = m6
		}

		if err := xdp.AllowIP(targetMap, line); err != nil {
			log.Printf("❌ Failed to import %s to whitelist: %v", line, err)
		} else {
			count++
			// Check if already in config
			found := false
			for _, ip := range globalCfg.Base.Whitelist {
				if ip == line {
					found = true
					break
				}
			}
			if !found {
				globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, line)
				updatedConfig = true
			}
		}
	}

	if updatedConfig {
		if err := SaveGlobalConfig(configPath, globalCfg); err != nil {
			log.Printf("⚠️  Failed to save whitelist to config: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("❌ Error reading whitelist file %s: %v", filePath, err)
	}

	log.Printf("⚪ Imported %d IPs/ranges from %s to whitelist (Updated config: %v)", count, filePath, updatedConfig)
}
