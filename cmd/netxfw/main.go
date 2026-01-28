package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/plugins"
	"github.com/livp123/netxfw/pkg/storage"
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

func getStore() storage.Store {
	configPath := "/etc/netxfw/config.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = "rules/default.yaml"
	}

	// For simplicity, always use the default lock file path
	lockPath := "/etc/netxfw/lock.yaml"

	return storage.NewYAMLStore(configPath, lockPath)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	command := os.Args[1]

	// Parse flags and positional arguments / 解析 Flag 和位置参数
	var posArgs []string
	flags := make(map[string]string)

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "--") {
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "--") {
				flags[arg] = os.Args[i+1]
				i++ // skip next
			} else {
				flags[arg] = "true"
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}

	// Helper to get TTL / 获取 TTL 的辅助逻辑
	var expiresAt *time.Time
	if ttlStr, ok := flags["--ttl"]; ok {
		d, err := time.ParseDuration(ttlStr)
		if err == nil {
			t := time.Now().Add(d)
			expiresAt = &t
		}
	}

	switch command {
	case "load":
		// Load XDP program / 加载 XDP 程序
		if len(posArgs) < 1 || posArgs[0] != "xdp" {
			usage()
			return
		}
		installXDP()
	case "daemon":
		// Start daemon for metrics and sync / 启动常驻进程
		runDaemon()
	case "lock":
		// Block an IP or CIDR / 封禁 IP 或网段
		if len(posArgs) < 1 {
			log.Fatal("❌ Missing IP address")
		}
		syncLockMap(posArgs[0], true, expiresAt)
	case "unlock":
		// Unblock an IP or CIDR / 解封 IP 或网段
		if len(posArgs) < 1 {
			log.Fatal("❌ Missing IP address")
		}
		syncLockMap(posArgs[0], false, nil)
	case "allow":
		// Whitelist an IP or CIDR / 将 IP 或网段加入白名单
		if len(posArgs) < 1 {
			log.Fatal("❌ Missing IP address")
		}

		targetIP := posArgs[0]
		portStr := flags["--port"]

		// Handle legacy syntax: allow ip <ip> port <port>
		if targetIP == "ip" || targetIP == "cidr" {
			if len(posArgs) >= 4 && posArgs[2] == "port" {
				targetIP = posArgs[1]
				portStr = posArgs[3]
			}
		}

		if portStr != "" {
			handleIPPortCommand(targetIP, portStr, true, expiresAt)
		} else {
			syncWhitelistMap(targetIP, true, expiresAt)
		}
	case "unallow":
		// Remove an IP or CIDR from whitelist / 将 IP 或网段从白名单移除
		if len(posArgs) < 1 {
			log.Fatal("❌ Missing IP address")
		}

		targetIP := posArgs[0]
		portStr := flags["--port"]

		// Handle legacy syntax: unallow ip <ip> port <port>
		if targetIP == "ip" || targetIP == "cidr" {
			if len(posArgs) >= 4 && posArgs[2] == "port" {
				targetIP = posArgs[1]
				portStr = posArgs[3]
			}
		}

		if portStr != "" {
			handleIPPortCommand(targetIP, portStr, false, nil)
		} else {
			syncWhitelistMap(targetIP, false, nil)
		}
	case "list":
		// List blocked and/or whitelisted ranges
		if len(os.Args) < 3 {
			// netxfw list -> Show both
			showWhitelist()
			fmt.Println()
			showLockList()
		} else {
			subCommand := os.Args[2]
			switch subCommand {
			case "lock":
				// netxfw list lock
				showLockList()
			case "allow":
				// netxfw list allow
				showWhitelist()
			default:
				usage()
			}
		}
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
		default:
			usage()
		}
	case "plugin":
		// Plugin management / 插件管理
		handlePluginCommand()
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
	fmt.Println("  ./netxfw load xdp              # 安装 XDP 程序到内核")
	fmt.Println("  ./netxfw daemon                # 启动后台进程 (监控与同步)")
	fmt.Println("  ./netxfw lock 1.2.3.4          # 封禁 IP/网段")
	fmt.Println("  ./netxfw lock 1.2.3.4 --ttl 1h # 临时封禁 IP")
	fmt.Println("  ./netxfw unlock 1.2.3.4        # 解封 IP/网段")
	fmt.Println("  ./netxfw allow 1.2.3.4         # 加入白名单")
	fmt.Println("  ./netxfw allow 1.2.3.4 --ttl 1h # 临时白名单")
	fmt.Println("  ./netxfw allow 10.0.0.5 --port 80/tcp          # 允许访问特定端口")
	fmt.Println("  ./netxfw allow 10.0.0.5 --port 80/tcp --ttl 1h # 临时允许访问")
	fmt.Println("  ./netxfw unallow 1.2.3.4       # 从白名单移除")
	fmt.Println("  ./netxfw list                  # 查看当前规则")
	fmt.Println("  ./netxfw list lock             # 仅查看封禁列表")
	fmt.Println("  ./netxfw list allow            # 仅查看白名单")
	fmt.Println("  ./netxfw import lock file.txt  # 批量导入封禁列表")
	fmt.Println("  ./netxfw import allow file.txt # 批量导入白名单")
	fmt.Println("  ./netxfw plugin list           # 列出可用插件")
	fmt.Println("  ./netxfw plugin start <name>   # 启动插件")
	fmt.Println("  ./netxfw plugin stop <name>    # 停止插件")
	fmt.Println("  ./netxfw unload xdp            # 卸载 XDP 程序")
}

/**
 * handlePluginCommand handles CLI plugin management.
 */
func handlePluginCommand() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./netxfw plugin [list|start|stop] [name]")
		return
	}

	sub := os.Args[2]
	switch sub {
	case "list":
		fmt.Println("🧩 Available Plugins:")
		for name, p := range plugins.Registry {
			fmt.Printf(" - %s: %s\n", name, p.Description())
		}
	case "start":
		if len(os.Args) < 4 {
			log.Fatal("❌ Missing plugin name")
		}
		name := os.Args[3]
		p, ok := plugins.Registry[name]
		if !ok {
			log.Fatalf("❌ Plugin %s not found", name)
		}

		// For CLI execution, we need a manager that uses pinned maps
		manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
		if err != nil {
			log.Fatalf("❌ Failed to create manager from pins: %v", err)
		}

		// Note: CLI plugin start uses default config for now
		if err := p.Init(manager, nil); err != nil {
			log.Fatalf("❌ Failed to init plugin: %v", err)
		}
		if err := p.Start(); err != nil {
			log.Fatalf("❌ Failed to start plugin: %v", err)
		}
	case "stop":
		if len(os.Args) < 4 {
			log.Fatal("❌ Missing plugin name")
		}
		name := os.Args[3]
		p, ok := plugins.Registry[name]
		if !ok {
			log.Fatalf("❌ Plugin %s not found", name)
		}

		manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
		if err != nil {
			log.Fatalf("❌ Failed to create manager from pins: %v", err)
		}
		if err := p.Init(manager, nil); err != nil {
			log.Fatalf("❌ Failed to init plugin: %v", err)
		}
		if err := p.Stop(); err != nil {
			log.Fatalf("❌ Failed to stop plugin: %v", err)
		}
	default:
		usage()
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

	log.Println("🚀 XDP program installed successfully and pinned to /sys/fs/bpf/netxfw")
	log.Println("✨ You can now start the daemon with './netxfw daemon' or use CLI to manage rules.")
}

/**
 * runDaemon starts the background process for metrics and rule synchronization.
 */
func runDaemon() {
	configPath := "/etc/netxfw/config.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = "rules/default.yaml"
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Printf("⚠️ Failed to load config from %s: %v, using defaults", configPath, err)
	}

	metricsAddr := ":9100"
	if cfg != nil && cfg.MetricsPort > 0 {
		metricsAddr = fmt.Sprintf(":%d", cfg.MetricsPort)
	}

	manager, err := xdp.NewManager()
	if err != nil {
		log.Fatalf("❌ Failed to create XDP manager: %v", err)
	}
	defer manager.Close()

	if err := manager.Pin("/sys/fs/bpf/netxfw"); err != nil {
		log.Printf("⚠️  Map pinning warning: %v", err)
	}

	if cfg != nil {
		// Use Store to load and sync rules / 使用 Store 加载并同步规则
		store := getStore()
		whitelist, lockList, ipPortRules, err := store.LoadAll()
		if err == nil {
			// Sync Whitelist / 同步白名单
			for _, rule := range whitelist {
				ipStr := rule.CIDR
				var targetMap *ebpf.Map
				if !isIPv6(ipStr) {
					targetMap = manager.Whitelist()
				} else {
					targetMap = manager.Whitelist6()
				}
				if err := xdp.AllowIP(targetMap, ipStr, rule.ExpiresAt); err == nil {
					log.Printf("⚪ Whitelisted (from store): %s", ipStr)
				}
			}

			// Sync Lock List / 同步锁定列表
			for _, rule := range lockList {
				ipStr := rule.CIDR
				var targetMap *ebpf.Map
				if !isIPv6(ipStr) {
					targetMap = manager.LockList()
				} else {
					targetMap = manager.LockList6()
				}
				if err := xdp.LockIP(targetMap, ipStr, rule.ExpiresAt); err == nil {
					log.Printf("🛡️ Locked (from store): %s", ipStr)
				}
			}

			// Sync IP+Port Rules / 同步 IP+端口 规则
			for _, rule := range ipPortRules {
				_, ipNet, err := net.ParseCIDR(storage.NormalizeCIDR(rule.CIDR))
				if err == nil {
					if err := manager.AddIPPortRule(ipNet, rule.Port, 1, rule.ExpiresAt); err == nil {
						log.Printf("✅ IP+Port allowed (from store): %s -> %d", rule.CIDR, rule.Port)
					}
				}
			}
		} else {
			log.Printf("⚠️ Failed to load rules from store: %v", err)
		}

		// Handle auto-start plugins from config / 处理配置文件中的自动启动插件
		for _, pluginName := range cfg.Plugins {
			if p, ok := plugins.Registry[pluginName]; ok {
				// 1. Try to load from separate plugin config file / 尝试从独立的插件配置文件加载
				pluginConfig, err := LoadPluginConfig(pluginName)
				if err != nil {
					log.Printf("⚠️  Failed to load separate config for plugin %s: %v", pluginName, err)
				}

				// 2. If no separate config, fallback to main config / 如果没有独立配置，回退到主配置
				if pluginConfig == nil {
					pluginConfig = cfg.PluginConfig[pluginName]
				}

				if err := p.Init(manager, pluginConfig); err == nil {
					if err := p.Start(); err != nil {
						log.Printf("❌ Failed to start plugin %s: %v", pluginName, err)
					}
				} else {
					log.Printf("❌ Failed to init plugin %s: %v", pluginName, err)
				}
			} else {
				log.Printf("⚠️  Plugin %s not found in registry", pluginName)
			}
		}
	}

	// Cleanup loop for expired rules / 过期规则清理循环
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		store := getStore()
		for range ticker.C {
			whitelist, lockList, ipPortRules, err := store.LoadAll()
			if err != nil {
				continue
			}

			now := time.Now()

			// Check Whitelist / 检查白名单
			for _, rule := range whitelist {
				if rule.ExpiresAt != nil && rule.ExpiresAt.Before(now) {
					log.Printf("🕒 Whitelist rule expired: %s", rule.CIDR)
					var targetMap *ebpf.Map
					if !isIPv6(rule.CIDR) {
						targetMap = manager.Whitelist()
					} else {
						targetMap = manager.Whitelist6()
					}
					xdp.UnlockIP(targetMap, rule.CIDR)
					store.RemoveIP(storage.RuleTypeWhitelist, rule.CIDR)
				}
			}

			// Check Lock List / 检查锁定列表
			for _, rule := range lockList {
				if rule.ExpiresAt != nil && rule.ExpiresAt.Before(now) {
					log.Printf("🕒 Lock rule expired: %s", rule.CIDR)
					var targetMap *ebpf.Map
					if !isIPv6(rule.CIDR) {
						targetMap = manager.LockList()
					} else {
						targetMap = manager.LockList6()
					}
					xdp.UnlockIP(targetMap, rule.CIDR)
					store.RemoveIP(storage.RuleTypeLockList, rule.CIDR)
				}
			}

			// Check IP+Port Rules / 检查 IP+端口 规则
			for _, rule := range ipPortRules {
				if rule.ExpiresAt != nil && rule.ExpiresAt.Before(now) {
					log.Printf("🕒 IP+Port rule expired: %s -> %d", rule.CIDR, rule.Port)
					_, ipNet, err := net.ParseCIDR(storage.NormalizeCIDR(rule.CIDR))
					if err == nil {
						manager.RemoveIPPortRule(ipNet, rule.Port)
						store.RemoveIPPortRule(rule.CIDR, rule.Port, rule.Protocol)
					}
				}
			}
		}
	}()

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Printf("📊 Metrics server listening on %s", metricsAddr)

		ticker := time.NewTicker(2 * time.Second)
		for range ticker.C {
			count, err := manager.GetDropCount()
			if err == nil {
				UpdateMetrics(count)
			}
		}
		log.Fatal(http.ListenAndServe(metricsAddr, nil))
	}()

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
func syncLockMap(cidrStr string, lock bool, expiresAt *time.Time) {
	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to load pinned maps: %v", err)
	}
	defer manager.Close()

	store := getStore()

	var targetMap *ebpf.Map
	if !isIPv6(cidrStr) {
		targetMap = manager.LockList()
	} else {
		targetMap = manager.LockList6()
	}

	if lock {
		if err := xdp.LockIP(targetMap, cidrStr, expiresAt); err != nil {
			log.Fatalf("❌ Failed to lock %s: %v", cidrStr, err)
		}
		store.AddIP(storage.RuleTypeLockList, cidrStr, expiresAt)
		log.Printf("🛡️ Locked: %s", cidrStr)
	} else {
		if err := xdp.UnlockIP(targetMap, cidrStr); err != nil {
			log.Fatalf("❌ Failed to unlock %s: %v", cidrStr, err)
		}
		store.RemoveIP(storage.RuleTypeLockList, cidrStr)
		log.Printf("🔓 Unlocked: %s", cidrStr)
	}
}

/**
 * syncWhitelistMap interacts with pinned BPF maps to allow/unallow ranges.
 * syncWhitelistMap 通过操作固定的 BPF Map 来允许或移除白名单网段。
 */
func syncWhitelistMap(cidrStr string, allow bool, expiresAt *time.Time) {
	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to load pinned maps: %v", err)
	}
	defer manager.Close()

	store := getStore()

	var targetMap *ebpf.Map
	if !isIPv6(cidrStr) {
		targetMap = manager.Whitelist()
	} else {
		targetMap = manager.Whitelist6()
	}

	if allow {
		if err := xdp.AllowIP(targetMap, cidrStr, expiresAt); err != nil {
			log.Fatalf("❌ Failed to whitelist %s: %v", cidrStr, err)
		}
		store.AddIP(storage.RuleTypeWhitelist, cidrStr, expiresAt)
		log.Printf("⚪ Whitelisted: %s", cidrStr)
	} else {
		if err := xdp.UnlockIP(targetMap, cidrStr); err != nil {
			log.Fatalf("❌ Failed to unwhitelist %s: %v", cidrStr, err)
		}
		store.RemoveIP(storage.RuleTypeWhitelist, cidrStr)
		log.Printf("➖ Removed from whitelist: %s", cidrStr)
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
 * importLockListFromFile reads IPs/CIDRs from a file and loads them into pinned BPF maps.
 */
func importLockListFromFile(filePath string) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 lock list: %v", err)
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 lock list: %v", err)
	}
	defer m6.Close()

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open lock list file %s: %v", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	store := getStore()
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

		if err := xdp.LockIP(targetMap, line, nil); err != nil {
			log.Printf("❌ Failed to import %s to lock list: %v", line, err)
		} else {
			store.AddIP(storage.RuleTypeLockList, line, nil)
			count++
		}
	}

	log.Printf("🛡️ Imported %d IPs/ranges from %s to lock list and store", count, filePath)
}

/**
 * importWhitelistFromFile reads IPs/CIDRs from a file and loads them into pinned BPF maps.
 */
func importWhitelistFromFile(filePath string) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 whitelist: %v", err)
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 whitelist: %v", err)
	}
	defer m6.Close()

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open whitelist file %s: %v", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	store := getStore()
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

		if err := xdp.AllowIP(targetMap, line, nil); err != nil {
			log.Printf("❌ Failed to import %s to whitelist: %v", line, err)
		} else {
			store.AddIP(storage.RuleTypeWhitelist, line, nil)
			count++
		}
	}

	log.Printf("⚪ Imported %d IPs/ranges from %s to whitelist and store", count, filePath)
}

/**
 * handleIPPortCommand handles the "allow ip ... port ..." style commands.
 */
func handleIPPortCommand(ipStr string, portProto string, allow bool, expiresAt *time.Time) {
	// Parse port/proto / 解析 端口/协议
	parts := strings.Split(portProto, "/")
	portStr := parts[0]
	var port uint16
	_, err := fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		log.Fatalf("❌ Invalid port: %s", portStr)
	}

	// Prepare CIDR / 准备 CIDR
	cidr := ipStr
	if !strings.Contains(cidr, "/") {
		if !isIPv6(cidr) {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("❌ Invalid IP/CIDR: %s", cidr)
	}

	// Load manager from pins / 从固定路径加载管理器
	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to load XDP manager: %v (is the daemon running?)", err)
	}

	if allow {
		if err := manager.AddIPPortRule(ipNet, port, 1, expiresAt); err != nil {
			log.Fatalf("❌ Failed to add rule: %v", err)
		}
		// Persist to store / 持久化到存储
		rule := storage.IPPortRule{
			CIDR:      cidr,
			Port:      port,
			Protocol:  "tcp", // Default to tcp for now
			Action:    "allow",
			ExpiresAt: expiresAt,
		}
		if err := getStore().AddIPPortRule(rule); err != nil {
			log.Printf("⚠️ Failed to persist IP+Port rule for %s: %v", cidr, err)
		}
		log.Printf("✅ Allowed %s on port %d", cidr, port)
	} else {
		if err := manager.RemoveIPPortRule(ipNet, port); err != nil {
			log.Fatalf("❌ Failed to remove rule: %v", err)
		}
		// Persist to store / 持久化到存储
		if err := getStore().RemoveIPPortRule(cidr, port, "tcp"); err != nil {
			log.Printf("⚠️ Failed to persist IP+Port rule removal for %s: %v", cidr, err)
		}
		log.Printf("❌ Removed allowance for %s on port %d", cidr, port)
	}
}
