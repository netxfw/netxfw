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
	case "load":
		// Load XDP program / 加载 XDP 程序
		if len(os.Args) < 3 || os.Args[2] != "xdp" {
			usage()
			return
		}
		runServer()
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
		// Import lock list from file / 从文件导入锁定列表
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing file path")
		}
		importLockListFromFile(os.Args[2])
	case "unload":
		// Unload XDP program / 卸载 XDP 程序
		if len(os.Args) < 3 || os.Args[2] != "xdp" {
			usage()
			return
		}
		unloadXDP()
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
	fmt.Println("  ./netxfw load xdp        # 加载 XDP 程序到网卡")
	fmt.Println("  ./netxfw lock 1.2.3.4    # 封禁 IP 或网段 (如 192.168.1.0/24)")
	fmt.Println("  ./netxfw unlock 1.2.3.4  # 解封 IP 或网段")
	fmt.Println("  ./netxfw allow 1.2.3.4   # 将 IP 或网段加入白名单")
	fmt.Println("  ./netxfw unallow 1.2.3.4 # 将 IP 或网段从白名单移除")
	fmt.Println("  ./netxfw list            # 查看封禁 IP 列表及拦截统计")
	fmt.Println("  ./netxfw allow-list      # 查看白名单 IP 列表")
	fmt.Println("  ./netxfw import file.txt # 从文件导入锁定列表 IP 列表")
	fmt.Println("  ./netxfw unload xdp      # 卸载 XDP 程序")
}

/**
 * runServer initializes the XDP manager and starts the metrics server.
 * runServer 初始化 XDP 管理器并启动指标服务。
 */
func runServer() {
	// Try loading config, priority: /etc/netxfw/config.yaml > rules/default.yaml
	// 尝试加载配置，优先级：/etc/netxfw/config.yaml > rules/default.yaml
	configPath := "/etc/netxfw/config.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = "rules/default.yaml"
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Printf("⚠️ Failed to load config from %s: %v, using defaults", configPath, err)
	} else {
		log.Printf("📖 Loaded %d rules and %d whitelisted IPs from %s", len(cfg.Rules), len(cfg.Whitelist), configPath)
	}

	// Metrics port / 指标服务端口
	metricsAddr := ":9100"
	if cfg != nil && cfg.MetricsPort > 0 {
		metricsAddr = fmt.Sprintf(":%d", cfg.MetricsPort)
	}

	// Get all physical interfaces / 获取所有物理网卡
	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		log.Fatalf("❌ Failed to get interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		log.Fatal("❌ No physical interfaces found")
	}

	// Initialize XDP Manager / 初始化 XDP 管理器
	manager, err := xdp.NewManager()
	if err != nil {
		log.Fatalf("❌ Failed to create XDP manager: %v", err)
	}
	defer manager.Close()

	// Pin maps for external control (CLI) / 固定 Map 到文件系统以供 CLI 访问
	if err := manager.Pin("/sys/fs/bpf/netxfw"); err != nil {
		log.Fatalf("❌ Failed to pin maps: %v", err)
	}
	defer manager.Unpin("/sys/fs/bpf/netxfw")

	// Attach XDP to all interfaces / 将 XDP 程序挂载到所有网卡
	if err := manager.Attach(interfaces); err != nil {
		log.Fatalf("❌ Failed to attach XDP: %v", err)
	}

	// Load whitelisted ranges from config / 从配置中加载白名单网段
	if cfg != nil && len(cfg.Whitelist) > 0 {
		for _, ipStr := range cfg.Whitelist {
			var targetMap *ebpf.Map
			if !isIPv6(ipStr) {
				targetMap = manager.Whitelist()
			} else {
				targetMap = manager.Whitelist6()
			}

			if err := xdp.AllowIP(targetMap, ipStr); err != nil {
				log.Printf("❌ Failed to add %s to whitelist: %v", ipStr, err)
			} else {
				log.Printf("⚪ Whitelisted: %s", ipStr)
			}
		}
	}

	// Load locked ranges from config or file / 从配置或文件中加载封禁网段
	if cfg != nil {
		lockListPath := cfg.LockListFile
		// If not specified in config, check default path / 如果配置中未指定，则检查默认路径
		if lockListPath == "" {
			defaultPath := "/etc/netxfw/lock.conf"
			if _, err := os.Stat(defaultPath); err == nil {
				lockListPath = defaultPath
			}
		}

		if lockListPath != "" {
			loadLockListFromFile(manager, lockListPath)
		}

		// 2. Load from rules (future expansion) / 从规则中加载（后续扩展）
		/*
			if len(cfg.Rules) > 0 {
				// ...
			}
		*/
	}

	// Start Prometheus metrics server / 启动 Prometheus 指标服务
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Printf("📊 Metrics server listening on %s", metricsAddr)

		// Periodic metrics update / 定期更新统计指标
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			for range ticker.C {
				count, err := manager.GetDropCount()
				if err == nil {
					UpdateMetrics(count)
				}
			}
		}()

		log.Fatal(http.ListenAndServe(metricsAddr, nil))
	}()

	// Wait for exit signal (Ctrl+C, etc) / 等待退出信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("👋 Shutting down...")
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
		log.Fatalf("❌ Failed to load pinned map (is the server running?): %v", err)
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

	// Load map from filesystem / 从文件系统加载 Map
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the server running?): %v", err)
	}
	defer m.Close()

	if allow {
		if err := xdp.AllowIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to allow %s: %v", cidrStr, err)
		}
		log.Printf("⚪ Whitelisted: %s", cidrStr)
	} else {
		if err := xdp.UnlockIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to unallow %s: %v", cidrStr, err)
		}
		log.Printf("❌ Removed from whitelist: %s", cidrStr)
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
 * loadLockListFromFile reads IPs/CIDRs from a file and loads them into the BPF map.
 * loadLockListFromFile 从文件中读取 IP/CIDR 并加载到 BPF Map 中。
 */
func loadLockListFromFile(manager *xdp.Manager, filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("⚠️ Failed to open lock list file %s: %v", filePath, err)
		return
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
			targetMap = manager.LockList()
		} else {
			targetMap = manager.LockList6()
		}

		if err := xdp.LockIP(targetMap, line); err != nil {
			log.Printf("❌ Failed to pre-load %s from file: %v", line, err)
		} else {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("❌ Error reading lock list file %s: %v", filePath, err)
	}

	log.Printf("🛡️ Pre-loaded %d IPs/ranges from %s", count, filePath)
}

/**
 * importLockListFromFile reads IPs/CIDRs from a file and loads them into pinned BPF maps.
 * importLockListFromFile 从文件中读取 IP/CIDR 并加载到固定的 BPF Map 中。
 */
func importLockListFromFile(filePath string) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 lock list (is the server running?): %v", err)
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 lock list (is the server running?): %v", err)
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
			log.Printf("❌ Failed to import %s: %v", line, err)
		} else {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("❌ Error reading lock list file %s: %v", filePath, err)
	}

	log.Printf("🛡️ Imported %d IPs/ranges from %s", count, filePath)
}
