package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/livp123/netxfw/internal/xdp"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	command := os.Args[1]
	switch command {
	case "load":
		if len(os.Args) < 3 || os.Args[2] != "xdp" {
			usage()
			return
		}
		runServer()
	case "lock":
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing IP address")
		}
		updateBlacklist(os.Args[2], true)
	case "unlock":
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing IP address")
		}
		updateBlacklist(os.Args[2], false)
	case "list":
		listBlacklist()
	case "unload":
		if len(os.Args) < 3 || os.Args[2] != "xdp" {
			usage()
			return
		}
		unloadXDP()
	default:
		usage()
	}
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  ./netxfw load xdp        # 加载 XDP 程序到网卡")
	fmt.Println("  ./netxfw lock 1.2.3.4    # 封禁 IP")
	fmt.Println("  ./netxfw unlock 1.2.3.4  # 解封 IP")
	fmt.Println("  ./netxfw list            # 查看封禁 IP 列表")
	fmt.Println("  ./netxfw unload xdp      # 卸载 XDP 程序")
}

func runServer() {
	// 加载配置
	cfg, err := LoadConfig("rules/default.yaml")
	if err != nil {
		log.Printf("⚠️ Failed to load config: %v, using defaults", err)
	} else {
		log.Printf("📖 Loaded %d rules from config", len(cfg.Rules))
	}

	// 获取物理网卡
	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		log.Fatalf("❌ Failed to get interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		log.Fatal("❌ No physical interfaces found")
	}

	// 初始化 XDP
	manager, err := xdp.NewManager()
	if err != nil {
		log.Fatalf("❌ Failed to create XDP manager: %v", err)
	}
	defer manager.Close()

	// Pin maps for external control
	if err := manager.Pin("/sys/fs/bpf/netxfw"); err != nil {
		log.Fatalf("❌ Failed to pin maps: %v", err)
	}
	defer manager.Unpin("/sys/fs/bpf/netxfw")

	// Attach 到所有网卡
	if err := manager.Attach(interfaces); err != nil {
		log.Fatalf("❌ Failed to attach XDP: %v", err)
	}

	// 启动指标服务
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("📊 Metrics server listening on :9100")

		// 定期更新指标
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			for range ticker.C {
				count, err := manager.GetDropCount()
				if err == nil {
					UpdateMetrics(count)
				}
			}
		}()

		log.Fatal(http.ListenAndServe(":9100", nil))
	}()

	// 等待退出信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("👋 Shutting down...")
}

func updateBlacklist(ipStr string, lock bool) {
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		log.Fatalf("❌ Invalid IP address: %s", ipStr)
	}

	mapPath := "/sys/fs/bpf/netxfw/blacklist"
	if parsedIP.To4() == nil {
		mapPath = "/sys/fs/bpf/netxfw/blacklist6"
	}

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the server running?): %v", err)
	}
	defer m.Close()

	if lock {
		if err := xdp.BanIP(m, ipStr); err != nil {
			log.Fatalf("❌ Failed to lock IP %s: %v", ipStr, err)
		}
		log.Printf("🛡️ Locked IP: %s", ipStr)
	} else {
		if err := xdp.UnbanIP(m, ipStr); err != nil {
			log.Fatalf("❌ Failed to unlock IP %s: %v", ipStr, err)
		}
		log.Printf("🔓 Unlocked IP: %s", ipStr)
	}
}

func listBlacklist() {
	// List IPv4
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/blacklist", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 blacklist: %v", err)
	}
	defer m4.Close()

	ips4, err := xdp.ListBlockedIPs(m4, false)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv4 blocked IPs: %v", err)
	}

	// List IPv6
	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/blacklist6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 blacklist: %v", err)
	}
	defer m6.Close()

	ips6, err := xdp.ListBlockedIPs(m6, true)
	if err != nil {
		log.Fatalf("❌ Failed to list IPv6 blocked IPs: %v", err)
	}

	if len(ips4) == 0 && len(ips6) == 0 {
		fmt.Println("Empty blacklist.")
		return
	}

	fmt.Println("🛡️ Currently blocked IPs and drop counts:")
	for ip, count := range ips4 {
		fmt.Printf(" - [IPv4] %s: %d drops\n", ip, count)
	}
	for ip, count := range ips6 {
		fmt.Printf(" - [IPv6] %s: %d drops\n", ip, count)
	}
}

func unloadXDP() {
	log.Println("👋 Unloading XDP and cleaning up...")
	// The server handles cleanup on SIGINT/SIGTERM via defer manager.Close()
	// and defer manager.Unpin(). This command is mainly to trigger cleanup if running.
	// In a real scenario, we might want to send a signal to the running process.
	fmt.Println("Please stop the running 'load xdp' process (e.g., Ctrl+C) to unload.")
}
