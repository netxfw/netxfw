// Package main demonstrates cloud environment Proxy Protocol support.
// Package main 演示云环境 Proxy Protocol 支持。
package main

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/livp123/netxfw/internal/cloudconfig"
	"github.com/livp123/netxfw/internal/proxyproto"
	"github.com/livp123/netxfw/internal/realip"
)

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║     NetXFW 云环境 Proxy Protocol 支持演示                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// 1. 云服务商配置演示
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│ 1. 云服务商配置演示                                         │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	demoCloudConfig()

	fmt.Println()

	// 2. Proxy Protocol 解析演示
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│ 2. Proxy Protocol 解析演示                                  │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	demoProxyProtocol()

	fmt.Println()

	// 3. 真实 IP 黑名单演示
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│ 3. 真实 IP 黑名单演示                                       │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	demoRealIPBlacklist()

	fmt.Println()

	// 4. 完整流程演示
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│ 4. 完整流程演示                                             │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	demoFullFlow()

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    演示完成                                   ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

// demoCloudConfig 演示云服务商配置
func demoCloudConfig() {
	fmt.Println()
	fmt.Println("支持的云服务商:")
	fmt.Println("┌────────────┬─────────────────────┬─────────────────────┬──────────┐")
	fmt.Println("│ 服务商     │ 显示名称            │ 默认 IP 段          │ PP 支持  │")
	fmt.Println("├────────────┼─────────────────────┼─────────────────────┼──────────┤")

	info := cloudconfig.GetProviderInfo()
	providers := []cloudconfig.Provider{
		cloudconfig.ProviderAlibaba,
		cloudconfig.ProviderTencent,
		cloudconfig.ProviderAWS,
		cloudconfig.ProviderAzure,
		cloudconfig.ProviderGCP,
		cloudconfig.ProviderOther,
	}

	for _, p := range providers {
		inf := info[p]
		pp := "❌"
		if inf.SupportsPP {
			pp = "✅"
		}
		fmt.Printf("│ %-10s │ %-19s │ %-19s │ %-8s │\n",
			p, inf.DisplayName, fmt.Sprintf("%d ranges", len(inf.DefaultRanges)), pp)
	}
	fmt.Println("└────────────┴─────────────────────┴─────────────────────┴──────────┘")

	// 演示合并配置
	fmt.Println()
	fmt.Println("阿里云配置 + 自定义 IP 段:")
	cfg := cloudconfig.GetMergedConfig(cloudconfig.ProviderAlibaba, []string{"192.168.0.0/16", "10.100.0.0/16"}, true, "5m")
	fmt.Printf("  - 服务商: %s\n", cfg.Provider)
	fmt.Printf("  - 获取真实 IP 方法: %s\n", cfg.RealIPMethod)
	fmt.Printf("  - Proxy Protocol: %v\n", cfg.ProxyProtocolEnabled)
	fmt.Printf("  - 可信代理范围: %v\n", cfg.TrustedProxies)
}

// demoProxyProtocol 演示 Proxy Protocol 解析
func demoProxyProtocol() {
	fmt.Println()

	// 创建解析器
	parser := proxyproto.NewParser(true)
	fmt.Printf("Proxy Protocol 解析器状态: enabled=%v\n", parser.IsEnabled())

	// 模拟 Proxy Protocol V2 IPv4 数据
	// 签名 + 版本/命令 + 地址族 + 地址长度 + 源IP + 目的IP + 源端口 + 目的端口
	fmt.Println()
	fmt.Println("解析 Proxy Protocol V2 数据包:")
	fmt.Println("  原始数据: [签名 + 头部 + 地址信息]")
	fmt.Println("  ┌─────────────────────────────────────────────────────┐")
	fmt.Println("  │ 签名: \\x0D\\x0A\\x0D\\x0A\\x00\\x0D\\x0A\\x51\\x55\\x49\\x54\\x0A │")
	fmt.Println("  │ 版本: V2, 命令: PROXY                                │")
	fmt.Println("  │ 地址族: AF_INET (IPv4)                               │")
	fmt.Println("  │ 源 IP: 192.168.1.100                                 │")
	fmt.Println("  │ 目的 IP: 10.0.1.50                                   │")
	fmt.Println("  │ 源端口: 12345                                        │")
	fmt.Println("  │ 目的端口: 80                                         │")
	fmt.Println("  └─────────────────────────────────────────────────────┘")

	// 创建测试数据
	testData := createProxyProtocolV2IPv4()
	header, consumed, err := parser.Parse(testData)
	if err != nil {
		fmt.Printf("  解析错误: %v\n", err)
		return
	}

	if header != nil {
		fmt.Println()
		fmt.Println("解析结果:")
		fmt.Printf("  ✓ 源 IP: %s\n", header.SourceIP)
		fmt.Printf("  ✓ 目的 IP: %s\n", header.DestinationIP)
		fmt.Printf("  ✓ 源端口: %d\n", header.SourcePort)
		fmt.Printf("  ✓ 目的端口: %d\n", header.DestinationPort)
		fmt.Printf("  ✓ 消耗字节数: %d\n", consumed)
	}
}

// demoRealIPBlacklist 演示真实 IP 黑名单
func demoRealIPBlacklist() {
	fmt.Println()

	// 创建 Manager
	mgr := realip.NewManager(&realip.Config{
		ProxyProtocolEnabled: true,
		TrustedLBs:           []string{"10.0.0.0/8", "100.64.0.0/10"},
		SyncToXDPCallback: func(ip string, ttl time.Duration) error {
			fmt.Printf("  [SDK] 同步到 dynamic_blacklist: IP=%s, TTL=%v\n", ip, ttl)
			return nil
		},
	})

	fmt.Println("添加真实 IP 到黑名单:")
	fmt.Println()

	// 从 CLI/API 加载
	fmt.Println("1. 通过 CLI/API 添加:")
	fmt.Println("   $ netxfw cloud block 192.168.1.100 --reason \"SSH 暴力破解\" --duration \"24h\"")
	mgr.AddToBlacklistWithSource("192.168.1.100", "SSH 暴力破解", 24*time.Hour, "api")
	fmt.Println("   $ netxfw cloud block 192.168.1.200 --reason \"端口扫描\" --duration \"1h\"")
	mgr.AddToBlacklistWithSource("192.168.1.200", "端口扫描", 1*time.Hour, "api")

	fmt.Println()
	fmt.Println("2. 通过 API 批量添加:")
	mgr.AddToBlacklistWithSource("10.0.0.50", "恶意请求", 30*time.Minute, "api")

	fmt.Println()
	fmt.Println("3. 自动检测添加:")
	mgr.AddToBlacklistWithSource("172.16.0.100", "自动检测: DDoS 攻击", 2*time.Hour, "auto")

	// 列出黑名单
	fmt.Println()
	fmt.Println("当前黑名单:")
	fmt.Println("┌─────────────────┬──────────────────┬──────────┬─────────────────────┐")
	fmt.Println("│ IP 地址         │ 原因             │ 来源     │ 过期时间            │")
	fmt.Println("├─────────────────┼──────────────────┼──────────┼─────────────────────┤")
	for _, entry := range mgr.ListBlacklist() {
		expiry := "永久"
		if !entry.ExpiresAt.IsZero() {
			expiry = entry.ExpiresAt.Format("2006-01-02 15:04:05")
		}
		fmt.Printf("│ %-15s │ %-16s │ %-8s │ %-19s │\n",
			entry.IP.String(), truncate(entry.Reason, 16), entry.Source, expiry)
	}
	fmt.Println("└─────────────────┴──────────────────┴──────────┴─────────────────────┘")

	// 统计信息
	fmt.Println()
	stats := mgr.GetStats()
	fmt.Printf("统计: 黑名单 %d 条, 可信 LB 范围 %d 个\n",
		stats["blacklist_count"], stats["trusted_lb_ranges"])
}

// demoFullFlow 演示完整流程
func demoFullFlow() {
	fmt.Println()

	// 创建 Manager
	mgr := realip.NewManager(&realip.Config{
		ProxyProtocolEnabled: true,
		TrustedLBs:           []string{"10.0.0.0/8"},
		SyncToXDPCallback: func(ip string, ttl time.Duration) error {
			return nil
		},
	})

	// 添加黑名单
	mgr.AddToBlacklistWithSource("192.168.1.100", "恶意攻击", 24*time.Hour, "config")

	fmt.Println("场景: 恶意客户端通过云 LB 访问")
	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│                     连接处理流程                            │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// 模拟连接
	lbIP := "10.0.1.100"
	realIP := netip.MustParseAddr("192.168.1.100")

	fmt.Printf("步骤 1: 收到连接\n")
	fmt.Printf("        源 IP (LB IP): %s\n", lbIP)
	fmt.Println()

	fmt.Printf("步骤 2: 检查是否可信 LB\n")
	isTrusted := mgr.IsTrustedLB(lbIP)
	fmt.Printf("        %s 在可信范围: %v\n", lbIP, isTrusted)
	fmt.Println()

	fmt.Printf("步骤 3: 解析 Proxy Protocol 获取真实 IP\n")
	fmt.Printf("        真实客户端 IP: %s\n", realIP)
	fmt.Println()

	fmt.Printf("步骤 4: 检查真实 IP 是否在黑名单\n")
	shouldDrop, reason := mgr.ShouldDrop(lbIP, realIP)
	fmt.Printf("        是否封禁: %v\n", shouldDrop)
	if shouldDrop {
		fmt.Printf("        封禁原因: %s\n", reason)
		fmt.Println()
		fmt.Println("        ┌─────────────────────────────────────┐")
		fmt.Println("        │  ✗ 连接被 DROP (真实 IP 在黑名单)    │")
		fmt.Println("        └─────────────────────────────────────┘")
	} else {
		fmt.Println()
		fmt.Println("        ┌─────────────────────────────────────┐")
		fmt.Println("        │  ✓ 连接允许通过                     │")
		fmt.Println("        └─────────────────────────────────────┘")
	}
}

// createProxyProtocolV2IPv4 创建 Proxy Protocol V2 IPv4 测试数据
func createProxyProtocolV2IPv4() []byte {
	// Proxy Protocol V2 签名
	sig := []byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")

	// 版本 (2) 和命令 (1 = PROXY)
	verCmd := byte(0x21)

	// 地址族 (AF_INET = 1) 和协议 (STREAM = 1)
	family := byte(0x11)

	// 地址长度 (IPv4: 4+4+2+2 = 12 bytes)
	addrLen := []byte{0x00, 0x0C}

	// 源 IP: 192.168.1.100
	srcIP := []byte{192, 168, 1, 100}

	// 目的 IP: 10.0.1.50
	dstIP := []byte{10, 0, 1, 50}

	// 源端口: 12345
	srcPort := []byte{0x30, 0x39}

	// 目的端口: 80
	dstPort := []byte{0x00, 0x50}

	// 组合
	data := make([]byte, 0, 28)
	data = append(data, sig...)
	data = append(data, verCmd, family)
	data = append(data, addrLen...)
	data = append(data, srcIP...)
	data = append(data, dstIP...)
	data = append(data, srcPort...)
	data = append(data, dstPort...)

	return data
}

// truncate 截断字符串
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
