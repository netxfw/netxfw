package agent

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/internal/app"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var SystemCmd = &cobra.Command{
	Use:   "system",
	Short: "System management commands",
	// Short: 系统管理命令
	Long: `System management commands for netxfw`,
	// Long: netxfw 的系统管理命令
}

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	// Short: 初始化配置文件
	Long: `Initialize default configuration file in /root/netxfw/`,
	// Long: 在 /root/netxfw/ 中初始化默认配置文件
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize configuration
		// 初始化配置
		core.InitConfiguration(cmd.Context())
	},
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show runtime status and statistics",
	// Short: 显示运行时状态和统计信息
	Long: `Show current runtime status and statistics`,
	// Long: 显示当前的运行时状态和统计信息
	Run: func(cmd *cobra.Command, args []string) {
		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		// Show system status
		// 显示系统状态
		if err := showStatus(cmd.Context(), s); err != nil {
			cmd.PrintErrln(err)
		}
	},
}

var systemTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration validity",
	// Short: 测试配置有效性
	Long: `Test configuration validity`,
	// Long: 测试配置有效性
	Run: func(cmd *cobra.Command, args []string) {
		// Test configuration
		// 测试配置
		daemon.TestConfiguration(cmd.Context())
	},
}

var systemDaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background process",
	// Short: 启动后台进程
	Long: `Start background process`,
	// Long: 启动后台进程
	Run: func(cmd *cobra.Command, args []string) {
		// Run as daemon
		// 以守护进程方式运行
		app.RunDaemon(cmd.Context())
	},
}

var interfaces []string

var systemLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load XDP driver",
	// Short: 加载 XDP 驱动
	Long: `Load XDP driver`,
	// Long: 加载 XDP 驱动
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		if err := app.InstallXDP(cmd.Context(), interfaces); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

var systemReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Hot-reload XDP program with new configuration",
	// Short: 使用新配置热重载 XDP 程序
	Long: `Hot-reload XDP program: applies new configuration without dropping connections.
Supports capacity changes with state migration.`,
	// Long: 热重载 XDP 程序：应用新配置而不中断连接。支持容量变更时的状态迁移。
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		if err := app.ReloadXDP(cmd.Context(), interfaces); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		fmt.Println("✅ XDP program reloaded successfully")
	},
}

func init() {
	SystemCmd.AddCommand(systemInitCmd)
	SystemCmd.AddCommand(systemStatusCmd)
	SystemCmd.AddCommand(systemTestCmd)
	SystemCmd.AddCommand(systemDaemonCmd)

	systemLoadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to attach XDP to")
	SystemCmd.AddCommand(systemLoadCmd)

	systemReloadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to attach XDP to")
	SystemCmd.AddCommand(systemReloadCmd)
}

// showStatus displays the system status including statistics and configuration
// showStatus 显示系统状态，包括统计信息和配置
func showStatus(ctx context.Context, s *sdk.SDK) error {
	fmt.Println("✅ XDP Program Status: Loaded and Running")

	mgr := s.GetManager()

	// Get global stats
	// 获取全局统计
	pass, drops, err := s.Stats.GetCounters()
	if err != nil {
		fmt.Printf("⚠️  Could not retrieve statistics: %v\n", err)
		return nil
	}

	// Show drop statistics
	// 显示丢弃统计
	showDropStatistics(s.Stats, drops, pass)

	// Show pass statistics
	// 显示通过统计
	showPassStatistics(s.Stats, pass, drops)

	// Map statistics
	// Map 统计
	showMapStatistics(mgr)

	// Load configuration for policy display
	// 加载配置以显示策略
	showPolicyConfiguration()

	// Show attached interfaces
	// 显示已附加的接口
	showAttachedInterfaces()

	return nil
}

// StatsAPI interface for statistics operations (for testing and decoupling)
// StatsAPI 统计操作接口（用于测试和解耦）
type StatsAPI interface {
	GetDropDetails() ([]sdk.DropDetailEntry, error)
	GetPassDetails() ([]sdk.DropDetailEntry, error)
}

// showDropStatistics displays drop statistics with percentages
// showDropStatistics 显示带百分比的丢弃统计
func showDropStatistics(s StatsAPI, drops, pass uint64) {
	totalPackets := pass + drops
	dropPercent := float64(0)
	if totalPackets > 0 {
		dropPercent = float64(drops) / float64(totalPackets) * 100
	}
	fmt.Printf("\n📊 Global Drop Count: %d packets (%.2f%%)\n", drops, dropPercent)

	// Show detailed drop stats
	// 显示详细丢弃统计
	dropDetails, err := s.GetDropDetails()
	if err == nil && len(dropDetails) > 0 {
		// Sort by count descending
		// 按计数降序排序
		sort.Slice(dropDetails, func(i, j int) bool {
			return dropDetails[i].Count > dropDetails[j].Count
		})

		// Limit to top 10
		// 限制显示前 10 条
		maxShow := 10
		if len(dropDetails) < maxShow {
			maxShow = len(dropDetails)
		}

		fmt.Println("\n   🚫 Top Drops by Reason & Source:")
		fmt.Printf("   %-20s %-8s %-40s %-8s %-10s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count", "Percent")
		fmt.Printf("   %s\n", strings.Repeat("-", 100))

		for i := 0; i < maxShow; i++ {
			d := dropDetails[i]
			percent := float64(0)
			if drops > 0 {
				percent = float64(d.Count) / float64(drops) * 100
			}
			fmt.Printf("   %-20s %-8s %-40s %-8d %-10d %.2f%%\n",
				dropReasonToString(d.Reason),
				protocolToString(d.Protocol),
				d.SrcIP,
				d.DstPort,
				d.Count,
				percent)
		}
		if len(dropDetails) > 10 {
			fmt.Printf("   ... and more\n")
		}

		// Show drop reason summary
		// 显示丢弃原因汇总
		showDropReasonSummary(dropDetails, drops)
	}
}

// showDropReasonSummary displays a summary of drop reasons
// showDropReasonSummary 显示丢弃原因汇总
func showDropReasonSummary(dropDetails []sdk.DropDetailEntry, drops uint64) {
	dropReasonSummary := make(map[string]uint64)
	for _, d := range dropDetails {
		reason := dropReasonToString(d.Reason)
		dropReasonSummary[reason] += d.Count
	}
	if len(dropReasonSummary) > 0 {
		fmt.Println("\n   📈 Drop Reason Summary:")
		for reason, count := range dropReasonSummary {
			percent := float64(0)
			if drops > 0 {
				percent = float64(count) / float64(drops) * 100
			}
			fmt.Printf("      %s: %d (%.2f%%)\n", reason, count, percent)
		}
	}
}

// showPassStatistics displays pass statistics with percentages
// showPassStatistics 显示带百分比的通过统计
func showPassStatistics(s StatsAPI, pass, drops uint64) {
	totalPackets := pass + drops
	passPercent := float64(0)
	if totalPackets > 0 {
		passPercent = float64(pass) / float64(totalPackets) * 100
	}
	fmt.Printf("\n📊 Global Pass Count: %d packets (%.2f%%)\n", pass, passPercent)

	// Show detailed pass stats
	// 显示详细通过统计
	passDetails, err := s.GetPassDetails()
	if err == nil && len(passDetails) > 0 {
		// Sort by count descending
		// 按计数降序排序
		sort.Slice(passDetails, func(i, j int) bool {
			return passDetails[i].Count > passDetails[j].Count
		})

		// Limit to top 10
		// 限制显示前 10 条
		maxShow := 10
		if len(passDetails) < maxShow {
			maxShow = len(passDetails)
		}

		fmt.Println("\n   ✅ Top Allowed by Reason & Source:")
		fmt.Printf("   %-20s %-8s %-40s %-8s %-10s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count", "Percent")
		fmt.Printf("   %s\n", strings.Repeat("-", 100))

		for i := 0; i < maxShow; i++ {
			d := passDetails[i]
			percent := float64(0)
			if pass > 0 {
				percent = float64(d.Count) / float64(pass) * 100
			}
			fmt.Printf("   %-20s %-8s %-40s %-8d %-10d %.2f%%\n",
				passReasonToString(d.Reason),
				protocolToString(d.Protocol),
				d.SrcIP,
				d.DstPort,
				d.Count,
				percent)
		}
		if len(passDetails) > 10 {
			fmt.Printf("   ... and more\n")
		}

		// Show pass reason summary
		// 显示通过原因汇总
		showPassReasonSummary(passDetails, pass)
	}
}

// showPassReasonSummary displays a summary of pass reasons
// showPassReasonSummary 显示通过原因汇总
func showPassReasonSummary(passDetails []sdk.DropDetailEntry, pass uint64) {
	passReasonSummary := make(map[string]uint64)
	for _, d := range passDetails {
		reason := passReasonToString(d.Reason)
		passReasonSummary[reason] += d.Count
	}
	if len(passReasonSummary) > 0 {
		fmt.Println("\n   📈 Pass Reason Summary:")
		for reason, count := range passReasonSummary {
			percent := float64(0)
			if pass > 0 {
				percent = float64(count) / float64(pass) * 100
			}
			fmt.Printf("      %s: %d (%.2f%%)\n", reason, count, percent)
		}
	}
}

// showMapStatistics displays BPF map statistics
// showMapStatistics 显示 BPF Map 统计
func showMapStatistics(mgr sdk.ManagerInterface) {
	fmt.Println()
	fmt.Println("📦 Map Statistics:")

	blacklistCount, _ := mgr.GetLockedIPCount()
	fmt.Printf("   ├─ 🔒 Blacklist Entries: %d\n", blacklistCount)

	dynBlacklist, _, _ := mgr.ListDynamicBlacklistIPs(0, "")
	fmt.Printf("   ├─ 🔒 Dynamic Blacklist: %d\n", len(dynBlacklist))

	whitelistCount, _ := mgr.GetWhitelistCount()
	fmt.Printf("   ├─ ⚪ Whitelist Entries: %d\n", whitelistCount)

	conntrackCount, _ := mgr.GetConntrackCount()
	fmt.Printf("   ├─ 🕵️  Active Connections: %d\n", conntrackCount)

	// IP+Port rules
	// IP+端口规则
	ipPortRules, _, _ := mgr.ListIPPortRules(false, 0, "")
	fmt.Printf("   ├─ 📋 IP+Port Rules: %d\n", len(ipPortRules))

	// Allowed ports
	// 允许端口
	allowedPorts, _ := mgr.ListAllowedPorts()
	fmt.Printf("   ├─ 🔓 Allowed Ports: %d\n", len(allowedPorts))

	// Rate limit rules
	// 速率限制规则
	rateLimitRules, _, _ := mgr.ListRateLimitRules(0, "")
	fmt.Printf("   └─ ⏱️  Rate Limit Rules: %d\n", len(rateLimitRules))
}

// showPolicyConfiguration displays policy configuration
// showPolicyConfiguration 显示策略配置
func showPolicyConfiguration() {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err != nil {
		return
	}

	cfg := cfgManager.GetConfig()
	if cfg == nil {
		return
	}

	fmt.Println()
	fmt.Println("⚙️  Policy Configuration:")

	// Default deny policy
	// 默认拒绝策略
	if cfg.Base.DefaultDeny {
		fmt.Println("   ├─ 🛡️  Default Deny: Enabled (Deny by default)")
	} else {
		fmt.Println("   ├─ 🛡️  Default Deny: Disabled (Allow by default)")
	}

	// Return traffic
	// 回程流量
	if cfg.Base.AllowReturnTraffic {
		fmt.Println("   ├─ 🔄 Allow Return Traffic: Enabled")
	} else {
		fmt.Println("   ├─ 🔄 Allow Return Traffic: Disabled")
	}

	// ICMP
	// ICMP
	if cfg.Base.AllowICMP {
		fmt.Println("   ├─ 🏓 Allow ICMP (Ping): Enabled")
	} else {
		fmt.Println("   ├─ 🏓 Allow ICMP (Ping): Disabled")
	}

	// Strict TCP
	// 严格 TCP
	if cfg.Base.StrictTCP {
		fmt.Println("   ├─ 🔒 Strict TCP: Enabled")
	} else {
		fmt.Println("   ├─ 🔒 Strict TCP: Disabled")
	}

	// SYN Limit
	// SYN 限制
	if cfg.Base.SYNLimit {
		fmt.Println("   ├─ 🚧 SYN Flood Protection: Enabled")
	} else {
		fmt.Println("   ├─ 🚧 SYN Flood Protection: Disabled")
	}

	// Bogon Filter
	// Bogon 过滤
	if cfg.Base.BogonFilter {
		fmt.Println("   ├─ 🌐 Bogon Filter: Enabled")
	} else {
		fmt.Println("   ├─ 🌐 Bogon Filter: Disabled")
	}

	// Connection tracking
	// 连接跟踪
	if cfg.Conntrack.Enabled {
		fmt.Println("   ├─ 🕵️  Connection Tracking: Enabled")
		if cfg.Conntrack.TCPTimeout != "" {
			fmt.Printf("   │     └─ TCP Timeout: %s\n", cfg.Conntrack.TCPTimeout)
		}
		if cfg.Conntrack.UDPTimeout != "" {
			fmt.Printf("   │     └─ UDP Timeout: %s\n", cfg.Conntrack.UDPTimeout)
		}
	} else {
		fmt.Println("   ├─ 🕵️  Connection Tracking: Disabled")
	}

	// Rate limiting
	// 速率限制
	if cfg.RateLimit.Enabled {
		fmt.Println("   ├─ 🚀 Rate Limiting: Enabled")
		if cfg.RateLimit.AutoBlock {
			fmt.Printf("   │     └─ Auto Block: Enabled (Expiry: %s)\n", cfg.RateLimit.AutoBlockExpiry)
		}
	} else {
		fmt.Println("   ├─ 🚀 Rate Limiting: Disabled")
	}

	// Log Engine
	// 日志引擎
	if cfg.LogEngine.Enabled {
		fmt.Printf("   ├─ 📝 Log Engine: Enabled (%d rules)\n", len(cfg.LogEngine.Rules))
	} else {
		fmt.Println("   ├─ 📝 Log Engine: Disabled")
	}

	// Web Interface
	// Web 界面
	if cfg.Web.Enabled {
		fmt.Printf("   └─ 🌐 Web Interface: Enabled (Port: %d)\n", cfg.Web.Port)
	} else {
		fmt.Println("   └─ 🌐 Web Interface: Disabled")
	}
}

// showAttachedInterfaces displays attached network interfaces
// showAttachedInterfaces 显示已附加的网络接口
func showAttachedInterfaces() {
	fmt.Println("\n🔗 Attached Interfaces:")
	attachedIfaces, err := xdp.GetAttachedInterfaces(config.GetPinPath())
	if err == nil && len(attachedIfaces) > 0 {
		for _, iface := range attachedIfaces {
			fmt.Printf("  - %s (Mode: Native)\n", iface)
		}
	} else {
		fmt.Println("  - None")
	}
}
