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

// Drop reason codes / 丢弃原因码
const (
	DROP_REASON_UNKNOWN     = 0
	DROP_REASON_INVALID     = 1
	DROP_REASON_PROTOCOL    = 2
	DROP_REASON_BLACKLIST   = 3
	DROP_REASON_RATELIMIT   = 4
	DROP_REASON_STRICT_TCP  = 5
	DROP_REASON_DEFAULT     = 6
	DROP_REASON_LAND_ATTACK = 7
	DROP_REASON_BOGON       = 8
	DROP_REASON_FRAGMENT    = 9
	DROP_REASON_BAD_HEADER  = 10
	DROP_REASON_TCP_FLAGS   = 11
	DROP_REASON_SPOOF       = 12
)

// Pass reason codes / 通过原因码
const (
	PASS_REASON_UNKNOWN   = 100
	PASS_REASON_WHITELIST = 101
	PASS_REASON_RETURN    = 102
	PASS_REASON_CONNTRACK = 103
	PASS_REASON_DEFAULT   = 104
)

// dropReasonToString maps drop reason codes to human-readable strings
// dropReasonToString 将丢弃原因码映射为可读字符串
func dropReasonToString(reason uint32) string {
	switch reason {
	case DROP_REASON_BLACKLIST:
		return "BLACKLIST"
	case DROP_REASON_RATELIMIT:
		return "RATELIMIT"
	case DROP_REASON_DEFAULT:
		return "DEFAULT_DENY"
	case DROP_REASON_INVALID:
		return "INVALID"
	case DROP_REASON_PROTOCOL:
		return "PROTOCOL"
	case DROP_REASON_STRICT_TCP:
		return "STRICT_TCP"
	case DROP_REASON_LAND_ATTACK:
		return "LAND_ATTACK"
	case DROP_REASON_BOGON:
		return "BOGON"
	case DROP_REASON_FRAGMENT:
		return "FRAGMENT"
	case DROP_REASON_BAD_HEADER:
		return "BAD_HEADER"
	case DROP_REASON_TCP_FLAGS:
		return "TCP_FLAGS"
	case DROP_REASON_SPOOF:
		return "SPOOF"
	default:
		return "UNKNOWN"
	}
}

// passReasonToString maps pass reason codes to human-readable strings
// passReasonToString 将通过原因码映射为可读字符串
func passReasonToString(reason uint32) string {
	switch reason {
	case PASS_REASON_WHITELIST:
		return "WHITELIST"
	case PASS_REASON_RETURN:
		return "RETURN"
	case PASS_REASON_CONNTRACK:
		return "CONNTRACK"
	case PASS_REASON_DEFAULT:
		return "DEFAULT"
	default:
		return "UNKNOWN"
	}
}

// protocolToString maps protocol numbers to human-readable strings
// protocolToString 将协议号映射为可读字符串
func protocolToString(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

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
	fmt.Printf("\n📊 Global Drop Count: %d packets \n", drops)

	// Show detailed drop stats
	// 显示详细丢弃统计
	dropDetails, err := s.Stats.GetDropDetails()
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
		fmt.Printf("   %-20s %-8s %-40s %-8s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count")
		fmt.Printf("   %s\n", strings.Repeat("-", 90))

		for i := 0; i < maxShow; i++ {
			d := dropDetails[i]
			fmt.Printf("   %-20s %-8s %-40s %-8d %d\n",
				dropReasonToString(d.Reason),
				protocolToString(d.Protocol),
				d.SrcIP,
				d.DstPort,
				d.Count)
		}
		if len(dropDetails) > 10 {
			fmt.Printf("   ... and more\n")
		}
	}

	// Show pass statistics
	// 显示通过统计
	fmt.Printf("\n📊 Global Pass Count: %d packets \n", pass)

	// Show detailed pass stats
	// 显示详细通过统计
	passDetails, err := s.Stats.GetPassDetails()
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
		fmt.Printf("   %-20s %-8s %-40s %-8s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count")
		fmt.Printf("   %s\n", strings.Repeat("-", 90))

		for i := 0; i < maxShow; i++ {
			d := passDetails[i]
			fmt.Printf("   %-20s %-8s %-40s %-8d %d\n",
				passReasonToString(d.Reason),
				protocolToString(d.Protocol),
				d.SrcIP,
				d.DstPort,
				d.Count)
		}
		if len(passDetails) > 10 {
			fmt.Printf("   ... and more\n")
		}
	}

	// Map statistics
	// Map 统计
	blacklistCount, _ := mgr.GetLockedIPCount()
	fmt.Printf("\n🔒 Locked IP Count: %d addresses\n", blacklistCount)

	whitelistCount, _ := mgr.GetWhitelistCount()
	fmt.Printf("⚪ Whitelist Count: %d addresses\n", whitelistCount)

	conntrackCount, _ := mgr.GetConntrackCount()
	fmt.Printf("🕵️  Active Connections: %d\n", conntrackCount)

	// Load configuration for policy display
	// 加载配置以显示策略
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err == nil {
		cfg := cfgManager.GetConfig()
		if cfg != nil {
			// Default deny policy
			// 默认拒绝策略
			if cfg.Base.DefaultDeny {
				fmt.Println("🛡️  Default Deny Policy: Enabled (Deny by default)")
			} else {
				fmt.Println("🛡️  Default Deny Policy: Disabled (Allow by default)")
			}

			// Return traffic
			// 回程流量
			if cfg.Base.AllowReturnTraffic {
				fmt.Println("🔄 Allow Return Traffic: Enabled")
			} else {
				fmt.Println("🔄 Allow Return Traffic: Disabled")
			}

			// ICMP
			// ICMP
			if cfg.Base.AllowICMP {
				fmt.Println("🏓 Allow ICMP (Ping): Enabled")
			} else {
				fmt.Println("🏓 Allow ICMP (Ping): Disabled")
			}

			// Connection tracking
			// 连接跟踪
			if cfg.Conntrack.Enabled {
				fmt.Printf("🕵️  Connection Tracking: Enabled\n")
				if cfg.Conntrack.TCPTimeout != "" {
					fmt.Printf("   └─ TCP Timeout: %s\n", cfg.Conntrack.TCPTimeout)
				}
				if cfg.Conntrack.UDPTimeout != "" {
					fmt.Printf("   └─ UDP Timeout: %s\n", cfg.Conntrack.UDPTimeout)
				}
			} else {
				fmt.Println("🕵️  Connection Tracking: Disabled")
			}

			// Rate limiting
			// 速率限制
			if cfg.RateLimit.Enabled {
				fmt.Println("🚀 Global Rate Limiting: Enabled")
			} else {
				fmt.Println("🚀 Global Rate Limiting: Disabled")
			}
		}
	}

	// Show attached interfaces
	// 显示已附加的接口
	fmt.Println("\n🔗 Attached Interfaces:")
	attachedIfaces, err := xdp.GetAttachedInterfaces(config.GetPinPath())
	if err == nil && len(attachedIfaces) > 0 {
		for _, iface := range attachedIfaces {
			fmt.Printf("  - %s (Mode: Native)\n", iface)
		}
	} else {
		fmt.Println("  - None")
	}

	return nil
}
