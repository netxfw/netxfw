package agent

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/internal/app"
	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/daemon"
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

func showStatus(ctx context.Context, s *sdk.SDK) error {
	fmt.Println("✅ XDP Program Status: Loaded and Running")
	fmt.Println()

	// Get global stats
	// 获取全局统计
	pass, drops, err := s.Stats.GetCounters()
	if err != nil {
		fmt.Printf("⚠️  Could not retrieve statistics: %v\n", err)
	} else {
		fmt.Println("📊 Global Statistics:")
		fmt.Printf("   ├─ Total Packets Processed: %d\n", pass+drops)
		fmt.Printf("   ├─ Passed Packets: %d\n", pass)
		fmt.Printf("   └─ Dropped Packets: %d\n", drops)
	}

	// Get map counts
	// 获取 Map 条目数
	fmt.Println()
	fmt.Println("📦 Map Statistics:")

	mgr := s.GetManager()

	// Blacklist count
	// 黑名单条目数
	blacklistCount, err := mgr.GetLockedIPCount()
	if err == nil {
		fmt.Printf("   ├─ Blacklist Entries: %d\n", blacklistCount)
	}

	// Dynamic blacklist count
	// 动态黑名单条目数
	dynBlacklist, _, err := mgr.ListDynamicBlacklistIPs(0, "")
	if err == nil {
		fmt.Printf("   ├─ Dynamic Blacklist Entries: %d\n", len(dynBlacklist))
	}

	// Whitelist count
	// 白名单条目数
	whitelistCount, err := mgr.GetWhitelistCount()
	if err == nil {
		fmt.Printf("   ├─ Whitelist Entries: %d\n", whitelistCount)
	}

	// Conntrack count
	// 连接跟踪条目数
	conntrackCount, err := mgr.GetConntrackCount()
	if err == nil {
		fmt.Printf("   └─ Conntrack Entries: %d\n", conntrackCount)
	}

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

		fmt.Println()
		fmt.Printf("🚫 Top %d Drops by Reason & Source:\n", maxShow)
		fmt.Printf("   %-8s %-8s %-40s %-8s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count")
		fmt.Printf("   %s\n", strings.Repeat("-", 80))

		for i := 0; i < maxShow; i++ {
			d := dropDetails[i]
			fmt.Printf("   %-8d %-8d %-40s %-8d %d\n", d.Reason, d.Protocol, d.SrcIP, d.DstPort, d.Count)
		}
		if len(dropDetails) > 10 {
			fmt.Printf("   ... and %d more entries\n", len(dropDetails)-10)
		}
	}

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

		fmt.Println()
		fmt.Printf("✅ Top %d Pass by Reason & Source:\n", maxShow)
		fmt.Printf("   %-8s %-8s %-40s %-8s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count")
		fmt.Printf("   %s\n", strings.Repeat("-", 80))

		for i := 0; i < maxShow; i++ {
			d := passDetails[i]
			fmt.Printf("   %-8d %-8d %-40s %-8d %d\n", d.Reason, d.Protocol, d.SrcIP, d.DstPort, d.Count)
		}
		if len(passDetails) > 10 {
			fmt.Printf("   ... and %d more entries\n", len(passDetails)-10)
		}
	}

	return nil
}
