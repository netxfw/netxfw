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

	// Get stats
	pass, drops, err := s.Stats.GetCounters()
	if err != nil {
		fmt.Printf("⚠️  Could not retrieve statistics: %v\n", err)
	} else {
		fmt.Printf("📊 Global Drop Count: %d packets\n", drops)
		fmt.Printf("📊 Global Pass Count: %d packets\n", pass)

		// Show detailed drop stats
		details, err := s.Stats.GetDropDetails()
		if err == nil && len(details) > 0 {
			// Sort by count descending
			sort.Slice(details, func(i, j int) bool {
				return details[i].Count > details[j].Count
			})

			fmt.Println("\n   🚫 Top Drops by Reason & Source:")
			fmt.Printf("   %-20s %-8s %-40s %-8s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count")
			fmt.Printf("   %s\n", strings.Repeat("-", 90))

			for _, d := range details {
				fmt.Printf("   %-20d %-8d %-40s %-8d %d\n", d.Reason, d.Protocol, d.SrcIP, d.DstPort, d.Count)
			}
		} else if err != nil {
			fmt.Printf("⚠️  Could not retrieve detailed drop statistics: %v\n", err)
		}
	}
	return nil
}
