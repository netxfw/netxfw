package agent

import (
	"log"
	"os"
	"strconv"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var SystemCmd = &cobra.Command{
	Use:   "system",
	Short: "System management commands",
	Long:  `System management commands for netxfw`,
}

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	Long:  `Initialize default configuration file in /root/netxfw/`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.InitConfiguration == nil {
			cmd.PrintErrln("❌ common.InitConfiguration function not initialized")
			os.Exit(1)
		}
		// Initialize configuration
		// 初始化配置
		common.InitConfiguration(cmd.Context())
	},
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show runtime status and statistics",
	Long:  `Show current runtime status and statistics`,
	Run: func(cmd *cobra.Command, args []string) {
		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		// Show system status
		// 显示系统状态
		if err := common.ShowStatus(cmd.Context(), mgr); err != nil {
			cmd.PrintErrln(err)
		}
	},
}

var systemTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration validity",
	Long:  `Test configuration validity`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.TestConfiguration == nil {
			cmd.PrintErrln("❌ common.TestConfiguration function not initialized")
			os.Exit(1)
		}
		// Test configuration
		// 测试配置
		common.TestConfiguration(cmd.Context())
	},
}

var systemDaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background process",
	Long:  `Start background process`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.RunDaemon == nil {
			cmd.PrintErrln("❌ common.RunDaemon function not initialized")
			os.Exit(1)
		}
		// Run as daemon
		// 以守护进程方式运行
		common.RunDaemon(cmd.Context())
	},
}

var interfaces []string

var systemLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load XDP driver",
	Long:  `Load XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.InitConfiguration == nil {
			cmd.PrintErrln("❌ common.InitConfiguration function not initialized")
			os.Exit(1)
		}
		if common.InstallXDP == nil {
			cmd.PrintErrln("❌ common.InstallXDP function not initialized")
			os.Exit(1)
		}

		ctx := cmd.Context()
		common.InitConfiguration(ctx)

		// Install XDP program
		// 安装 XDP 程序
		// Note: InstallXDP creates its own manager internally usually, or attaches to interfaces.
		// Checking api.go, InstallXDP signature is: func(ctx context.Context, interfaces []string)
		common.InstallXDP(ctx, interfaces)
	},
}

var systemReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Smoothly reload XDP (supports capacity adjustment)",
	Long:  `Smoothly reload XDP (supports capacity adjustment)`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.ReloadXDP == nil {
			cmd.PrintErrln("❌ common.ReloadXDP function not initialized")
			os.Exit(1)
		}
		// Reload XDP program
		// 重载 XDP 程序
		common.ReloadXDP(cmd.Context(), interfaces)
	},
}

var systemUnloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Unload XDP driver",
	Long:  `Unload XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.RemoveXDP == nil {
			cmd.PrintErrln("❌ common.RemoveXDP function not initialized")
			os.Exit(1)
		}
		// Remove XDP program
		// 移除 XDP 程序
		common.RemoveXDP(cmd.Context(), interfaces)
	},
}

var systemSetDefaultDenyCmd = &cobra.Command{
	Use:   "set-default-deny [true|false]",
	Short: "Set default deny policy",
	Long:  `Set default deny policy`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		// Set default deny policy
		// 设置默认拒绝策略
		common.SyncDefaultDeny(cmd.Context(), mgr, enable)
	},
}

var systemRateLimitCmd = &cobra.Command{
	Use:   "ratelimit [true|false]",
	Short: "Enable/disable universal rate limiting",
	Long:  `Enable/disable universal rate limiting`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		// Toggle global rate limit
		// 切换全局速率限制
		common.SyncEnableRateLimit(cmd.Context(), mgr, enable)
	},
}

var systemAFXDPCmd = &cobra.Command{
	Use:   "afxdp [true|false]",
	Short: "Enable/disable AF_XDP redirection",
	Long:  `Enable/disable AF_XDP redirection`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		// Toggle AF_XDP
		// 切换 AF_XDP
		common.SyncEnableAFXDP(cmd.Context(), mgr, enable)
	},
}

func init() {
	SystemCmd.AddCommand(systemInitCmd)
	SystemCmd.AddCommand(systemStatusCmd)
	SystemCmd.AddCommand(systemTestCmd)
	SystemCmd.AddCommand(systemDaemonCmd)
	SystemCmd.AddCommand(systemLoadCmd)
	SystemCmd.AddCommand(systemReloadCmd)

	systemLoadCmd.Flags().StringSliceVarP(&interfaces, "iface", "i", nil, "Interfaces to attach to (e.g., eth0,eth1)")
	systemReloadCmd.Flags().StringSliceVarP(&interfaces, "iface", "i", nil, "Interfaces to attach to (e.g., eth0,eth1)")
	systemUnloadCmd.Flags().StringSliceVarP(&interfaces, "iface", "i", nil, "Interfaces to detach from (e.g., eth0,eth1)")

	SystemCmd.AddCommand(systemUnloadCmd)
	SystemCmd.AddCommand(systemSetDefaultDenyCmd)
	SystemCmd.AddCommand(systemRateLimitCmd)
	SystemCmd.AddCommand(systemAFXDPCmd)

	SystemCmd.AddCommand(systemTopCmd)
	systemTopCmd.Flags().IntVarP(&limit, "limit", "n", 10, "Number of entries to show")
	systemTopCmd.Flags().StringVarP(&sortBy, "sort", "s", "total", "Sort by: total (traffic) or drop")
}

var limit int
var sortBy string

var systemTopCmd = &cobra.Command{
	Use:   "top",
	Short: "Show top IPs by traffic or drops",
	Long:  `Show top source IPs sorted by total traffic or drop count.`,
	Run: func(cmd *cobra.Command, args []string) {
		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		common.ShowTopStats(cmd.Context(), mgr, limit, sortBy)
	},
}
