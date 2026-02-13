package agent

import (
	"log"
	"os"
	"strconv"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var SecurityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security management commands",
	Long: `Security management commands for netxfw
netxfw 的安全管理命令`,
}

var securityFragmentsCmd = &cobra.Command{
	Use:   "fragments [true|false]",
	Short: "Drop fragmented packets",
	Long: `Enable/disable dropping of fragmented packets
启用/禁用丢弃分片数据包`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncDropFragments == nil {
			cmd.PrintErrln("❌ common.SyncDropFragments function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		// Toggle drop fragments
		// 切换丢弃分片
		common.SyncDropFragments(enable)
	},
}

var securityStrictTCPCmd = &cobra.Command{
	Use:   "strict-tcp [true|false]",
	Short: "Strict TCP flag validation",
	Long: `Enable/disable strict TCP flag validation
启用/禁用严格 TCP 标志验证`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncStrictTCP == nil {
			cmd.PrintErrln("❌ common.SyncStrictTCP function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		// Toggle strict TCP
		// 切换严格 TCP 检查
		common.SyncStrictTCP(enable)
	},
}

var securitySYNLimitCmd = &cobra.Command{
	Use:   "syn-limit [true|false]",
	Short: "SYN flood protection",
	Long: `Enable/disable SYN flood protection
启用/禁用 SYN Flood 保护`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncSYNLimit == nil {
			cmd.PrintErrln("❌ common.SyncSYNLimit function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		// Toggle SYN limit
		// 切换 SYN 限制
		common.SyncSYNLimit(enable)
	},
}

var securityBogonCmd = &cobra.Command{
	Use:   "bogon [true|false]",
	Short: "Bogon filtering",
	Long: `Enable/disable Bogon filtering
启用/禁用 Bogon 过滤`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncBogonFilter == nil {
			cmd.PrintErrln("❌ common.SyncBogonFilter function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		// Toggle Bogon filtering
		// 切换 Bogon 过滤
		common.SyncBogonFilter(enable)
	},
}

var securityAutoBlockCmd = &cobra.Command{
	Use:   "auto-block [true|false]",
	Short: "Auto-blocking",
	Long: `Enable/disable auto-blocking
启用/禁用自动封锁`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncAutoBlock == nil {
			cmd.PrintErrln("❌ common.SyncAutoBlock function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		// Toggle auto-blocking
		// 切换自动封锁
		common.SyncAutoBlock(enable)
	},
}

var securityAutoBlockExpiryCmd = &cobra.Command{
	Use:   "auto-block-expiry <seconds>",
	Short: "Auto-block expiry time",
	Long: `Set auto-block expiry time in seconds
设置自动封锁过期时间（秒）`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncAutoBlockExpiry == nil {
			cmd.PrintErrln("❌ common.SyncAutoBlockExpiry function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		expiry, err := strconv.Atoi(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid expiry value: %v", err)
		}
		// Set auto-block expiry
		// 设置自动封锁过期时间
		common.SyncAutoBlockExpiry(uint32(expiry))
	},
}

func init() {
	SecurityCmd.AddCommand(securityFragmentsCmd)
	SecurityCmd.AddCommand(securityStrictTCPCmd)
	SecurityCmd.AddCommand(securitySYNLimitCmd)
	SecurityCmd.AddCommand(securityBogonCmd)
	SecurityCmd.AddCommand(securityAutoBlockCmd)
	SecurityCmd.AddCommand(securityAutoBlockExpiryCmd)
}
