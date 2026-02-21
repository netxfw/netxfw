package agent

import (
	"os"
	"strconv"
	"time"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var SecurityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security management commands",
	Long: `Security management commands for netxfw
netxfw 的安全管理命令`,
}

// runSecurityBoolCommand executes a security command with boolean argument.
// runSecurityBoolCommand 执行带有布尔参数的安全命令。
func runSecurityBoolCommand(cmd *cobra.Command, args []string, setter func(*sdk.SDK, bool) error, settingName string) {
	common.EnsureStandaloneMode()

	s, err := common.GetSDK()
	if err != nil {
		cmd.PrintErrln(err)
		os.Exit(1)
	}

	enable, err := strconv.ParseBool(args[0])
	if err != nil {
		logger.Get(nil).Fatalf("❌ Invalid boolean value: %v", err)
	}

	if err := setter(s, enable); err != nil {
		cmd.PrintErrln(err)
		os.Exit(1)
	}
	logger.Get(nil).Infof("✅ %s set to %v", settingName, enable)
}

var securityFragmentsCmd = &cobra.Command{
	Use:   "fragments [true|false]",
	Short: "Drop fragmented packets",
	Long: `Enable/disable dropping of fragmented packets
启用/禁用丢弃分片数据包`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runSecurityBoolCommand(cmd, args, func(s *sdk.SDK, v bool) error {
			return s.Security.SetDropFragments(v)
		}, "Drop Fragments")
	},
}

var securityStrictTCPCmd = &cobra.Command{
	Use:   "strict-tcp [true|false]",
	Short: "Strict TCP flag validation",
	Long: `Enable/disable strict TCP flag validation
启用/禁用严格 TCP 标志验证`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runSecurityBoolCommand(cmd, args, func(s *sdk.SDK, v bool) error {
			return s.Security.SetStrictTCP(v)
		}, "Strict TCP")
	},
}

var securitySYNLimitCmd = &cobra.Command{
	Use:   "syn-limit [true|false]",
	Short: "SYN flood protection",
	Long: `Enable/disable SYN flood protection
启用/禁用 SYN Flood 保护`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runSecurityBoolCommand(cmd, args, func(s *sdk.SDK, v bool) error {
			return s.Security.SetSYNLimit(v)
		}, "SYN Limit")
	},
}

var securityBogonCmd = &cobra.Command{
	Use:   "bogon [true|false]",
	Short: "Bogon filtering",
	Long: `Enable/disable Bogon filtering
启用/禁用 Bogon 过滤`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runSecurityBoolCommand(cmd, args, func(s *sdk.SDK, v bool) error {
			return s.Security.SetBogonFilter(v)
		}, "Bogon filter")
	},
}

var securityAutoBlockCmd = &cobra.Command{
	Use:   "auto-block [true|false]",
	Short: "Auto-blocking",
	Long: `Enable/disable auto-blocking
启用/禁用自动封锁`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runSecurityBoolCommand(cmd, args, func(s *sdk.SDK, v bool) error {
			return s.Security.SetAutoBlock(v)
		}, "Auto-block")
	},
}

var securityAutoBlockExpiryCmd = &cobra.Command{
	Use:   "auto-block-expiry <seconds>",
	Short: "Auto-block expiry time",
	Long: `Set auto-block expiry time in seconds
设置自动封锁过期时间（秒）`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		expiry, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Get(nil).Fatalf("❌ Invalid expiry value: %v", err)
		}
		duration := time.Duration(expiry) * time.Second
		if err := s.Security.SetAutoBlockExpiry(duration); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		logger.Get(nil).Infof("✅ Auto-block expiry set to %v", duration)
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
