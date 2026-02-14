package agent

import (
	"log"
	"os"
	"strconv"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var LimitCmd = &cobra.Command{
	Use:   "limit",
	Short: "Rate limit management",
	Long: `Rate limit management commands
限速管理命令`,
}

var limitAddCmd = &cobra.Command{
	Use:   "add <ip> <rate> <burst>",
	Short: "Add rate limit rule",
	Long: `Add IP rate limit rule (packets per second)
添加 IP 限速规则（每秒包数）`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}

		common.EnsureStandaloneMode()

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		ctx := cmd.Context()

		ip := args[0]
		rate, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			log.Fatalf("❌ Invalid rate: %v", err)
		}
		burst, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil {
			log.Fatalf("❌ Invalid burst: %v", err)
		}
		// Add rate limit rule
		// 添加限速规则
		if err := common.SyncRateLimitRule(ctx, mgr, ip, rate, burst, true); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

var limitRemoveCmd = &cobra.Command{
	Use:   "remove <ip>",
	Short: "Remove rate limit rule",
	Long:  `Remove IP rate limit rule`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}

		common.EnsureStandaloneMode()

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		ctx := cmd.Context()

		// Remove rate limit rule
		// 移除限速规则
		if err := common.SyncRateLimitRule(ctx, mgr, args[0], 0, 0, false); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

var limitListCmd = &cobra.Command{
	Use:   "list",
	Short: "List rate limit rules",
	Long:  `List all rate limit rules`,
	Run: func(cmd *cobra.Command, args []string) {
		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		// Show rate limit rules
		// 显示限速规则
		if err := common.ShowRateLimitRules(cmd.Context(), mgr); err != nil {
			cmd.PrintErrln(err)
		}
	},
}

func init() {
	LimitCmd.AddCommand(limitAddCmd)
	LimitCmd.AddCommand(limitRemoveCmd)
	LimitCmd.AddCommand(limitListCmd)
}
