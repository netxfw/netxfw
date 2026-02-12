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
	Long:  `Rate limit management commands`,
}

var limitAddCmd = &cobra.Command{
	Use:   "add <ip> <rate> <burst>",
	Short: "Add rate limit rule",
	Long:  `Add IP rate limit rule (packets per second)`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncRateLimitRule == nil {
			cmd.PrintErrln("❌ common.SyncRateLimitRule function not initialized")
			os.Exit(1)
		}

		common.EnsureStandaloneMode()

		ip := args[0]
		rate, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			log.Fatalf("❌ Invalid rate: %v", err)
		}
		burst, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil {
			log.Fatalf("❌ Invalid burst: %v", err)
		}
		common.SyncRateLimitRule(ip, rate, burst, true)
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
		if common.SyncRateLimitRule == nil {
			cmd.PrintErrln("❌ common.SyncRateLimitRule function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		common.SyncRateLimitRule(args[0], 0, 0, false)
	},
}

var limitListCmd = &cobra.Command{
	Use:   "list",
	Short: "List rate limit rules",
	Long:  `List all rate limit rules`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.ShowRateLimitRules == nil {
			cmd.PrintErrln("❌ common.ShowRateLimitRules function not initialized")
			os.Exit(1)
		}
		common.ShowRateLimitRules()
	},
}

func init() {
	LimitCmd.AddCommand(limitAddCmd)
	LimitCmd.AddCommand(limitRemoveCmd)
	LimitCmd.AddCommand(limitListCmd)
}
