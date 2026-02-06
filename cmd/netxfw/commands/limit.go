package commands

import (
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var limitCmd = &cobra.Command{
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
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncRateLimitRule == nil {
			cmd.PrintErrln("❌ SyncRateLimitRule function not initialized")
			os.Exit(1)
		}

		EnsureStandaloneMode()

		ip := args[0]
		rate, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			log.Fatalf("❌ Invalid rate: %v", err)
		}
		burst, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil {
			log.Fatalf("❌ Invalid burst: %v", err)
		}
		SyncRateLimitRule(ip, rate, burst, true)
	},
}

var limitRemoveCmd = &cobra.Command{
	Use:   "remove <ip>",
	Short: "Remove rate limit rule",
	Long:  `Remove IP rate limit rule`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncRateLimitRule == nil {
			cmd.PrintErrln("❌ SyncRateLimitRule function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		SyncRateLimitRule(args[0], 0, 0, false)
	},
}

var limitListCmd = &cobra.Command{
	Use:   "list",
	Short: "List rate limit rules",
	Long:  `List all rate limit rules`,
	Run: func(cmd *cobra.Command, args []string) {
		if ShowRateLimitRules == nil {
			cmd.PrintErrln("❌ ShowRateLimitRules function not initialized")
			os.Exit(1)
		}
		ShowRateLimitRules()
	},
}

func init() {
	limitCmd.AddCommand(limitAddCmd)
	limitCmd.AddCommand(limitRemoveCmd)
	limitCmd.AddCommand(limitListCmd)

	RootCmd.AddCommand(limitCmd)
}
