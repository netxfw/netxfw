package agent

import (
	"os"
	"strconv"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/spf13/cobra"
)

var LimitCmd = &cobra.Command{
	Use:   "limit",
	Short: "Rate limit management",
	// Short: 限速管理
	Long: `Rate limit management commands
限速管理命令`,
}

var limitAddCmd = &cobra.Command{
	Use:   "add <ip> <rate> <burst>",
	Short: "Add rate limit rule",
	// Short: 添加限速规则
	Long: `Add IP rate limit rule (packets per second)
添加 IP 限速规则（每秒包数）`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		ip := args[0]
		rate, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			logger.Get(nil).Fatalf("❌ Invalid rate: %v", err)
		}
		burst, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil {
			logger.Get(nil).Fatalf("❌ Invalid burst: %v", err)
		}
		// Add rate limit rule
		// 添加限速规则
		if err := s.Rule.AddRateLimitRule(ip, rate, burst); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		logger.Get(nil).Infof("✅ Rate limit rule added for %s: %d/s (burst %d)", ip, rate, burst)
	},
}

var limitRemoveCmd = &cobra.Command{
	Use:   "remove <ip>",
	Short: "Remove rate limit rule",
	// Short: 移除限速规则
	Long: `Remove IP rate limit rule`,
	// Long: 移除 IP 限速规则
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		ip := args[0]
		// Remove rate limit rule
		// 移除限速规则
		if err := s.Rule.RemoveRateLimitRule(ip); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		logger.Get(nil).Infof("✅ Rate limit rule removed for %s", ip)
	},
}

var limitListCmd = &cobra.Command{
	Use:   "list",
	Short: "List rate limit rules",
	// Short: 列出限速规则
	Long: `List all rate limit rules`,
	// Long: 列出所有限速规则
	Run: func(cmd *cobra.Command, args []string) {
		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		limit := 100
		search := ""

		if len(args) > 0 {
			if l, parseErr := strconv.Atoi(args[0]); parseErr == nil {
				limit = l
				if len(args) > 1 {
					search = args[1]
				}
			} else {
				search = args[0]
			}
		}

		rules, _, err := s.Rule.ListRateLimitRules(limit, search)
		if err != nil {
			cmd.PrintErrln(err)
		}

		cmd.Printf("Rate Limit Rules (%d):\n", len(rules))
		for ip, conf := range rules {
			cmd.Printf("  %s: %d/s (burst %d)\n", ip, conf.Rate, conf.Burst)
		}
	},
}

func init() {
	LimitCmd.AddCommand(limitAddCmd)
	LimitCmd.AddCommand(limitRemoveCmd)
	LimitCmd.AddCommand(limitListCmd)
}
