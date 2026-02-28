package agent

import (
	"strconv"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
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
添加 IP 限速规则（每秒包数）

有效范围：
  rate:  1 - 1,000,000 (每秒包数)
  burst: 1 - 10,000,000 (突发包数)`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		ExecuteWithArgs(cmd, args, func(s *sdk.SDK, args []string) error {
			ip := args[0]

			// 验证 IP 格式：必须是有效的 IPv4/IPv6 地址或 CIDR
			// Validate IP format: must be valid IPv4/IPv6 address or CIDR
			if err := common.ValidateIP(ip); err != nil {
				return err
			}

			rate, err := strconv.ParseUint(args[1], 10, 64)
			if err != nil {
				return err
			}
			burst, err := strconv.ParseUint(args[2], 10, 64)
			if err != nil {
				return err
			}

			// 验证 rate 和 burst 范围
			// Validate rate and burst range
			if err := common.ValidateRateLimit(rate, burst); err != nil {
				return err
			}

			// Add rate limit rule
			// 添加限速规则
			if err := s.Rule.AddRateLimitRule(ip, rate, burst); err != nil {
				return err
			}
			logger.Get(cmd.Context()).Infof("[OK] Rate limit rule added for %s: %d/s (burst %d)", ip, rate, burst)
			return nil
		})
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
		ExecuteWithArgs(cmd, args, func(s *sdk.SDK, args []string) error {
			ip := args[0]

			// 验证 IP 格式：必须是有效的 IPv4/IPv6 地址或 CIDR
			// Validate IP format: must be valid IPv4/IPv6 address or CIDR
			if err := common.ValidateIP(ip); err != nil {
				return err
			}

			// Remove rate limit rule
			// 移除限速规则
			if err := s.Rule.RemoveRateLimitRule(ip); err != nil {
				return err
			}
			logger.Get(cmd.Context()).Infof("[OK] Rate limit rule removed for %s", ip)
			return nil
		})
	},
}

var limitListCmd = &cobra.Command{
	Use:   "list",
	Short: "List rate limit rules",
	// Short: 列出限速规则
	Long: `List all rate limit rules`,
	// Long: 列出所有限速规则
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			// 使用公共函数解析 limit 和 search 参数
			// Use common function to parse limit and search parameters
			limit, search, err := common.ParseLimitAndSearch(args, 100)
			if err != nil {
				return err
			}

			rules, _, err := s.Rule.ListRateLimitRules(limit, search)
			if err != nil {
				return err
			}

			cmd.Printf("Rate Limit Rules (%d):\n", len(rules))
			for ip, conf := range rules {
				cmd.Printf("  %s: %d/s (burst %d)\n", ip, conf.Rate, conf.Burst)
			}
			return nil
		})
	},
}

func init() {
	LimitCmd.AddCommand(limitAddCmd)
	LimitCmd.AddCommand(limitRemoveCmd)
	LimitCmd.AddCommand(limitListCmd)

	RegisterCommonFlags(limitAddCmd)
	RegisterCommonFlags(limitRemoveCmd)
	RegisterCommonFlags(limitListCmd)
}
