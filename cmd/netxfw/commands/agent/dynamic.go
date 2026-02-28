package agent

import (
	"fmt"
	"time"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

// DynamicCmd 动态黑名单管理命令（dyn/dynamic 别名）
// DynamicCmd dynamic blacklist management command (dyn/dynamic aliases)
var DynamicCmd = &cobra.Command{
	Use:     "dynamic",
	Aliases: []string{"dyn"},
	Short:   "Dynamic blacklist management",
	// Short: 动态黑名单管理
	Long: `Dynamic blacklist management commands
动态黑名单管理命令

Dynamic blacklist uses LRU hash with auto-expiry (TTL).
动态黑名单使用 LRU Hash，支持自动过期（TTL）。

Examples:
  netxfw dynamic add 192.168.1.100 --ttl 1h     # Block IP for 1 hour
  netxfw dyn add 10.0.0.1 --ttl 24h             # Block IP for 24 hours (using alias)
  netxfw dynamic del 192.168.1.100              # Remove from dynamic blacklist
  netxfw dynamic list                           # List all dynamic blacklist entries`,
}

// dynamicAddCmd 添加动态黑名单命令
// dynamicAddCmd add dynamic blacklist command
var dynamicAddCmd = &cobra.Command{
	Use:   "add <ip>",
	Short: "Add IP to dynamic blacklist",
	// Short: 添加 IP 到动态黑名单
	Long: `Add IP to dynamic blacklist with TTL (Time To Live)
添加 IP 到动态黑名单，支持 TTL（生存时间）

The IP will be automatically removed when TTL expires.
IP 将在 TTL 过期时自动移除。

Examples:
  netxfw dynamic add 192.168.1.100 --ttl 1h
  netxfw dynamic add 10.0.0.1 --ttl 24h
  netxfw dynamic add 2001:db8::1 --ttl 30m`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			ip := args[0]

			// 验证 IP 格式：必须是有效的 IPv4/IPv6 地址
			// Validate IP format: must be valid IPv4/IPv6 address
			if err := common.ValidateIP(ip); err != nil {
				return err
			}

			// 获取 TTL 参数并验证
			// Get TTL parameter and validate
			ttlStr, _ := cmd.Flags().GetString("ttl")
			ttl, err := common.ParseAndValidateTTL(ttlStr)
			if err != nil {
				return err
			}

			// 添加到动态黑名单
			// Add to dynamic blacklist
			if err := s.Blacklist.AddWithDuration(ip, ttl); err != nil {
				return fmt.Errorf("[ERROR] Failed to add to dynamic blacklist: %v", err)
			}

			logger.Get(cmd.Context()).Infof("[BLOCK] Added %s to dynamic blacklist for %v", ip, ttl)
			return nil
		})
	},
}

// dynamicDelCmd 删除动态黑名单命令（del/delete 别名）
// dynamicDelCmd delete dynamic blacklist command (del/delete aliases)
var dynamicDelCmd = &cobra.Command{
	Use:     "del <ip>",
	Aliases: []string{"delete"},
	Short:   "Delete IP from dynamic blacklist",
	// Short: 从动态黑名单删除 IP
	Long: `Delete IP from dynamic blacklist
从动态黑名单删除 IP

Aliases: del, delete
别名：del, delete

Examples:
  netxfw dynamic del 192.168.1.100
  netxfw dynamic delete 10.0.0.1
  netxfw dyn del 2001:db8::1`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			ip := args[0]

			// 验证 IP 格式：必须是有效的 IPv4/IPv6 地址
			// Validate IP format: must be valid IPv4/IPv6 address
			if err := common.ValidateIP(ip); err != nil {
				return err
			}

			// 从动态黑名单删除
			// Delete from dynamic blacklist
			if err := s.Blacklist.RemoveDynamic(ip); err != nil {
				return fmt.Errorf("[ERROR] Failed to delete from dynamic blacklist: %v", err)
			}

			logger.Get(cmd.Context()).Infof("[OK] Deleted %s from dynamic blacklist", ip)
			return nil
		})
	},
}

// dynamicListCmd 列出动态黑名单命令
// dynamicListCmd list dynamic blacklist command
var dynamicListCmd = &cobra.Command{
	Use:   "list",
	Short: "List dynamic blacklist entries",
	// Short: 列出动态黑名单条目
	Long: `List all entries in dynamic blacklist
列出动态黑名单中的所有条目

Examples:
  netxfw dynamic list
  netxfw dyn list --limit 50`,
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			limit, _ := cmd.Flags().GetInt("limit")
			search, _ := cmd.Flags().GetString("search")

			// 列出动态黑名单
			// List dynamic blacklist
			ips, count, err := s.GetManager().ListDynamicBlacklistIPs(limit, search)
			if err != nil {
				return fmt.Errorf("[ERROR] Failed to list dynamic blacklist: %v", err)
			}

			if count == 0 {
				cmd.Println("[INFO] Dynamic blacklist is empty")
				return nil
			}

			cmd.Printf("[INFO] Dynamic blacklist entries (%d total):\n", count)
			cmd.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

			for _, ip := range ips {
				expiresStr := ""
				if ip.ExpiresAt > 0 {
					expiresAt := time.Unix(0, int64(ip.ExpiresAt))
					expiresStr = fmt.Sprintf(" (expires: %s)", expiresAt.Format("2006-01-02 15:04:05"))
				}
				cmd.Printf("  [BLOCK] %s%s\n", ip.IP, expiresStr)
			}

			return nil
		})
	},
}

func init() {
	// Add subcommands to DynamicCmd
	// 添加子命令到 DynamicCmd
	DynamicCmd.AddCommand(dynamicAddCmd)
	DynamicCmd.AddCommand(dynamicDelCmd)
	DynamicCmd.AddCommand(dynamicListCmd)

	// Register common flags for all subcommands
	// 为所有子命令注册通用标志
	RegisterCommonFlags(dynamicAddCmd)
	RegisterCommonFlags(dynamicDelCmd)
	RegisterCommonFlags(dynamicListCmd)

	// Add specific flags
	// 添加特定标志
	dynamicAddCmd.Flags().StringP("ttl", "t", "", "Time to live (e.g., 1h, 24h, 30m, 1h30m)")
	dynamicListCmd.Flags().IntP("limit", "l", 100, "Maximum number of entries to show")
	dynamicListCmd.Flags().StringP("search", "s", "", "Search filter for IP")
}
