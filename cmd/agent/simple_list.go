package agent

import (
	"fmt"
	"strings"

	"github.com/netxfw/netxfw/cmd/common"
	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var simpleListLimit int
var allowListLimit int
var denyListLimit int

var SimpleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List blocked IPs",
	Long: `List blocked IPs at XDP layer.
列出 XDP 层封禁的 IP。

Use --limit to restrict the number of results (default: 100).
使用 --limit 限制显示数量（默认: 100）。`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		static, _ := cmd.Flags().GetBool("static")
		dynamic, _ := cmd.Flags().GetBool("dynamic")

		limit := simpleListLimit
		if limit <= 0 {
			limit = 100
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			if static {
				ips, total, err := s.GetManager().ListBlacklistIPs(limit, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list blocked IPs: %v", err)
				}
				cmd.Println("=== Static Blocked IPs ===")
				for _, ip := range ips {
					cmd.Printf("%s\n", ip.IP)
				}
				if total > limit {
					cmd.Printf("\n[INFO] Showing %d of %d IPs (use --limit to see more)\n", len(ips), total)
				} else {
					cmd.Printf("\n[INFO] Total: %d IPs\n", total)
				}
			} else if dynamic {
				ips, total, err := s.GetManager().ListDynamicBlacklistIPs(limit, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list blocked IPs: %v", err)
				}
				cmd.Println("=== Dynamic Blocked IPs ===")
				for _, ip := range ips {
					cmd.Printf("%s\n", ip.IP)
				}
				if total > limit {
					cmd.Printf("\n[INFO] Showing %d of %d IPs (use --limit to see more)\n", len(ips), total)
				} else {
					cmd.Printf("\n[INFO] Total: %d IPs\n", total)
				}
			} else {
				staticIPs, staticTotal, err := s.GetManager().ListBlacklistIPs(limit, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list static blocked IPs: %v", err)
				}
				dynamicIPs, dynamicTotal, err := s.GetManager().ListDynamicBlacklistIPs(limit, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list dynamic blocked IPs: %v", err)
				}

				cmd.Println("=== Blocked IPs ===")
				if len(staticIPs) > 0 {
					cmd.Println("--- Static ---")
					for _, ip := range staticIPs {
						cmd.Printf("  %s\n", ip.IP)
					}
				}
				if len(dynamicIPs) > 0 {
					cmd.Println("--- Dynamic ---")
					for _, ip := range dynamicIPs {
						cmd.Printf("  %s (expires: %d)\n", ip.IP, ip.ExpiresAt)
					}
				}

				staticHint := ""
				if staticTotal > limit {
					staticHint = fmt.Sprintf(" (showing %d of %d)", len(staticIPs), staticTotal)
				}
				dynamicHint := ""
				if dynamicTotal > limit {
					dynamicHint = fmt.Sprintf(" (showing %d of %d)", len(dynamicIPs), dynamicTotal)
				}
				cmd.Printf("\n[INFO] Total:%s static,%s dynamic\n", staticHint, dynamicHint)
			}
			return nil
		})
	},
}

var SimpleAllowCmd = &cobra.Command{
	Use:   "allow [ip][:port]",
	Short: "Allow IP at XDP layer",
	Long: `Allow IP at XDP layer (add to whitelist).
支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080

Subcommands:
  allow <ip>         # Add IP to whitelist (backward compatible)
  allow add <ip>     # Add IP to whitelist
  allow list         # List whitelist IPs
  allow port list    # List IP+Port allow rules`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		if args[0] == "list" || args[0] == "add" || args[0] == "port" {
			return fmt.Errorf("subcommand required: use 'netxfw allow %s'", args[0])
		}
		return cobra.MaximumNArgs(2)(cmd, args)
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			return
		}
		runAllowCommand(cmd, args[0])
	},
}

var allowAddCmd = &cobra.Command{
	Use:   "add <ip>[:port]",
	Short: "Add IP to whitelist",
	Long: `Add IP to whitelist.
添加 IP 到白名单。

支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runAllowCommand(cmd, args[0])
	},
}

var allowListCmd = &cobra.Command{
	Use:   "list",
	Short: "List whitelist IPs",
	Long: `List whitelist IPs.
列出白名单 IP。

Use --limit to restrict the number of results (default: 100).
使用 --limit 限制显示数量（默认: 100）。`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")

		limit := allowListLimit
		if limit <= 0 {
			limit = 100
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			ips, total, err := s.Whitelist.List(limit, "")
			if err != nil {
				return fmt.Errorf("[ERROR] Failed to list whitelist: %v", err)
			}

			if len(ips) == 0 {
				cmd.Println("[INFO] Whitelist is empty")
				return nil
			}

			cmd.Println("=== Whitelist IPs ===")
			for _, ip := range ips {
				cmd.Printf("  %s\n", ip)
			}
			if total > limit {
				cmd.Printf("\n[INFO] Showing %d of %d IPs (use --limit to see more)\n", len(ips), total)
			} else {
				cmd.Printf("\n[INFO] Total: %d IPs\n", total)
			}
			return nil
		})
	},
}

var allowPortCmd = &cobra.Command{
	Use:   "port",
	Short: "IP+Port allow rule management",
	Long:  `IP+Port allow rule management commands.\nIP+Port 允许规则管理命令。`,
}

var allowPortListCmd = &cobra.Command{
	Use:   "list",
	Short: "List IP+Port allow rules",
	Long: `List IP+Port allow rules.
列出 IP+Port 允许规则。`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			return listIPPortRulesByAction(cmd, s, 1, "[INFO] No IP+Port allow rules", "=== IP+Port Allow Rules ===")
		})
	},
}

var SimpleDenyCmd = &cobra.Command{
	Use:   "deny [ip][:port]",
	Short: "Deny IP at XDP layer",
	Long: `Deny IP at XDP layer (add to blacklist).
支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080

默认添加到静态黑名单（永久封禁）。
使用 --ttl 参数添加到动态黑名单（临时封禁，自动过期）。

Subcommands:
  deny <ip>          # Add IP to blacklist (backward compatible)
  deny add <ip>      # Add IP to blacklist
  deny list          # List blacklist IPs
  deny port list     # List IP+Port deny rules`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		if args[0] == "list" || args[0] == "add" || args[0] == "port" {
			return fmt.Errorf("subcommand required: use 'netxfw deny %s'", args[0])
		}
		return cobra.MaximumNArgs(2)(cmd, args)
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			return
		}
		runDenyCommand(cmd, args[0])
	},
}

var denyAddCmd = &cobra.Command{
	Use:   "add <ip>[:port]",
	Short: "Add IP to blacklist",
	Long: `Add IP to blacklist.
添加 IP 到黑名单。

支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080
使用 --ttl 参数添加到动态黑名单。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runDenyCommand(cmd, args[0])
	},
}

var denyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List blacklist IPs",
	Long: `List blacklist IPs (both static and dynamic).
列出黑名单 IP（包括静态和动态）。

Use --limit to restrict the number of results (default: 100).
使用 --limit 限制显示数量（默认: 100）。`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		static, _ := cmd.Flags().GetBool("static")
		dynamic, _ := cmd.Flags().GetBool("dynamic")

		limit := denyListLimit
		if limit <= 0 {
			limit = 100
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			if static {
				ips, total, err := s.Blacklist.List(limit, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list blocked IPs: %v", err)
				}
				cmd.Println("=== Static Blacklist ===")
				for _, ip := range ips {
					cmd.Printf("  %s\n", ip.IP)
				}
				if total > limit {
					cmd.Printf("\n[INFO] Showing %d of %d IPs (use --limit to see more)\n", len(ips), total)
				} else {
					cmd.Printf("\n[INFO] Total: %d IPs\n", total)
				}
			} else if dynamic {
				ips, total, err := s.GetManager().ListDynamicBlacklistIPs(limit, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list dynamic blocked IPs: %v", err)
				}
				cmd.Println("=== Dynamic Blacklist ===")
				for _, ip := range ips {
					cmd.Printf("  %s (expires: %d)\n", ip.IP, ip.ExpiresAt)
				}
				if total > limit {
					cmd.Printf("\n[INFO] Showing %d of %d IPs (use --limit to see more)\n", len(ips), total)
				} else {
					cmd.Printf("\n[INFO] Total: %d IPs\n", total)
				}
			} else {
				staticIPs, staticTotal, err := s.Blacklist.List(limit, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list static blocked IPs: %v", err)
				}
				dynamicIPs, dynamicTotal, err := s.GetManager().ListDynamicBlacklistIPs(limit, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list dynamic blocked IPs: %v", err)
				}

				cmd.Println("=== Blacklist ===")
				cmd.Println("--- Static ---")
				for _, ip := range staticIPs {
					cmd.Printf("  %s\n", ip.IP)
				}
				cmd.Println("--- Dynamic ---")
				for _, ip := range dynamicIPs {
					cmd.Printf("  %s (expires: %d)\n", ip.IP, ip.ExpiresAt)
				}

				staticHint := ""
				if staticTotal > limit {
					staticHint = fmt.Sprintf(" (showing %d of %d)", len(staticIPs), staticTotal)
				}
				dynamicHint := ""
				if dynamicTotal > limit {
					dynamicHint = fmt.Sprintf(" (showing %d of %d)", len(dynamicIPs), dynamicTotal)
				}
				cmd.Printf("\n[INFO] Total:%s static,%s dynamic\n", staticHint, dynamicHint)
				if staticTotal > limit || dynamicTotal > limit {
					cmd.Println("[TIP] Use --limit 0 to show all, or --limit N to show N entries")
				}
			}
			return nil
		})
	},
}

var denyPortCmd = &cobra.Command{
	Use:   "port",
	Short: "IP+Port deny rule management",
	Long:  `IP+Port deny rule management commands.\nIP+Port 拒绝规则管理命令。`,
}

var denyPortListCmd = &cobra.Command{
	Use:   "list",
	Short: "List IP+Port deny rules",
	Long: `List IP+Port deny rules.
列出 IP+Port 拒绝规则。`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			return listIPPortRulesByAction(cmd, s, 0, "[INFO] No IP+Port deny rules", "=== IP+Port Deny Rules ===")
		})
	},
}

var SimpleDeleteCmd = &cobra.Command{
	Use:   "delete <ip>[:port]",
	Short: "Delete IP from whitelist or blacklist",
	Long: `Delete IP from whitelist or blacklist at XDP layer.
支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080

此命令会尝试从白名单、黑名单和 IP+Port 规则中删除指定的 IP。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		input := args[0]

		ip, port, err := parseAndValidateIPInput(input)
		if err != nil {
			reportCommandError(cmd, fmt.Errorf("[ERROR] %s", err.Error()))
			return
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			messages := app.DeleteFromAllRuleStores(s, ip, port)
			if len(messages) == 0 {
				cmd.PrintErrln("[WARN]  Rule not found")
				return nil
			}
			for _, msg := range messages {
				cmd.Printf("[OK] %s\n", msg)
			}
			return nil
		})
	},
}

var SimpleUnallowCmd = &cobra.Command{
	Use:   "unallow <ip>",
	Short: "Unallow IP at XDP layer",
	Long: `Unallow IP at XDP layer (remove from whitelist).
在 XDP 层不允许 IP（从白名单移除）。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		ip := args[0]

		if err := common.ValidateIP(ip); err != nil {
			reportCommandError(cmd, err)
			return
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			if err := s.Whitelist.Remove(ip); err != nil {
				return fmt.Errorf("[ERROR] Failed to unallow IP: %v", err)
			}
			executor.PrintSuccess("IP unallowed at XDP layer: " + ip)
			return nil
		})
	},
}

var SimpleBlockCmd = &cobra.Command{
	Use:   "block <ip>",
	Short: "Block IP at XDP layer (legacy, use 'deny')",
	Long: `Block IP at XDP layer (legacy command, use 'deny' instead).
在 XDP 层封禁 IP（旧命令，请使用 'deny'）。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		ip := args[0]

		duration, _ := cmd.Flags().GetString("duration")
		persistFile, _ := cmd.Flags().GetString("file")

		if err := common.ValidateIP(ip); err != nil {
			reportCommandError(cmd, err)
			return
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			if duration != "" {
				dur, err := common.ParseAndValidateTTL(duration)
				if err != nil {
					return err
				}
				if err := s.Blacklist.AddWithDuration(ip, dur); err != nil {
					return fmt.Errorf("[ERROR] Failed to block IP: %v", err)
				}
				executor.PrintSuccess(fmt.Sprintf("IP blocked at XDP layer: %s (duration: %s)", ip, duration))
			} else {
				var err error
				if persistFile != "" {
					err = s.Blacklist.AddWithFile(ip, persistFile)
				} else {
					err = s.Blacklist.Add(ip)
				}
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to block IP: %v", err)
				}
				executor.PrintSuccess("IP blocked at XDP layer: " + ip)
			}
			return nil
		})
	},
}

var SimpleUnblockCmd = &cobra.Command{
	Use:   "unblock <ip>",
	Short: "Unblock IP at XDP layer (legacy, use 'delete')",
	Long: `Unblock IP at XDP layer (legacy command, use 'delete' instead).
在 XDP 层解封 IP（旧命令，请使用 'delete'）。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		ip := args[0]

		if err := common.ValidateIP(ip); err != nil {
			reportCommandError(cmd, err)
			return
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			removed := false

			if err := s.Blacklist.Remove(ip); err == nil {
				executor.PrintSuccess("IP unblocked from static blacklist: " + ip)
				removed = true
			}

			if err := s.Blacklist.RemoveDynamic(ip); err == nil {
				executor.PrintSuccess("IP unblocked from dynamic blacklist: " + ip)
				removed = true
			}

			if !removed {
				cmd.PrintErrln("[WARN]  IP not found in any blacklist")
			}
			return nil
		})
	},
}

var UfwDenyCmd = &cobra.Command{
	Use:   "deny <ip>",
	Short: "Deny IP (alias for 'block')",
	Long:  `Deny an IP address (alias for 'block').`,
	Args:  SimpleBlockCmd.Args,
	Run:   SimpleBlockCmd.Run,
}

var UfwDeleteCmd = &cobra.Command{
	Use:   "delete <ip>",
	Short: "Delete/unblock IP (alias for 'unblock')",
	Long:  `Delete/unblock an IP address (alias for 'unblock').`,
	Args:  SimpleUnblockCmd.Args,
	Run:   SimpleUnblockCmd.Run,
}

func listIPPortRulesByAction(cmd *cobra.Command, s *sdk.SDK, action uint8, emptyMessage string, header string) error {
	rules, _, err := s.GetManager().ListIPPortRules(false, 0, "")
	if err != nil {
		return fmt.Errorf("[ERROR] Failed to list IP+Port rules: %v", err)
	}

	filtered := make([]sdk.IPPortRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Action == action {
			filtered = append(filtered, rule)
		}
	}

	if len(filtered) == 0 {
		cmd.Println(emptyMessage)
		return nil
	}

	cmd.Println(header)
	for _, rule := range filtered {
		cmd.Printf("  %s:%d\n", rule.IP, rule.Port)
	}
	cmd.Printf("\n[INFO] Total: %d rules\n", len(filtered))
	return nil
}

func runAllowCommand(cmd *cobra.Command, input string) {
	configFile, _ := cmd.Flags().GetString("config")

	ip, port, err := parseAndValidateIPInput(input)
	if err != nil {
		reportCommandError(cmd, fmt.Errorf("[ERROR] %s", err.Error()))
		return
	}

	executor := NewCommandExecutor(cmd).WithConfig(configFile)

	executor.ExecuteWithSDK(func(s *sdk.SDK) error {
		if err := app.AddRule(s, ip, port, app.RuleActionAllow); err != nil {
			return fmt.Errorf("[ERROR] Failed to allow IP: %v", err)
		}
		if port > 0 {
			executor.PrintSuccess(fmt.Sprintf("[OK] IP allowed at XDP layer: %s:%d", ip, port))
		} else {
			executor.PrintSuccess("[OK] IP allowed at XDP layer: " + ip)
		}
		return nil
	})
}

func runDenyCommand(cmd *cobra.Command, input string) {
	configFile, _ := cmd.Flags().GetString("config")
	ttlStr, _ := cmd.Flags().GetString("ttl")

	ip, port, err := parseAndValidateIPInput(input)
	if err != nil {
		reportCommandError(cmd, fmt.Errorf("[ERROR] %s", err.Error()))
		return
	}

	executor := NewCommandExecutor(cmd).WithConfig(configFile)

	executor.ExecuteWithSDKAndConfig(func(cfg *sdk.GlobalConfig, s *sdk.SDK) error {
		if port > 0 {
			if ttlStr != "" {
				cmd.PrintErrln("[WARN]  WARNING: TTL parameter is ignored for IP+Port rules")
				cmd.PrintErrln("[WARN]  警告：TTL 参数对 IP+Port 规则无效")
			}
			if err := app.AddRule(s, ip, port, app.RuleActionDeny); err != nil {
				return fmt.Errorf("[ERROR] Failed to add IP+Port deny rule: %v", err)
			}
			executor.PrintSuccess(fmt.Sprintf("[BLOCK] IP+Port deny rule added: %s:%d", ip, port))
			return nil
		}

		if ttlStr != "" {
			duration, err := common.ParseAndValidateTTL(ttlStr)
			if err != nil {
				return err
			}
			if err := s.Blacklist.AddWithDuration(ip, duration); err != nil {
				return fmt.Errorf("[ERROR] Failed to add to dynamic blacklist: %v", err)
			}
			executor.PrintSuccess(fmt.Sprintf("[BLOCK] IP added to dynamic blacklist: %s (TTL: %s)", ip, ttlStr))
		} else {
			persistFile := ""
			if cfg.Base.PersistRules && cfg.Base.LockListFile != "" {
				persistFile = cfg.Base.LockListFile
			}
			if err := s.Blacklist.AddWithFile(ip, persistFile); err != nil {
				return fmt.Errorf("[ERROR] Failed to add to static blacklist: %v", err)
			}
			executor.PrintSuccess("[BLOCK] IP added to static blacklist: " + ip)
		}
		return nil
	})
}

func parseIPInput(input string) (ip string, port uint16, err error) {
	host, pVal, parseErr := app.ParseIPPort(input)
	if parseErr != nil {
		if app.IsValidCIDR(input) {
			return input, 0, nil
		}
		if strings.Contains(input, ":") && !strings.HasPrefix(input, "[") {
			return "", 0, fmt.Errorf("IPv6 地址必须使用方括号包裹，例如: [2001:db8::1]:8080 / IPv6 address must be wrapped in brackets, e.g., [2001:db8::1]:8080")
		}
		return "", 0, fmt.Errorf("无效的输入格式，必须是 <ip>[:port]，例如: 1.2.3.4:8080 或 [2001:db8::1]:8080 / invalid input format, must be <ip>[:port], e.g., 1.2.3.4:8080 or [2001:db8::1]:8080")
	}
	return host, pVal, nil
}

func parseAndValidateIPInput(input string) (string, uint16, error) {
	ip, port, err := parseIPInput(input)
	if err != nil {
		return "", 0, err
	}

	if err := common.ValidateIP(ip); err != nil {
		return "", 0, err
	}

	return ip, port, nil
}

func init() {
	RegisterCommonFlags(SimpleListCmd)
	RegisterCommonFlags(SimpleAllowCmd)
	RegisterCommonFlags(SimpleDenyCmd)
	RegisterCommonFlags(SimpleDeleteCmd)
	RegisterCommonFlags(SimpleUnallowCmd)
	RegisterCommonFlags(SimpleBlockCmd)
	RegisterCommonFlags(SimpleUnblockCmd)
	RegisterCommonFlags(UfwDenyCmd)
	RegisterCommonFlags(UfwDeleteCmd)

	RegisterCommonFlags(allowAddCmd)
	RegisterCommonFlags(allowListCmd)
	RegisterCommonFlags(allowPortCmd)
	RegisterCommonFlags(allowPortListCmd)
	SimpleAllowCmd.AddCommand(allowAddCmd)
	SimpleAllowCmd.AddCommand(allowListCmd)
	allowPortCmd.AddCommand(allowPortListCmd)
	SimpleAllowCmd.AddCommand(allowPortCmd)
	allowListCmd.Flags().IntVarP(&allowListLimit, "limit", "l", 100, "Limit number of results (0 = all)")

	RegisterCommonFlags(denyAddCmd)
	RegisterCommonFlags(denyListCmd)
	RegisterCommonFlags(denyPortCmd)
	RegisterCommonFlags(denyPortListCmd)
	SimpleDenyCmd.AddCommand(denyAddCmd)
	SimpleDenyCmd.AddCommand(denyListCmd)
	denyPortCmd.AddCommand(denyPortListCmd)
	SimpleDenyCmd.AddCommand(denyPortCmd)

	SimpleDenyCmd.Flags().StringP("ttl", "t", "", "Time-to-live for dynamic blacklist (e.g., 1h, 30m, 1d)")
	denyAddCmd.Flags().StringP("ttl", "t", "", "Time-to-live for dynamic blacklist (e.g., 1h, 30m, 1d)")

	denyListCmd.Flags().Bool("static", false, "Show only static blacklist")
	denyListCmd.Flags().Bool("dynamic", false, "Show only dynamic blacklist")
	denyListCmd.Flags().IntVarP(&denyListLimit, "limit", "l", 100, "Limit number of results (0 = all)")

	SimpleListCmd.Flags().Bool("static", false, "Show only static blacklist")
	SimpleListCmd.Flags().Bool("dynamic", false, "Show only dynamic blacklist")
	SimpleListCmd.Flags().IntVarP(&simpleListLimit, "limit", "l", 100, "Limit number of results (0 = all)")

	SimpleBlockCmd.Flags().StringP("duration", "d", "", "Block duration (e.g., 1h, 30m)")
	SimpleBlockCmd.Flags().StringP("file", "f", "", "Persist blocked IPs to file")
}
