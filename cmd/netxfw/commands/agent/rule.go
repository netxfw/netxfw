package agent

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/spf13/cobra"
)

var RuleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage firewall rules",
	Long:  `Manage firewall rules (add/remove/list/import/clear)`,
}

var ruleAddCmd = &cobra.Command{
	Use:   "add <ip>[:port] [allow|deny]",
	Short: "Add a rule",
	Long: `Add a rule to allow or deny an IP or IP+Port combination.
Examples:
  netxfw rule add 1.2.3.4             # Block IP (default)
  netxfw rule add 1.2.3.4 allow       # Allow IP
  netxfw rule add 1.2.3.4:80 deny     # Block Port 80 on IP
  netxfw rule add 1.2.3.4:8080 allow  # Allow Port 8080 on IP`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		if len(args) == 0 {
			cmd.PrintErrln("❌ Missing arguments. Usage: netxfw rule add <ip>[:<port>] [allow|deny]")
			os.Exit(1)
		}

		input := args[0]
		var ip string
		var port int
		var actionStr string

		// 1. Parse IP and Port from input (e.g., 1.2.3.4:80 or [2001:db8::1]:80)
		// 1. 从输入中解析 IP 和端口 (例如：1.2.3.4:80 或 [2001:db8::1]:80)
		host, pVal, err := iputil.ParseIPPort(input)
		if err == nil {
			// Successfully split into Host and Port
			// 成功拆分出主机和端口
			ip = host
			port = int(pVal)
		} else {
			// Could not split (e.g. plain IPv4, plain IPv6, or invalid) / 无法拆分 (例如纯 IPv4, 纯 IPv6 或无效输入)
			// Assume it's just an IP address / 假设它只是一个 IP 地址
			ip = input
			// If input was [IPv6], strip brackets for consistency
			// 如果输入包含 [IPv6]，去掉方括号
			ip = strings.TrimPrefix(ip, "[")
			ip = strings.TrimSuffix(ip, "]")
		}

		// 2. Check remaining arguments
		// 2. 检查剩余参数
		remainingArgs := args[1:]
		if len(remainingArgs) > 0 {
			// Check if first remaining arg is a port (if we didn't find one yet)
			// 如果还没有找到端口，检查剩余参数的第一个是否为端口
			if port == 0 {
				if p, err := strconv.Atoi(remainingArgs[0]); err == nil {
					port = p
					remainingArgs = remainingArgs[1:]
				}
			}
		}

		// 3. Check for action in remaining args
		// 3. 检查剩余参数中的动作
		if len(remainingArgs) > 0 {
			actionStr = remainingArgs[0]
		}

		// 4. Normalize Action
		// 4. 规范化动作
		isAllow := false
		if actionStr == "allow" {
			isAllow = true
		} else if actionStr == "deny" {
			isAllow = false
		} else if actionStr != "" {
			cmd.PrintErrln("❌ Invalid action. Use 'allow' or 'deny'.")
			os.Exit(1)
		} else {
			// Default action: Deny (Block)
			isAllow = false
		}

		// 5. Execute
		// 5. 执行
		if port > 0 {
			// IP + Port Rule
			// Action: 1 = Allow, 2 = Deny
			// IP + 端口规则
			// 动作：1 = 允许，2 = 拒绝
			var act uint8 = 2
			if isAllow {
				act = 1
			}
			// Use SDK for Rule API
			if err := s.Rule.AddIPPortRule(ip, uint16(port), act); err != nil {
				cmd.PrintErrln(err)
				os.Exit(1)
			}
			cmd.Printf("✅ Rule added: %s:%d (Action: %d)\n", ip, port, act)
		} else {
			// IP Only Rule
			if isAllow {
				// Use SDK for Whitelist
				if err := s.Whitelist.Add(ip, 0); err != nil {
					cmd.PrintErrln(err)
					os.Exit(1)
				}
				// Ensure it's not locked
				s.Blacklist.Remove(ip)
				cmd.Printf("✅ Added %s to Whitelist\n", ip)
			} else {
				// Use SDK for Blacklist
				if err := s.Blacklist.Add(ip); err != nil {
					cmd.PrintErrln(err)
					os.Exit(1)
				}
				// Ensure it's not whitelisted
				s.Whitelist.Remove(ip)
				cmd.Printf("🚫 Added %s to Blacklist\n", ip)
			}
		}
	},
}

var ruleIPListCmd = &cobra.Command{
	Use:   "list",
	Short: "List IP rules",
	// Short: 列出 IP 规则
	Long: `List IP-based firewall rules (whitelist and blacklist)`,
	// Long: 列出基于 IP 的防火墙规则（白名单和黑名单）
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

		cmd.Println("=== Whitelist (IP Rules) ===")
		// SDK List Whitelist
		wl, _, err := s.Whitelist.List(limit, search)
		if err != nil {
			cmd.PrintErrln(err)
		}
		for _, ip := range wl {
			cmd.Println(ip)
		}

		cmd.Println("\n=== Blacklist (IP Rules) ===")
		// SDK List Blacklist
		bl, _, err := s.Blacklist.List(limit, search)
		if err != nil {
			cmd.PrintErrln(err)
		}
		for _, ip := range bl {
			cmd.Println(ip.IP)
		}
	},
}

var rulePortListCmd = &cobra.Command{
	Use:   "list",
	Short: "List port rules",
	// Short: 列出端口规则
	Long: `List port-based firewall rules`,
	// Long: 列出基于端口的防火墙规则
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

		fmt.Println("=== IP+Port Rules ===")
		rules, _, err := s.Rule.ListIPPortRules(limit, search)
		if err != nil {
			cmd.PrintErrln(err)
		}
		for _, rule := range rules {
			action := "deny"
			if rule.Action == 1 {
				action = "allow"
			}
			fmt.Printf("%s:%d (%s)\n", rule.IP, rule.Port, action)
		}
	},
}

var ruleRemoveCmd = &cobra.Command{
	Use:   "remove [flags] <ip> [port|allow|deny]",
	Short: "Remove a rule",
	// Short: 移除规则
	Long: `Remove a rule for an IP or IP+Port combination`,
	// Long: 移除 IP 或 IP+端口组合的规则
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		input := args[0]
		var ip string
		var port int

		// 1. Parse IP and Port from input (e.g., 1.2.3.4:80 or [2001:db8::1]:80)
		host, pVal, err := iputil.ParseIPPort(input)
		if err == nil {
			ip = host
			port = int(pVal)
		} else {
			ip = input
			ip = strings.TrimPrefix(ip, "[")
			ip = strings.TrimSuffix(ip, "]")
		}

		// Check second arg for port if not found yet
		if len(args) > 1 && port == 0 {
			if p, err := strconv.Atoi(args[1]); err == nil {
				port = p
			}
		}

		if port > 0 {
			// Remove IP+Port Rule
			if err := s.Rule.RemoveIPPortRule(ip, uint16(port)); err != nil {
				cmd.PrintErrln(err)
			} else {
				cmd.Printf("✅ Removed rule: %s:%d\n", ip, port)
			}
		} else {
			// Try to remove from both if port is not specified
			removed := false
			if err := s.Blacklist.Remove(ip); err == nil {
				cmd.Printf("✅ Removed %s from Blacklist\n", ip)
				removed = true
			}
			if err := s.Whitelist.Remove(ip); err == nil {
				cmd.Printf("✅ Removed %s from Whitelist\n", ip)
				removed = true
			}
			if !removed {
				cmd.PrintErrln("⚠️  Failed to remove (or not found in either list)")
			}
		}
	},
}

var ruleListCmd = &cobra.Command{
	Use:   "list [ip|port|lock|allow|rules]",
	Short: "List rules",
	// Short: 列出规则
	Long: `List firewall rules`,
	// Long: 列出防火墙规则
	Run: func(cmd *cobra.Command, args []string) {
		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		ctx := cmd.Context()

		// Handle the new command structure
		// 处理新的命令结构
		if len(args) > 0 {
			firstArg := args[0]
			args = args[1:] // consume the argument

			switch firstArg {
			case "ip":
				// Handle rule list ip [allow|white|deny|block|lock]
				// 处理 rule list ip [allow|white|deny|block|lock]
				limit := 100
				search := ""

				if len(args) > 0 {
					subArg := args[0]
					args = args[1:]

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

					if subArg == "allow" || subArg == "white" {
						cmd.Println("=== Whitelist (IP Rules) ===")
						wl, _, listErr := s.Whitelist.List(limit, search)
						if listErr != nil {
							cmd.PrintErrln(listErr)
						}
						for _, ip := range wl {
							cmd.Println(ip)
						}
						return
					} else if subArg == "deny" || subArg == "block" || subArg == "lock" {
						cmd.Println("=== Blacklist (IP Rules) ===")
						bl, _, listErr := s.Blacklist.List(limit, search)
						if listErr != nil {
							cmd.PrintErrln(listErr)
						}
						for _, ip := range bl {
							cmd.Println(ip.IP)
						}
						return
					}
				}

				// Default to showing both IP whitelist and blacklist
				// 默认显示 IP 白名单和黑名单
				cmd.Println("=== Whitelist (IP Rules) ===")
				wl, _, listErr := s.Whitelist.List(limit, search)
				if listErr != nil {
					cmd.PrintErrln(listErr)
				}
				for _, ip := range wl {
					cmd.Println(ip)
				}
				cmd.Println("\n=== Blacklist (IP Rules) ===")
				bl, _, listErr := s.Blacklist.List(limit, search)
				if listErr != nil {
					cmd.PrintErrln(listErr)
				}
				for _, ip := range bl {
					cmd.Println(ip.IP)
				}
				return

			case "port":
				// Handle rule list port [allow|white|deny|block|lock]
				// 处理 rule list port [allow|white|deny|block|lock]
				limit := 100
				search := ""

				if len(args) > 0 {
					args = args[1:]

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

					// We only have one list for IP+Port rules, filter by action manually if needed
					// But ListIPPortRules returns both.
					// We will just list all for now, filtering display if needed is complex here without more logic.
					// Simplified: Just list all.
				}

				// Default to showing all IP+Port rules
				// 默认显示所有 IP+Port 规则
				cmd.Println("=== IP+Port Rules ===")
				rules, _, listErr := s.Rule.ListIPPortRules(limit, search)
				if listErr != nil {
					cmd.PrintErrln(listErr)
				}
				for _, rule := range rules {
					action := "deny"
					if rule.Action == 1 {
						action = "allow"
					}
					cmd.Printf("%s:%d (%s)\n", rule.IP, rule.Port, action)
				}
				return

			case "whitelist", "allow":
				// Handle original behavior - show whitelist only
				// 处理原始行为 - 仅显示白名单
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

				wl, _, listErr := s.Whitelist.List(limit, search)
				if listErr != nil {
					cmd.PrintErrln(listErr)
				}
				for _, ip := range wl {
					cmd.Println(ip)
				}
				return

			case "blacklist", "lock", "deny", "block":
				// Handle original behavior - show lock list only
				// 处理原始行为 - 仅显示锁定列表
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

				bl, _, listErr := s.Blacklist.List(limit, search)
				if listErr != nil {
					cmd.PrintErrln(listErr)
				}
				for _, ip := range bl {
					cmd.Println(ip.IP)
				}
				return

			case "rules":
				// Handle original behavior - show IP+Port rules
				// 处理原始行为 - 显示 IP+Port 规则
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

				rules, _, listErr := s.Rule.ListIPPortRules(limit, search)
				if listErr != nil {
					cmd.PrintErrln(listErr)
				}
				for _, rule := range rules {
					action := "deny"
					if rule.Action == 1 {
						action = "allow"
					}
					cmd.Printf("%s:%d (%s)\n", rule.IP, rule.Port, action)
				}
				return

			case "conntrack":
				if connErr := common.ShowConntrack(ctx, s); connErr != nil {
					cmd.PrintErrln(connErr)
				}
				return
			}
		}

		// Default behavior: show all rules (IP whitelist, IP blacklist, and IP+Port rules)
		// 默认行为：显示所有规则（IP 白名单，IP 黑名单和 IP+Port 规则）
		cmd.Println("=== Whitelist (IP Rules) ===")
		wl, _, listErr := s.Whitelist.List(100, "")
		if listErr != nil {
			cmd.PrintErrln(listErr)
		}
		for _, ip := range wl {
			cmd.Println(ip)
		}

		cmd.Println("\n=== Blacklist (IP Rules) ===")
		bl, _, listErr := s.Blacklist.List(100, "")
		if listErr != nil {
			cmd.PrintErrln(listErr)
		}
		for _, ip := range bl {
			cmd.Println(ip.IP)
		}

		cmd.Println("\n=== IP+Port Rules ===")
		rules, _, listErr := s.Rule.ListIPPortRules(100, "")
		if listErr != nil {
			cmd.PrintErrln(listErr)
		}
		for _, rule := range rules {
			action := "deny"
			if rule.Action == 1 {
				action = "allow"
			}
			cmd.Printf("%s:%d (%s)\n", rule.IP, rule.Port, action)
		}
	},
}

var ruleImportCmd = &cobra.Command{
	Use:   "import [lock|allow|rules] <file>",
	Short: "Import rules from file",
	// Short: 从文件导入规则
	Long: `Import rules from a file`,
	// Long: 从文件导入规则
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		// Context is still useful if we refactor Import functions to use SDK, or pass SDK to them.
		// For now, let's keep using common helpers but we need to update them or adapt here.
		// Since Import functions in common package use XDPManager, and we have SDK which has Manager.
		// We can get Manager from SDK.

		ruleType := args[0]
		filePath := args[1]

		switch ruleType {
		case "lock", "deny":
			if err := common.ImportLockListFromFile(s, filePath); err != nil {
				cmd.PrintErrln(err)
				os.Exit(1)
			}
		case "allow":
			if err := common.ImportWhitelistFromFile(s, filePath); err != nil {
				cmd.PrintErrln(err)
				os.Exit(1)
			}
		case "rules":
			if err := common.ImportIPPortRulesFromFile(s, filePath); err != nil {
				cmd.PrintErrln(err)
				os.Exit(1)
			}
		default:
			cmd.PrintErrln("❌ Unknown rule type. Use: lock (or deny), allow, or rules")
		}
	},
}

var ruleClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear blacklist",
	// Short: 清空黑名单
	Long: `Clear all entries from blacklist`,
	// Long: 清空黑名单中的所有条目
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		if err := s.Blacklist.Clear(); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		log.Println("✅ Blacklist cleared")
	},
}

func init() {
	// Add commands to ruleCmd
	RuleCmd.AddCommand(ruleAddCmd)
	RuleCmd.AddCommand(ruleRemoveCmd)
	RuleCmd.AddCommand(ruleListCmd)
	RuleCmd.AddCommand(ruleImportCmd)
	RuleCmd.AddCommand(ruleClearCmd)
}
