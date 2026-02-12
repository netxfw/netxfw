package agent

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
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
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncLockMap == nil {
			cmd.PrintErrln("❌ common.SyncLockMap function not initialized")
			os.Exit(1)
		}
		if common.SyncWhitelistMap == nil {
			cmd.PrintErrln("❌ common.SyncWhitelistMap function not initialized")
			os.Exit(1)
		}
		if common.SyncIPPortRule == nil {
			cmd.PrintErrln("❌ common.SyncIPPortRule function not initialized")
			os.Exit(1)
		}

		common.EnsureStandaloneMode()

		if len(args) == 0 {
			cmd.PrintErrln("❌ Missing arguments. Usage: netxfw rule add <ip>[:<port>] [allow|deny]")
			os.Exit(1)
		}

		input := args[0]
		var ip string
		var port int
		var actionStr string

		// 1. Parse IP and Port from input (e.g., 1.2.3.4:80)
		if strings.Contains(input, ":") && !strings.Contains(input, "]:") && !strings.HasSuffix(input, ":") {
			// Handle IPv4:Port or [IPv6]:Port
			host, portStr, err := net.SplitHostPort(input)
			if err == nil {
				ip = host
				p, err := strconv.Atoi(portStr)
				if err == nil {
					port = p
				}
			} else {
				// Maybe it's just an IPv6 address?
				ip = input
			}
		} else {
			ip = input
		}

		// 2. Check remaining arguments
		remainingArgs := args[1:]
		if len(remainingArgs) > 0 {
			// Check if first remaining arg is a port (if we didn't find one yet)
			if port == 0 {
				if p, err := strconv.Atoi(remainingArgs[0]); err == nil {
					port = p
					remainingArgs = remainingArgs[1:]
				}
			}
		}

		// 3. Check for action in remaining args
		if len(remainingArgs) > 0 {
			actionStr = remainingArgs[0]
		}

		// 4. Normalize Action
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
		if port > 0 {
			// IP + Port Rule
			// Action: 1 = Allow, 2 = Deny
			var act uint8 = 2
			if isAllow {
				act = 1
			}
			common.SyncIPPortRule(ip, uint16(port), act, true)
		} else {
			// IP Only Rule
			if isAllow {
				common.SyncWhitelistMap(ip, 0, true)
				// Ensure it's not locked
				common.SyncLockMap(ip, false)
			} else {
				common.SyncLockMap(ip, true)
				// Ensure it's not whitelisted
				common.SyncWhitelistMap(ip, 0, false)
			}
		}
	},
}

var ruleIPListCmd = &cobra.Command{
	Use:   "list",
	Short: "List IP rules",
	Long:  `List IP-based firewall rules (whitelist and blacklist)`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.ShowWhitelist == nil {
			cmd.PrintErrln("❌ common.ShowWhitelist function not initialized")
			os.Exit(1)
		}
		if common.ShowLockList == nil {
			cmd.PrintErrln("❌ common.ShowLockList function not initialized")
			os.Exit(1)
		}

		limit := 100
		search := ""

		if len(args) > 0 {
			if l, err := strconv.Atoi(args[0]); err == nil {
				limit = l
				if len(args) > 1 {
					search = args[1]
				}
			} else {
				search = args[0]
			}
		}

		fmt.Println("=== Whitelist (IP Rules) ===")
		common.ShowWhitelist(limit, search)
		fmt.Println("\n=== Blacklist (IP Rules) ===")
		common.ShowLockList(limit, search)
	},
}

var rulePortListCmd = &cobra.Command{
	Use:   "list",
	Short: "List port rules",
	Long:  `List port-based firewall rules`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.ShowIPPortRules == nil {
			cmd.PrintErrln("❌ common.ShowIPPortRules function not initialized")
			os.Exit(1)
		}

		limit := 100
		search := ""

		if len(args) > 0 {
			if l, err := strconv.Atoi(args[0]); err == nil {
				limit = l
				if len(args) > 1 {
					search = args[1]
				}
			} else {
				search = args[0]
			}
		}

		fmt.Println("=== IP+Port Rules ===")
		common.ShowIPPortRules(limit, search)
	},
}

var ruleRemoveCmd = &cobra.Command{
	Use:   "remove [flags] <ip> [port|allow|deny]",
	Short: "Remove a rule",
	Long:  `Remove a rule for an IP or IP+Port combination`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncLockMap == nil {
			cmd.PrintErrln("❌ common.SyncLockMap function not initialized")
			os.Exit(1)
		}
		if common.SyncWhitelistMap == nil {
			cmd.PrintErrln("❌ common.SyncWhitelistMap function not initialized")
			os.Exit(1)
		}
		if common.SyncIPPortRule == nil {
			cmd.PrintErrln("❌ common.SyncIPPortRule function not initialized")
			os.Exit(1)
		}

		common.EnsureStandaloneMode()

		input := args[0]
		var ip string
		var port int

		// 1. Parse IP and Port from input (e.g., 1.2.3.4:80)
		if strings.Contains(input, ":") && !strings.Contains(input, "]:") && !strings.HasSuffix(input, ":") {
			// Handle IPv4:Port or [IPv6]:Port
			host, portStr, err := net.SplitHostPort(input)
			if err == nil {
				ip = host
				p, err := strconv.Atoi(portStr)
				if err == nil {
					port = p
				}
			} else {
				// Maybe it's just an IPv6 address?
				ip = input
			}
		} else {
			ip = input
		}

		// Check second arg for port if not found yet
		if len(args) > 1 && port == 0 {
			if p, err := strconv.Atoi(args[1]); err == nil {
				port = p
			}
		}

		if port > 0 {
			common.SyncIPPortRule(ip, uint16(port), 0, false)
		} else {
			// Try to remove from both if port is not specified
			common.SyncLockMap(ip, false)
			common.SyncWhitelistMap(ip, 0, false)
		}
	},
}

var ruleListCmd = &cobra.Command{
	Use:   "list [ip|port|lock|allow|rules]",
	Short: "List rules",
	Long:  `List firewall rules`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.ShowIPPortRules == nil {
			cmd.PrintErrln("❌ common.ShowIPPortRules function not initialized")
			os.Exit(1)
		}
		if common.ShowWhitelist == nil {
			cmd.PrintErrln("❌ common.ShowWhitelist function not initialized")
			os.Exit(1)
		}
		if common.ShowLockList == nil {
			cmd.PrintErrln("❌ common.ShowLockList function not initialized")
			os.Exit(1)
		}
		if common.ShowConntrack == nil {
			cmd.PrintErrln("❌ common.ShowConntrack function not initialized")
			os.Exit(1)
		}

		// Handle the new command structure
		if len(args) > 0 {
			firstArg := args[0]
			args = args[1:] // consume the argument

			switch firstArg {
			case "ip":
				// Handle rule list ip [allow|white|deny|block|lock]
				limit := 100
				search := ""

				if len(args) > 0 {
					subArg := args[0]
					args = args[1:]

					if len(args) > 0 {
						if l, err := strconv.Atoi(args[0]); err == nil {
							limit = l
							if len(args) > 1 {
								search = args[1]
							}
						} else {
							search = args[0]
						}
					}

					if subArg == "allow" || subArg == "white" {
						fmt.Println("=== Whitelist (IP Rules) ===")
						common.ShowWhitelist(limit, search)
						return
					} else if subArg == "deny" || subArg == "block" || subArg == "lock" {
						fmt.Println("=== Blacklist (IP Rules) ===")
						common.ShowLockList(limit, search)
						return
					}
				}

				// Default to showing both IP whitelist and blacklist
				fmt.Println("=== Whitelist (IP Rules) ===")
				common.ShowWhitelist(limit, search)
				fmt.Println("\n=== Blacklist (IP Rules) ===")
				common.ShowLockList(limit, search)
				return

			case "port":
				// Handle rule list port [allow|white|deny|block|lock]
				limit := 100
				search := ""

				if len(args) > 0 {
					subArg := args[0]
					args = args[1:]

					if len(args) > 0 {
						if l, err := strconv.Atoi(args[0]); err == nil {
							limit = l
							if len(args) > 1 {
								search = args[1]
							}
						} else {
							search = args[0]
						}
					}

					if subArg == "allow" || subArg == "white" {
						fmt.Println("=== Whitelist (IP+Port Rules) ===")
						common.ShowIPPortRules(limit, search)
						return
					} else if subArg == "deny" || subArg == "block" || subArg == "lock" {
						fmt.Println("=== Blacklist (IP+Port Rules) ===")
						common.ShowIPPortRules(limit, search)
						return
					}
				}

				// Default to showing all IP+Port rules
				fmt.Println("=== IP+Port Rules ===")
				common.ShowIPPortRules(limit, search)
				return

			case "whitelist", "allow":
				// Handle original behavior - show whitelist only
				limit := 100
				search := ""

				if len(args) > 0 {
					if l, err := strconv.Atoi(args[0]); err == nil {
						limit = l
						if len(args) > 1 {
							search = args[1]
						}
					} else {
						search = args[0]
					}
				}

				common.ShowWhitelist(limit, search)
				return

			case "blacklist", "lock":
				// Handle original behavior - show lock list only
				limit := 100
				search := ""

				if len(args) > 0 {
					if l, err := strconv.Atoi(args[0]); err == nil {
						limit = l
						if len(args) > 1 {
							search = args[1]
						}
					} else {
						search = args[0]
					}
				}

				common.ShowLockList(limit, search)
				return

			case "rules":
				// Handle original behavior - show IP+Port rules
				limit := 100
				search := ""

				if len(args) > 0 {
					if l, err := strconv.Atoi(args[0]); err == nil {
						limit = l
						if len(args) > 1 {
							search = args[1]
						}
					} else {
						search = args[0]
					}
				}

				common.ShowIPPortRules(limit, search)
				return

			case "conntrack":
				common.ShowConntrack()
				return
			}
		}

		// Default behavior: show all rules (IP whitelist, IP blacklist, and IP+Port rules)
		fmt.Println("=== Whitelist (IP Rules) ===")
		common.ShowWhitelist(100, "")
		fmt.Println("\n=== Blacklist (IP Rules) ===")
		common.ShowLockList(100, "")
		fmt.Println("\n=== IP+Port Rules ===")
		common.ShowIPPortRules(100, "")
	},
}

var ruleImportCmd = &cobra.Command{
	Use:   "import [lock|allow|rules] <file>",
	Short: "Import rules from file",
	Long:  `Import rules from a file`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.ImportLockListFromFile == nil {
			cmd.PrintErrln("❌ common.ImportLockListFromFile function not initialized")
			os.Exit(1)
		}
		if common.ImportWhitelistFromFile == nil {
			cmd.PrintErrln("❌ common.ImportWhitelistFromFile function not initialized")
			os.Exit(1)
		}
		if common.ImportIPPortRulesFromFile == nil {
			cmd.PrintErrln("❌ common.ImportIPPortRulesFromFile function not initialized")
			os.Exit(1)
		}

		common.EnsureStandaloneMode()
		ruleType := args[0]
		filePath := args[1]

		switch ruleType {
		case "lock":
			common.ImportLockListFromFile(filePath)
		case "allow":
			common.ImportWhitelistFromFile(filePath)
		case "rules":
			common.ImportIPPortRulesFromFile(filePath)
		default:
			fmt.Println("❌ Unknown rule type. Use: lock, allow, or rules")
		}
	},
}

var ruleClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear blacklist",
	Long:  `Clear all entries from blacklist`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.ClearBlacklist == nil {
			cmd.PrintErrln("❌ common.ClearBlacklist function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		common.ClearBlacklist()
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
