package commands

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage firewall rules",
	Long:  `Manage firewall rules (add/remove/list/import/clear)`,
}

var ruleAddCmd = &cobra.Command{
	Use:   "add [flags] <ip> [port] [allow|deny]",
	Short: "Add a rule",
	Long:  `Add a rule to allow or deny an IP or IP+Port combination`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncLockMap == nil {
			cmd.PrintErrln("❌ SyncLockMap function not initialized")
			os.Exit(1)
		}
		if SyncWhitelistMap == nil {
			cmd.PrintErrln("❌ SyncWhitelistMap function not initialized")
			os.Exit(1)
		}
		if SyncIPPortRule == nil {
			cmd.PrintErrln("❌ SyncIPPortRule function not initialized")
			os.Exit(1)
		}

		EnsureStandaloneMode()
		if len(args) < 1 {
			log.Fatal("❌ Missing IP address")
		}
		ip := args[0]
		if len(args) == 1 {
			// Default to deny
			SyncLockMap(ip, true)
		} else if len(args) == 2 {
			// Check if second argument is port or action
			if args[1] == "allow" || args[1] == "deny" {
				if args[1] == "allow" {
					SyncWhitelistMap(ip, 0, true)
				} else {
					SyncLockMap(ip, true)
				}
			} else {
				port, err := strconv.ParseUint(args[1], 10, 16)
				if err != nil {
					log.Fatalf("❌ Invalid port: %v", err)
				}
				SyncWhitelistMap(ip, uint16(port), true)
			}
		} else if len(args) == 3 {
			port, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				log.Fatalf("❌ Invalid port: %v", err)
			}
			actionStr := args[2]
			action := uint8(2) // default deny
			if actionStr == "allow" {
				action = 1
			}
			SyncIPPortRule(ip, uint16(port), action, true)
		}
	},
}

var ruleIPListCmd = &cobra.Command{
	Use:   "list",
	Short: "List IP rules",
	Long:  `List IP-based firewall rules (whitelist and blacklist)`,
	Run: func(cmd *cobra.Command, args []string) {
		if ShowWhitelist == nil {
			cmd.PrintErrln("❌ ShowWhitelist function not initialized")
			os.Exit(1)
		}
		if ShowLockList == nil {
			cmd.PrintErrln("❌ ShowLockList function not initialized")
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
		ShowWhitelist(limit, search)
		fmt.Println("\n=== Blacklist (IP Rules) ===")
		ShowLockList(limit, search)
	},
}

var rulePortListCmd = &cobra.Command{
	Use:   "list",
	Short: "List port rules",
	Long:  `List port-based firewall rules`,
	Run: func(cmd *cobra.Command, args []string) {
		if ShowIPPortRules == nil {
			cmd.PrintErrln("❌ ShowIPPortRules function not initialized")
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
		ShowIPPortRules(limit, search)
	},
}

var ruleRemoveCmd = &cobra.Command{
	Use:   "remove [flags] <ip> [port|allow|deny]",
	Short: "Remove a rule",
	Long:  `Remove a rule for an IP or IP+Port combination`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncLockMap == nil {
			cmd.PrintErrln("❌ SyncLockMap function not initialized")
			os.Exit(1)
		}
		if SyncWhitelistMap == nil {
			cmd.PrintErrln("❌ SyncWhitelistMap function not initialized")
			os.Exit(1)
		}
		if SyncIPPortRule == nil {
			cmd.PrintErrln("❌ SyncIPPortRule function not initialized")
			os.Exit(1)
		}

		EnsureStandaloneMode()

		ip := args[0]
		if len(args) == 1 {
			SyncLockMap(ip, false)
			SyncWhitelistMap(ip, 0, false)
		} else if len(args) == 2 {
			arg2 := args[1]
			if arg2 == "allow" {
				SyncWhitelistMap(ip, 0, false)
			} else if arg2 == "deny" {
				SyncLockMap(ip, false)
			} else {
				port, err := strconv.Atoi(arg2)
				if err != nil {
					log.Fatalf("❌ Invalid port: %v", err)
				}
				SyncIPPortRule(ip, uint16(port), 0, false)
			}
		}
	},
}

var ruleListCmd = &cobra.Command{
	Use:   "list [ip|port|lock|allow|rules]",
	Short: "List rules",
	Long:  `List firewall rules`,
	Run: func(cmd *cobra.Command, args []string) {
		if ShowIPPortRules == nil {
			cmd.PrintErrln("❌ ShowIPPortRules function not initialized")
			os.Exit(1)
		}
		if ShowWhitelist == nil {
			cmd.PrintErrln("❌ ShowWhitelist function not initialized")
			os.Exit(1)
		}
		if ShowLockList == nil {
			cmd.PrintErrln("❌ ShowLockList function not initialized")
			os.Exit(1)
		}
		if ShowConntrack == nil {
			cmd.PrintErrln("❌ ShowConntrack function not initialized")
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
						ShowWhitelist(limit, search)
						return
					} else if subArg == "deny" || subArg == "block" || subArg == "lock" {
						fmt.Println("=== Blacklist (IP Rules) ===")
						ShowLockList(limit, search)
						return
					}
				}

				// Default to showing both IP whitelist and blacklist
				fmt.Println("=== Whitelist (IP Rules) ===")
				ShowWhitelist(limit, search)
				fmt.Println("\n=== Blacklist (IP Rules) ===")
				ShowLockList(limit, search)
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
						ShowIPPortRules(limit, search)
						return
					} else if subArg == "deny" || subArg == "block" || subArg == "lock" {
						fmt.Println("=== Blacklist (IP+Port Rules) ===")
						ShowIPPortRules(limit, search)
						return
					}
				}

				// Default to showing all IP+Port rules
				fmt.Println("=== IP+Port Rules ===")
				ShowIPPortRules(limit, search)
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

				ShowWhitelist(limit, search)
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

				ShowLockList(limit, search)
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

				ShowIPPortRules(limit, search)
				return

			case "conntrack":
				ShowConntrack()
				return
			}
		}

		// Default behavior: show all rules (IP whitelist, IP blacklist, and IP+Port rules)
		fmt.Println("=== Whitelist (IP Rules) ===")
		ShowWhitelist(100, "")
		fmt.Println("\n=== Blacklist (IP Rules) ===")
		ShowLockList(100, "")
		fmt.Println("\n=== IP+Port Rules ===")
		ShowIPPortRules(100, "")
	},
}

var ruleImportCmd = &cobra.Command{
	Use:   "import [lock|allow|rules] <file>",
	Short: "Import rules from file",
	Long:  `Import rules from a file`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if ImportLockListFromFile == nil {
			cmd.PrintErrln("❌ ImportLockListFromFile function not initialized")
			os.Exit(1)
		}
		if ImportWhitelistFromFile == nil {
			cmd.PrintErrln("❌ ImportWhitelistFromFile function not initialized")
			os.Exit(1)
		}
		if ImportIPPortRulesFromFile == nil {
			cmd.PrintErrln("❌ ImportIPPortRulesFromFile function not initialized")
			os.Exit(1)
		}

		EnsureStandaloneMode()
		ruleType := args[0]
		filePath := args[1]

		switch ruleType {
		case "lock":
			ImportLockListFromFile(filePath)
		case "allow":
			ImportWhitelistFromFile(filePath)
		case "rules":
			ImportIPPortRulesFromFile(filePath)
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
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if ClearBlacklist == nil {
			cmd.PrintErrln("❌ ClearBlacklist function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		ClearBlacklist()
	},
}

func init() {
	// Add commands to ruleCmd
	ruleCmd.AddCommand(ruleAddCmd)
	ruleCmd.AddCommand(ruleRemoveCmd)
	ruleCmd.AddCommand(ruleListCmd)
	ruleCmd.AddCommand(ruleImportCmd)
	ruleCmd.AddCommand(ruleClearCmd)

	RootCmd.AddCommand(ruleCmd)
}
