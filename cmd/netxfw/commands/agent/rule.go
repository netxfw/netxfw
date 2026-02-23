package agent

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/utils/iputil"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Rule action string constants.
// 规则动作字符串常量。
const (
	actionAllow = "allow"
	actionDeny  = "deny"
	actionBlock = "block"
	actionLock  = "lock"
	actionWhite = "white"
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
		Execute(cmd, args, func(s *sdk.SDK) error {
			if len(args) == 0 {
				return fmt.Errorf("❌ Missing arguments. Usage: netxfw rule add <ip>[:<port>] [allow|deny]")
			}

			input := args[0]
			var ip string
			var port int
			var actionStr string

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

			// 2. Check remaining arguments
			remainingArgs := args[1:]
			if len(remainingArgs) > 0 {
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
			if actionStr == actionAllow {
				isAllow = true
			} else if actionStr == actionDeny {
				isAllow = false
			} else if actionStr != "" {
				return fmt.Errorf("invalid action %q, use 'allow' or 'deny'", actionStr)
			} // else Default action: Deny (Block)

			// 5. Execute
			if port > 0 {
				var act uint8 = 2
				if isAllow {
					act = 1
				}
				if err := s.Rule.AddIPPortRule(ip, uint16(port), act); err != nil {
					return err
				}
				cmd.Printf("✅ Rule added: %s:%d (Action: %d)\n", ip, port, act)
			} else {
				if isAllow {
					if err := s.Whitelist.Add(ip, 0); err != nil {
						return err
					}
					s.Blacklist.Remove(ip)
					cmd.Printf("✅ Added %s to Whitelist\n", ip)
				} else {
					if err := s.Blacklist.Add(ip); err != nil {
						return err
					}
					s.Whitelist.Remove(ip)
					cmd.Printf("🚫 Added %s to Blacklist\n", ip)
				}
			}
			return nil
		})
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
		Execute(cmd, args, func(s *sdk.SDK) error {
			input := args[0]
			var ip string
			var port int

			// 1. Parse IP and Port from input
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
				if err := s.Rule.RemoveIPPortRule(ip, uint16(port)); err != nil {
					cmd.PrintErrln(err)
				} else {
					cmd.Printf("✅ Removed rule: %s:%d\n", ip, port)
				}
			} else {
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
			return nil
		})
	},
}

var ruleListCmd = &cobra.Command{
	Use:   "list [ip|port|lock|allow|rules]",
	Short: "List rules",
	// Short: 列出规则
	Long: `List firewall rules`,
	// Long: 列出防火墙规则
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			ctx := cmd.Context()
			// Handle the new command structure
			if len(args) > 0 {
				firstArg := args[0]
				restArgs := args[1:]

				switch firstArg {
				case "ip":
					limit := 100
					search := ""
					if len(restArgs) > 0 {
						subArg := restArgs[0]
						restArgs = restArgs[1:]

						if len(restArgs) > 0 {
							if l, parseErr := strconv.Atoi(restArgs[0]); parseErr == nil {
								limit = l
								if len(restArgs) > 1 {
									search = restArgs[1]
								}
							} else {
								search = restArgs[0]
							}
						}

						if subArg == actionAllow || subArg == actionWhite {
							cmd.Println("=== Whitelist (IP Rules) ===")
							wl, _, listErr := s.Whitelist.List(limit, search)
							if listErr != nil {
								return listErr
							}
							for _, ip := range wl {
								cmd.Println(ip)
							}
							return nil
						} else if subArg == actionDeny || subArg == actionBlock || subArg == actionLock {
							cmd.Println("=== Blacklist (IP Rules) ===")
							bl, _, listErr := s.Blacklist.List(limit, search)
							if listErr != nil {
								return listErr
							}
							for _, ip := range bl {
								cmd.Println(ip.IP)
							}
							return nil
						}
					}

					// Default to showing both
					cmd.Println("=== Whitelist (IP Rules) ===")
					wl, _, _ := s.Whitelist.List(limit, search)
					for _, ip := range wl {
						cmd.Println(ip)
					}
					cmd.Println("\n=== Blacklist (IP Rules) ===")
					bl, _, _ := s.Blacklist.List(limit, search)
					for _, ip := range bl {
						cmd.Println(ip.IP)
					}
					return nil

				case "port":
					limit := 100
					search := ""
					if len(restArgs) > 0 {
						if l, parseErr := strconv.Atoi(restArgs[0]); parseErr == nil {
							limit = l
							if len(restArgs) > 1 {
								search = restArgs[1]
							}
						} else {
							search = restArgs[0]
						}
					}
					cmd.Println("=== IP+Port Rules ===")
					rules, _, err := s.Rule.ListIPPortRules(limit, search)
					if err != nil {
						return err
					}
					for _, rule := range rules {
						action := actionDeny
						if rule.Action == 1 {
							action = actionAllow
						}
						cmd.Printf("%s:%d (%s)\n", rule.IP, rule.Port, action)
					}
					return nil

				case "whitelist", actionAllow:
					limit := 100
					search := ""
					if len(restArgs) > 0 {
						if l, parseErr := strconv.Atoi(restArgs[0]); parseErr == nil {
							limit = l
							if len(restArgs) > 1 {
								search = restArgs[1]
							}
						} else {
							search = restArgs[0]
						}
					}
					wl, _, err := s.Whitelist.List(limit, search)
					if err != nil {
						return err
					}
					for _, ip := range wl {
						cmd.Println(ip)
					}
					return nil

				case "blacklist", actionLock, actionDeny, actionBlock:
					limit := 100
					search := ""
					if len(restArgs) > 0 {
						if l, parseErr := strconv.Atoi(restArgs[0]); parseErr == nil {
							limit = l
							if len(restArgs) > 1 {
								search = restArgs[1]
							}
						} else {
							search = restArgs[0]
						}
					}
					bl, _, err := s.Blacklist.List(limit, search)
					if err != nil {
						return err
					}
					for _, ip := range bl {
						cmd.Println(ip.IP)
					}
					return nil

				case "rules":
					limit := 100
					search := ""
					if len(restArgs) > 0 {
						if l, parseErr := strconv.Atoi(restArgs[0]); parseErr == nil {
							limit = l
							if len(restArgs) > 1 {
								search = restArgs[1]
							}
						} else {
							search = restArgs[0]
						}
					}
					rules, _, err := s.Rule.ListIPPortRules(limit, search)
					if err != nil {
						return err
					}
					for _, rule := range rules {
						action := actionDeny
						if rule.Action == 1 {
							action = actionAllow
						}
						cmd.Printf("%s:%d (%s)\n", rule.IP, rule.Port, action)
					}
					return nil

				case "conntrack":
					return common.ShowConntrack(ctx, s)
				}
			}

			// Default behavior: show all
			cmd.Println("=== Whitelist (IP Rules) ===")
			if wl, _, err := s.Whitelist.List(100, ""); err == nil {
				for _, ip := range wl {
					cmd.Println(ip)
				}
			}
			cmd.Println("\n=== Blacklist (IP Rules) ===")
			if bl, _, err := s.Blacklist.List(100, ""); err == nil {
				for _, ip := range bl {
					cmd.Println(ip.IP)
				}
			}
			cmd.Println("\n=== IP+Port Rules ===")
			if rules, _, err := s.Rule.ListIPPortRules(100, ""); err == nil {
				for _, rule := range rules {
					action := actionDeny
					if rule.Action == 1 {
						action = actionAllow
					}
					cmd.Printf("%s:%d (%s)\n", rule.IP, rule.Port, action)
				}
			}
			return nil
		})
	},
}

var ruleImportCmd = &cobra.Command{
	Use:   "import [lock|allow|rules] <file>",
	Short: "Import rules from file",
	// Short: 从文件导入规则
	Long: `Import rules from a file. Supports multiple formats:
  - Text format (default): One IP per line for lock/allow, IP:Port:Action for rules
  - JSON format: Auto-detected from .json extension, compatible with 'rule export' output
  - YAML format: Auto-detected from .yaml/.yml extension, compatible with 'rule export' output

Examples:
  netxfw rule import deny blacklist.txt        # Text format: one IP per line
  netxfw rule import allow whitelist.txt       # Text format: one IP per line
  netxfw rule import rules ipport.txt          # Text format: IP:Port:Action per line
  netxfw rule import all rules.json            # JSON format: import all rule types
  netxfw rule import all rules.yaml            # YAML format: import all rule types`,
	// Long: 从文件导入规则。支持多种格式：
	//   - 文本格式（默认）：lock/allow 每行一个 IP，rules 每行 IP:Port:Action
	//   - JSON 格式：从 .json 扩展名自动检测，与 'rule export' 输出兼容
	//   - YAML 格式：从 .yaml/.yml 扩展名自动检测，与 'rule export' 输出兼容
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			ruleType := args[0]
			filePath := args[1]

			// Auto-detect format from file extension
			lowerPath := strings.ToLower(filePath)
			isJSON := strings.HasSuffix(lowerPath, ".json")
			isYAML := strings.HasSuffix(lowerPath, ".yaml") || strings.HasSuffix(lowerPath, ".yml")

			if isJSON || isYAML {
				if ruleType != "all" {
					return fmt.Errorf("❌ For JSON/YAML imports, use: netxfw rule import all <file>")
				}
				return importFromStructuredFile(s, filePath, isJSON)
			}

			// Text format import
			switch ruleType {
			case actionLock, actionDeny:
				return common.ImportLockListFromFile(s, filePath)
			case actionAllow:
				return common.ImportWhitelistFromFile(s, filePath)
			case "rules":
				return common.ImportIPPortRulesFromFile(s, filePath)
			default:
				return fmt.Errorf("❌ Unknown rule type. Use: lock (or deny), allow, rules, or all (for JSON/YAML)")
			}
		})
	},
}

// importFromStructuredFile imports rules from JSON or YAML file.
// importFromStructuredFile 从 JSON 或 YAML 文件导入规则。
func importFromStructuredFile(s *sdk.SDK, filePath string, isJSON bool) error {
	safePath := filepath.Clean(filePath) // Sanitize path to prevent directory traversal
	data, err := os.ReadFile(safePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var importData ExportData
	if isJSON {
		if err := json.Unmarshal(data, &importData); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &importData); err != nil {
			return fmt.Errorf("failed to parse YAML: %w", err)
		}
	}

	var addedBlacklist, addedWhitelist, addedIPPort int
	var failedBlacklist, failedWhitelist, failedIPPort int

	// Import blacklist
	// 导入黑名单
	for _, rule := range importData.Blacklist {
		if rule.IP == "" {
			continue
		}
		if err := s.Blacklist.Add(rule.IP); err != nil {
			fmt.Printf("⚠️  Failed to add blacklist %s: %v\n", rule.IP, err)
			failedBlacklist++
		} else {
			addedBlacklist++
		}
	}

	// Import whitelist
	// 导入白名单
	for _, rule := range importData.Whitelist {
		if rule.IP == "" {
			continue
		}
		var port uint16
		if rule.Port > 0 {
			port = uint16(rule.Port) // #nosec G115 // port is always 0-65535
		}
		if err := s.Whitelist.Add(rule.IP, port); err != nil {
			fmt.Printf("⚠️  Failed to add whitelist %s: %v\n", rule.IP, err)
			failedWhitelist++
		} else {
			addedWhitelist++
		}
	}

	// Import IP+Port rules
	// 导入 IP+端口规则
	for _, rule := range importData.IPPort {
		if rule.IP == "" || rule.Port == 0 {
			continue
		}
		action := uint8(2) // Deny default
		if rule.Action == actionAllow {
			action = 1
		}
		if err := s.Rule.AddIPPortRule(rule.IP, uint16(rule.Port), action); err != nil { // #nosec G115 // port is always 0-65535
			fmt.Printf("⚠️  Failed to add IP+Port rule %s:%d: %v\n", rule.IP, rule.Port, err)
			failedIPPort++
		} else {
			addedIPPort++
		}
	}

	// Print summary
	// 打印摘要
	fmt.Println("✅ Import completed:")
	fmt.Printf("   Blacklist: %d added, %d failed\n", addedBlacklist, failedBlacklist)
	fmt.Printf("   Whitelist: %d added, %d failed\n", addedWhitelist, failedWhitelist)
	fmt.Printf("   IP+Port:   %d added, %d failed\n", addedIPPort, failedIPPort)

	return nil
}

var ruleClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear blacklist",
	// Short: 清空黑名单
	Long: `Clear all entries from blacklist`,
	// Long: 清空黑名单中的所有条目
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			if err := s.Blacklist.Clear(); err != nil {
				return err
			}
			logger.Get(cmd.Context()).Infof("✅ Blacklist cleared")
			return nil
		})
	},
}

// ExportRule represents a single rule for export
// ExportRule 表示导出的单条规则
type ExportRule struct {
	Type   string `json:"type" yaml:"type"`                         // "blacklist", "whitelist", "ipport"
	IP     string `json:"ip" yaml:"ip"`                             // IP address or CIDR
	Port   int    `json:"port,omitempty" yaml:"port,omitempty"`     // Port number (for ipport rules)
	Action string `json:"action,omitempty" yaml:"action,omitempty"` // "allow" or "deny" (for ipport rules)
}

// ExportData represents the complete export structure
// ExportData 表示完整的导出结构
type ExportData struct {
	Blacklist []ExportRule `json:"blacklist" yaml:"blacklist"`
	Whitelist []ExportRule `json:"whitelist" yaml:"whitelist"`
	IPPort    []ExportRule `json:"ipport_rules" yaml:"ipport_rules"`
}

var ruleExportCmd = &cobra.Command{
	Use:   "export <file> [--format json|yaml|csv]",
	Short: "Export rules to file",
	// Short: 导出规则到文件
	Long: `Export all firewall rules to a file in JSON, YAML, or CSV format.
Examples:
  netxfw rule export rules.json
  netxfw rule export rules.yaml --format yaml
  netxfw rule export rules.csv --format csv`,
	// Long: 将所有防火墙规则导出为 JSON、YAML 或 CSV 格式的文件。
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			filePath := args[0]
			format, _ := cmd.Flags().GetString("format")

			// Auto-detect format from file extension if not specified
			if format == "" {
				if strings.HasSuffix(strings.ToLower(filePath), ".json") {
					format = "json"
				} else if strings.HasSuffix(strings.ToLower(filePath), ".yaml") || strings.HasSuffix(strings.ToLower(filePath), ".yml") {
					format = "yaml"
				} else if strings.HasSuffix(strings.ToLower(filePath), ".csv") {
					format = "csv"
				} else {
					format = "json" // default
				}
			}

			// Collect all rules
			exportData := ExportData{}

			// Get blacklist
			blacklist, _, err := s.Blacklist.List(100000, "")
			if err != nil {
				return fmt.Errorf("failed to get blacklist: %w", err)
			}
			for _, entry := range blacklist {
				exportData.Blacklist = append(exportData.Blacklist, ExportRule{
					Type: "blacklist",
					IP:   entry.IP,
				})
			}

			// Get whitelist
			whitelist, _, err := s.Whitelist.List(100000, "")
			if err != nil {
				return fmt.Errorf("failed to get whitelist: %w", err)
			}
			for _, ip := range whitelist {
				exportData.Whitelist = append(exportData.Whitelist, ExportRule{
					Type: "whitelist",
					IP:   ip,
				})
			}

			// Get IP+Port rules
			ipportRules, _, err := s.Rule.ListIPPortRules(100000, "")
			if err != nil {
				return fmt.Errorf("failed to get IP+Port rules: %w", err)
			}
			for _, rule := range ipportRules {
				action := actionDeny
				if rule.Action == 1 {
					action = actionAllow
				}
				exportData.IPPort = append(exportData.IPPort, ExportRule{
					Type:   "ipport",
					IP:     rule.IP,
					Port:   int(rule.Port),
					Action: action,
				})
			}

			// Export based on format
			var data []byte
			switch format {
			case "yaml":
				data, err = yaml.Marshal(exportData)
			case "csv":
				data, err = exportToCSV(exportData)
			default: // json
				data, err = json.MarshalIndent(exportData, "", "  ")
			}
			if err != nil {
				return fmt.Errorf("failed to marshal export data: %w", err)
			}

			// Write to file
			if err := os.WriteFile(filePath, data, 0600); err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}

			totalRules := len(exportData.Blacklist) + len(exportData.Whitelist) + len(exportData.IPPort)
			cmd.Printf("✅ Exported %d rules to %s (format: %s)\n", totalRules, filePath, format)
			cmd.Printf("   Blacklist: %d entries\n", len(exportData.Blacklist))
			cmd.Printf("   Whitelist: %d entries\n", len(exportData.Whitelist))
			cmd.Printf("   IP+Port:   %d entries\n", len(exportData.IPPort))
			return nil
		})
	},
}

// exportToCSV exports rules to CSV format
// exportToCSV 将规则导出为 CSV 格式
func exportToCSV(data ExportData) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	// 写入表头
	if err := writer.Write([]string{"type", "ip", "port", "action"}); err != nil {
		return nil, err
	}

	// Write blacklist
	// 写入黑名单
	for _, rule := range data.Blacklist {
		if err := writer.Write([]string{rule.Type, rule.IP, "", ""}); err != nil {
			return nil, err
		}
	}

	// Write whitelist
	// 写入白名单
	for _, rule := range data.Whitelist {
		if err := writer.Write([]string{rule.Type, rule.IP, "", ""}); err != nil {
			return nil, err
		}
	}

	// Write IP+Port rules
	// 写入 IP+端口规则
	for _, rule := range data.IPPort {
		if err := writer.Write([]string{rule.Type, rule.IP, strconv.Itoa(rule.Port), rule.Action}); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	return []byte(buf.String()), writer.Error()
}

func init() {
	// Add commands to RuleCmd
	RuleCmd.AddCommand(ruleAddCmd)
	RuleCmd.AddCommand(ruleRemoveCmd)
	RuleCmd.AddCommand(ruleListCmd)
	RuleCmd.AddCommand(ruleImportCmd)
	RuleCmd.AddCommand(ruleExportCmd)
	RuleCmd.AddCommand(ruleClearCmd)

	// Register common flags for all subcommands
	RegisterCommonFlags(ruleAddCmd)
	RegisterCommonFlags(ruleRemoveCmd)
	RegisterCommonFlags(ruleListCmd)
	RegisterCommonFlags(ruleImportCmd)
	RegisterCommonFlags(ruleExportCmd)
	RegisterCommonFlags(ruleClearCmd)

	// Add specific flags
	ruleExportCmd.Flags().StringP("format", "f", "", "Export format: json, yaml, csv (default: auto-detect from file extension)")
}
