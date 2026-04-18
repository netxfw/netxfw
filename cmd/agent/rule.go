package agent

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/netxfw/netxfw/cmd/common"
	apprule "github.com/netxfw/netxfw/internal/app/rule"
	"github.com/netxfw/netxfw/internal/config"
	domainrule "github.com/netxfw/netxfw/internal/domain/rule"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

// Rule action string constants.
// 规则动作字符串常量。
const (
	actionAllow = "allow"
	actionDeny  = "deny"
	actionBlock = "block"
	actionLock  = "lock"
	actionWhite = "white"

	// Rule type constants / 规则类型常量
	ruleTypePort   = "port"
	ruleTypeBinary = "binary"
	ruleTypeTOML   = "toml"
	ruleTypeJSON   = "json"
	ruleTypeCSV    = "csv"
	ruleTypeRules  = "rules"
)

var RuleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage firewall rules",
	Long:  `Manage firewall rules (add/remove/list/import/clear)`,
}

var PortCmd = &cobra.Command{
	Use:   "port",
	Short: "Allowed ports management",
	Long:  `Allowed ports management commands`,
}

var portAddCmd = &cobra.Command{
	Use:   "add <port>",
	Short: "Add allowed port",
	Long:  `Add port to global allow list`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			port, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			if err := common.ValidatePortNonZero(port); err != nil {
				return err
			}
			if err := s.Rule.AllowPort(uint16(port)); err != nil {
				return err
			}
			printInfof(cmd, "[OK] Port %d added to allowed list", port)
			return nil
		})
	},
}

var portRemoveCmd = &cobra.Command{
	Use:     "del <port>",
	Aliases: []string{"delete", "remove"},
	Short:   "Remove allowed port",
	Long:    `Remove port from global allow list`,
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			port, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			if err := common.ValidatePortNonZero(port); err != nil {
				return err
			}
			if err := s.Rule.RemoveAllowedPort(uint16(port)); err != nil {
				return err
			}
			printInfof(cmd, "[OK] Port %d removed from allowed list", port)
			return nil
		})
	},
}

var ruleAddCmd = &cobra.Command{
	Use:   "add <ip>[:port] <allow|deny>",
	Short: "Add a rule",
	Long: `Add a rule to allow or deny an IP or IP+Port combination.
支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080
注意：IPv6 地址必须使用方括号包裹，如 [2001:db8::1]:8080
注意：必须指定 allow 或 deny 动作，不能省略
Examples:
  netxfw rule add 1.2.3.4 deny        # Deny IP (added to blacklist)
  netxfw rule add 1.2.3.4 allow       # Allow IP (added to whitelist)
  netxfw rule add 1.2.3.4:80 deny     # Deny Port 80 on IP
  netxfw rule add 1.2.3.4:8080 allow  # Allow Port 8080 on IP`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			input := args[0]
			ip, portVal, err := parseAndValidateIPInput(input)
			if err != nil {
				return fmt.Errorf("[ERROR] %s", err.Error())
			}

			actionStr := args[1]
			var action domainrule.Action
			switch actionStr {
			case actionAllow:
				action = domainrule.ActionAllow
			case actionDeny:
				action = domainrule.ActionDeny
			default:
				return fmt.Errorf("[ERROR] invalid action %q, use 'allow' or 'deny'", actionStr)
			}

			if err := apprule.Add(s, ip, portVal, action); err != nil {
				return err
			}

			if portVal > 0 {
				cmd.Printf("[OK] Rule added: %s:%d (Action: %d)\n", ip, portVal, uint8(action))
				return nil
			}
			if action == domainrule.ActionAllow {
				cmd.Printf("[OK] Added %s to Whitelist\n", ip)
			} else {
				cmd.Printf("[BLOCK] Added %s to Blacklist\n", ip)
			}
			return nil
		})
	},
}

// ruleDelCmd 删除规则命令（del 为主命令，delete 和 remove 为别名）
// ruleDelCmd delete rule command (del is primary, delete and remove are aliases)
var ruleDelCmd = &cobra.Command{
	Use:   "del <ip>[:port]",
	Short: "Delete a rule",
	Long: `Delete a rule for an IP or IP+Port combination
删除 IP 或 IP+端口组合的规则

Aliases: delete, remove
别名：delete, remove`,
	Aliases: []string{"delete", "remove"},
	Args:    cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDKAndConfig(func(cfg *sdk.GlobalConfig, s *sdk.SDK) error {
			input := args[0]

			ip, portVal, err := parseAndValidateIPInput(input)
			if err != nil {
				return fmt.Errorf("[ERROR] %s", err.Error())
			}
			port := portVal

			if len(args) > 1 && port == 0 {
				if p, parseErr := strconv.Atoi(args[1]); parseErr == nil {
					if p < 0 || p > 65535 {
						return fmt.Errorf("[ERROR] Port must be between 0-65535, got %d", p)
					}
					port = uint16(p)
				}
			}

			if validateErr := common.ValidatePort(int(port)); validateErr != nil {
				return validateErr
			}

			removed, err := apprule.Remove(cfg, s, ip, port)
			if err != nil {
				return fmt.Errorf("[ERROR] %v", err)
			}
			if !removed {
				return fmt.Errorf("[ERROR] IP not found in any list: %s", ip)
			}
			if port > 0 {
				cmd.Printf("[OK] Deleted rule: %s:%d\n", ip, port)
			} else {
				cmd.Printf("[OK] Removed %s from configured rule sets\n", ip)
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
					limit, search, err := common.ParseLimitAndSearch(restArgs, 100)
					if err != nil {
						return err
					}

					if len(restArgs) > 0 {
						subArg := restArgs[0]
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

				case ruleTypePort:
					limit, search, err := common.ParseLimitAndSearch(restArgs, 100)
					if err != nil {
						return err
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
					limit, search, err := common.ParseLimitAndSearch(restArgs, 100)
					if err != nil {
						return err
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
					limit, search, err := common.ParseLimitAndSearch(restArgs, 100)
					if err != nil {
						return err
					}
					bl, _, err := s.Blacklist.List(limit, search)
					if err != nil {
						return err
					}
					for _, ip := range bl {
						cmd.Println(ip.IP)
					}
					return nil

				case ruleTypeRules:
					limit, search, err := common.ParseLimitAndSearch(restArgs, 100)
					if err != nil {
						return err
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
	Use:   "import [lock|allow|rules|binary] <file>",
	Short: "Import rules from file",
	// Short: 从文件导入规则
	Long: `Import rules from a file. Supports multiple formats:
  - Text format (default): One IP per line for lock/allow, IP:Port:Action for rules
  - JSON format: Auto-detected from .json extension, accepted by 'rule export' output
  - TOML format: Auto-detected from .toml extension, accepted by 'rule export' output
  - Binary format (.bin.zst): Compressed binary format for blacklist entries

Examples:
  netxfw rule import deny blacklist.txt        # Text format: one IP per line
  netxfw rule import allow whitelist.txt       # Text format: one IP per line
  netxfw rule import rules ipport.txt          # Text format: IP:Port:Action per line
  netxfw rule import all rules.json            # JSON format: import all rule types
  netxfw rule import all rules.toml            # TOML format: import all rule types
  netxfw rule import binary rules.deny.bin.zst # Binary format: compressed blacklist`,
	// Long: 从文件导入规则。支持多种格式：
	//   - 文本格式（默认）：lock/allow 每行一个 IP，rules 每行 IP:Port:Action
	//   - JSON 格式：从 .json 扩展名自动检测，与 'rule export' 输出兼容
	//   - TOML 格式：从 .toml 扩展名自动检测，与 'rule export' 输出兼容
	//   - 二进制格式 (.bin.zst)：黑名单条目的压缩二进制格式
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			ruleType := args[0]
			filePath := args[1]

			// Auto-detect format from file extension
			lowerPath := strings.ToLower(filePath)
			isJSON := strings.HasSuffix(lowerPath, ".json")
			isTOML := strings.HasSuffix(lowerPath, ".toml")
			isBinary := strings.HasSuffix(lowerPath, ".bin.zst")

			w := cmd.OutOrStdout()

			if isJSON || isTOML {
				if ruleType != "all" {
					return fmt.Errorf("[ERROR] For JSON/TOML imports, use: netxfw rule import all <file>")
				}
				return apprule.ImportStructured(w, s, filePath, isJSON)
			}

			if isBinary {
				if ruleType != ruleTypeBinary {
					return fmt.Errorf("[ERROR] For binary imports, use: netxfw rule import binary <file>")
				}
				return apprule.ImportBinary(w, s, filePath)
			}

			// Text format import
			return apprule.ImportText(w, s, ruleType, filePath)
		})
	},
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
			printInfof(cmd, "[OK] Blacklist cleared")
			return nil
		})
	},
}

var ruleExportCmd = &cobra.Command{
	Use:   "export <file> [--format json|toml|csv|binary]",
	Short: "Export rules to file",
	// Short: 导出规则到文件
	Long: `Export all firewall rules to a file in JSON, TOML, CSV, or binary format.
Examples:
  netxfw rule export rules.json
  netxfw rule export rules.toml --format toml
  netxfw rule export rules.csv --format csv
  netxfw rule export rules.deny.bin.zst --format binary`,
	// Long: 将所有防火墙规则导出为 JSON、TOML、CSV 或二进制格式的文件。
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			filePath := args[0]
			format, _ := cmd.Flags().GetString("format")
			w := cmd.OutOrStdout()

			// Auto-detect format from file extension if not specified
			if format == "" {
				if strings.HasSuffix(strings.ToLower(filePath), ".json") {
					format = ruleTypeJSON
				} else if strings.HasSuffix(strings.ToLower(filePath), ".toml") {
					format = ruleTypeTOML
				} else if strings.HasSuffix(strings.ToLower(filePath), ".csv") {
					format = ruleTypeCSV
				} else if strings.HasSuffix(strings.ToLower(filePath), ".bin.zst") {
					format = ruleTypeBinary
				} else {
					format = ruleTypeJSON // default
				}
			}

			// Export based on format
			switch format {
			case ruleTypeBinary:
				return apprule.ExportBinary(w, s, filePath)
			case ruleTypeTOML:
				return apprule.ExportStructured(w, config.DefaultWriteGateway(), s, filePath, "toml")
			case ruleTypeCSV:
				return apprule.ExportCSV(w, config.DefaultWriteGateway(), s, filePath)
			default: // json
				return apprule.ExportStructured(w, config.DefaultWriteGateway(), s, filePath, "json")
			}
		})
	},
}

func init() {
	// Add commands to RuleCmd
	// 添加子命令到 RuleCmd
	RuleCmd.AddCommand(ruleAddCmd)
	RuleCmd.AddCommand(ruleDelCmd)
	RuleCmd.AddCommand(ruleListCmd)
	RuleCmd.AddCommand(ruleImportCmd)
	RuleCmd.AddCommand(ruleExportCmd)
	RuleCmd.AddCommand(ruleClearCmd)

	// Register common flags for all subcommands
	// 为所有子命令注册通用标志
	RegisterCommonFlags(ruleAddCmd)
	RegisterCommonFlags(ruleDelCmd)
	RegisterCommonFlags(ruleListCmd)
	RegisterCommonFlags(ruleImportCmd)
	RegisterCommonFlags(ruleExportCmd)
	RegisterCommonFlags(ruleClearCmd)

	ruleExportCmd.Flags().StringP("format", "f", "", "Export format: json, toml, csv (default: auto-detect from file extension)")

	PortCmd.AddCommand(portAddCmd)
	PortCmd.AddCommand(portRemoveCmd)
	RegisterCommonFlags(portAddCmd)
	RegisterCommonFlags(portRemoveCmd)
}
