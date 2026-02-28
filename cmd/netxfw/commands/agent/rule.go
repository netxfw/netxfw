package agent

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/binary"
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

			// 使用公共函数解析并验证 IP 输入
			// Use common function to parse and validate IP input
			ip, portVal, err := parseAndValidateIPInput(input)
			if err != nil {
				return fmt.Errorf("[ERROR] %s", err.Error())
			}
			port := int(portVal)

			// 2. Get action from args[1]
			actionStr := args[1]

			// 3. Normalize Action
			isAllow := false
			if actionStr == actionAllow {
				isAllow = true
			} else if actionStr == actionDeny {
				isAllow = false
			} else {
				return fmt.Errorf("[ERROR] invalid action %q, use 'allow' or 'deny'", actionStr)
			}

			// 4. Execute
			if port > 0 {
				var act uint8 = 2
				if isAllow {
					act = 1
				}
				if err := s.Rule.AddIPPortRule(ip, uint16(port), act); err != nil {
					return err
				}
				cmd.Printf("[OK] Rule added: %s:%d (Action: %d)\n", ip, port, act)
			} else {
				if isAllow {
					if err := s.Whitelist.Add(ip, 0); err != nil {
						return err
					}
					s.Blacklist.Remove(ip)
					cmd.Printf("[OK] Added %s to Whitelist\n", ip)
				} else {
					if err := s.Blacklist.Add(ip); err != nil {
						return err
					}
					s.Whitelist.Remove(ip)
					cmd.Printf("[BLOCK] Added %s to Blacklist\n", ip)
				}
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
	// Short: 删除规则
	Long: `Delete a rule for an IP or IP+Port combination
删除 IP 或 IP+端口组合的规则

Aliases: delete, remove
别名：delete, remove`,
	Aliases: []string{"delete", "remove"},
	Args:    cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			input := args[0]

			// 使用公共函数解析并验证 IP 输入
			// Use common function to parse and validate IP input
			ip, portVal, err := parseAndValidateIPInput(input)
			if err != nil {
				return fmt.Errorf("[ERROR] %s", err.Error())
			}
			port := int(portVal)

			// Check second arg for port if not found yet
			// 如果未找到端口，检查第二个参数
			if len(args) > 1 && port == 0 {
				if p, parseErr := strconv.Atoi(args[1]); parseErr == nil {
					// 验证端口范围
					// Validate port range
					if p < 0 || p > 65535 {
						return fmt.Errorf("[ERROR] Port must be between 0-65535, got %d", p)
					}
					port = p
				}
			}

			// 验证端口范围：0 表示未指定端口，有效范围 0-65535
			// Validate port range: 0 means no port specified, valid range 0-65535
			if err := common.ValidatePort(port); err != nil {
				return err
			}

			if port > 0 {
				if err := s.Rule.RemoveIPPortRule(ip, uint16(port)); err != nil {
					return fmt.Errorf("[ERROR] Failed to delete IP+Port rule: %v", err)
				}
				cmd.Printf("[OK] Deleted rule: %s:%d\n", ip, port)
			} else {
				removed := false
				if err := s.Blacklist.Remove(ip); err == nil {
					cmd.Printf("[OK] Deleted %s from Blacklist\n", ip)
					removed = true
				}
				if err := s.Whitelist.Remove(ip); err == nil {
					cmd.Printf("[OK] Deleted %s from Whitelist\n", ip)
					removed = true
				}
				if !removed {
					return fmt.Errorf("[ERROR] IP not found in any list: %s", ip)
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

				case "port":
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

				case "rules":
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
  - JSON format: Auto-detected from .json extension, compatible with 'rule export' output
  - YAML format: Auto-detected from .yaml/.yml extension, compatible with 'rule export' output
  - Binary format (.bin.zst): Compressed binary format for blacklist entries

Examples:
  netxfw rule import deny blacklist.txt        # Text format: one IP per line
  netxfw rule import allow whitelist.txt       # Text format: one IP per line
  netxfw rule import rules ipport.txt          # Text format: IP:Port:Action per line
  netxfw rule import all rules.json            # JSON format: import all rule types
  netxfw rule import all rules.yaml            # YAML format: import all rule types
  netxfw rule import binary rules.deny.bin.zst # Binary format: compressed blacklist`,
	// Long: 从文件导入规则。支持多种格式：
	//   - 文本格式（默认）：lock/allow 每行一个 IP，rules 每行 IP:Port:Action
	//   - JSON 格式：从 .json 扩展名自动检测，与 'rule export' 输出兼容
	//   - YAML 格式：从 .yaml/.yml 扩展名自动检测，与 'rule export' 输出兼容
	//   - 二进制格式 (.bin.zst)：黑名单条目的压缩二进制格式
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			ruleType := args[0]
			filePath := args[1]

			// Auto-detect format from file extension
			lowerPath := strings.ToLower(filePath)
			isJSON := strings.HasSuffix(lowerPath, ".json")
			isYAML := strings.HasSuffix(lowerPath, ".yaml") || strings.HasSuffix(lowerPath, ".yml")
			isBinary := strings.HasSuffix(lowerPath, ".bin.zst")

			if isJSON || isYAML {
				if ruleType != "all" {
					return fmt.Errorf("[ERROR] For JSON/YAML imports, use: netxfw rule import all <file>")
				}
				return importFromStructuredFile(s, filePath, isJSON)
			}

			if isBinary {
				if ruleType != "binary" {
					return fmt.Errorf("[ERROR] For binary imports, use: netxfw rule import binary <file>")
				}
				return importFromBinaryFile(s, filePath)
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
				return fmt.Errorf("[ERROR] Unknown rule type. Use: lock (or deny), allow, rules, binary, or all (for JSON/YAML)")
			}
		})
	},
}

// importFromStructuredFile imports rules from JSON or YAML file.
// importFromStructuredFile 从 JSON 或 YAML 文件导入规则。
func importFromStructuredFile(s *sdk.SDK, filePath string, isJSON bool) error {
	// 验证文件路径和大小
	// Validate file path and size
	safePath, err := common.ValidateImportFile(filePath)
	if err != nil {
		return err
	}

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
		// 验证 IP 格式
		// Validate IP format
		if err := common.ValidateIP(rule.IP); err != nil {
			fmt.Printf("[WARN]  Invalid IP in blacklist: %s: %v\n", rule.IP, err)
			failedBlacklist++
			continue
		}
		if err := s.Blacklist.Add(rule.IP); err != nil {
			fmt.Printf("[WARN]  Failed to add blacklist %s: %v\n", rule.IP, err)
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
		// 验证 IP 格式
		// Validate IP format
		if err := common.ValidateIP(rule.IP); err != nil {
			fmt.Printf("[WARN]  Invalid IP in whitelist: %s: %v\n", rule.IP, err)
			failedWhitelist++
			continue
		}
		// 验证端口范围
		// Validate port range
		if rule.Port < 0 || rule.Port > 65535 {
			fmt.Printf("[WARN]  Invalid port in whitelist: %s:%d (must be 0-65535)\n", rule.IP, rule.Port)
			failedWhitelist++
			continue
		}
		var port uint16
		if rule.Port > 0 {
			port = uint16(rule.Port) // #nosec G115 // port is always 0-65535
		}
		if err := s.Whitelist.Add(rule.IP, port); err != nil {
			fmt.Printf("[WARN]  Failed to add whitelist %s: %v\n", rule.IP, err)
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
		// 验证 IP 格式
		// Validate IP format
		if err := common.ValidateIP(rule.IP); err != nil {
			fmt.Printf("[WARN]  Invalid IP in IP+Port rule: %s: %v\n", rule.IP, err)
			failedIPPort++
			continue
		}
		// 验证端口范围
		// Validate port range
		if rule.Port < 1 || rule.Port > 65535 {
			fmt.Printf("[WARN]  Invalid port in IP+Port rule: %s:%d (must be 1-65535)\n", rule.IP, rule.Port)
			failedIPPort++
			continue
		}
		action := uint8(2) // Deny default
		if rule.Action == actionAllow {
			action = 1
		}
		if err := s.Rule.AddIPPortRule(rule.IP, uint16(rule.Port), action); err != nil { // #nosec G115 // port is always 0-65535
			fmt.Printf("[WARN]  Failed to add IP+Port rule %s:%d: %v\n", rule.IP, rule.Port, err)
			failedIPPort++
		} else {
			addedIPPort++
		}
	}

	// Print summary
	// 打印摘要
	fmt.Println("[OK] Import completed:")
	fmt.Printf("   Blacklist: %d added, %d failed\n", addedBlacklist, failedBlacklist)
	fmt.Printf("   Whitelist: %d added, %d failed\n", addedWhitelist, failedWhitelist)
	fmt.Printf("   IP+Port:   %d added, %d failed\n", addedIPPort, failedIPPort)

	return nil
}

// importFromBinaryFile imports blacklist entries from a binary file.
// importFromBinaryFile 从二进制文件导入黑名单条目。
func importFromBinaryFile(s *sdk.SDK, filePath string) error {
	// 验证文件路径和大小
	// Validate file path and size
	safePath, err := common.ValidateImportFile(filePath)
	if err != nil {
		return err
	}

	file, err := os.Open(safePath)
	if err != nil {
		return fmt.Errorf("failed to open binary file: %v", err)
	}
	defer file.Close()

	// Create zstd decoder
	// 创建 zstd 解码器
	decoder, err := zstd.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create zstd decoder: %v", err)
	}
	defer decoder.Close()

	// Decode binary records
	// 解码二进制记录
	records, err := binary.Decode(decoder)
	if err != nil {
		return fmt.Errorf("failed to decode binary file: %v", err)
	}

	var added, failed int

	// Import each record
	// 导入每条记录
	for _, record := range records {
		// Construct CIDR notation using IP and PrefixLen
		// 使用 IP 和 PrefixLen 构建 CIDR 表示法
		var ipStr string
		if record.IsIPv6 {
			// For IPv6, construct /128 CIDR for single IP or specific prefix
			// 对于 IPv6，为单个 IP 构建 /128 CIDR 或特定前缀
			ipStr = fmt.Sprintf("%s/%d", record.IP.String(), record.PrefixLen)
		} else {
			// For IPv4, construct /32 CIDR for single IP or specific prefix
			// 对于 IPv4，为单个 IP 构建 /32 CIDR 或特定前缀
			ipStr = fmt.Sprintf("%s/%d", record.IP.String(), record.PrefixLen)
		}

		if err := s.Blacklist.Add(ipStr); err != nil {
			fmt.Printf("[WARN]  Failed to add %s: %v\n", ipStr, err)
			failed++
		} else {
			fmt.Printf("[OK] Added %s to blacklist\n", ipStr)
			added++
		}
	}

	// Print summary
	// 打印摘要
	fmt.Println("[OK] Binary import completed:")
	fmt.Printf("   Blacklist: %d added, %d failed\n", added, failed)

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
			logger.Get(cmd.Context()).Infof("[OK] Blacklist cleared")
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

// collectExportData 收集所有规则用于导出
// collectExportData collects all rules for export
func collectExportData(s *sdk.SDK) (ExportData, error) {
	exportData := ExportData{}

	// Get blacklist / 获取黑名单
	blacklist, _, err := s.Blacklist.List(100000, "")
	if err != nil {
		return exportData, fmt.Errorf("failed to get blacklist: %w", err)
	}
	for _, entry := range blacklist {
		exportData.Blacklist = append(exportData.Blacklist, ExportRule{
			Type: "blacklist",
			IP:   entry.IP,
		})
	}

	// Get whitelist / 获取白名单
	whitelist, _, err := s.Whitelist.List(100000, "")
	if err != nil {
		return exportData, fmt.Errorf("failed to get whitelist: %w", err)
	}
	for _, ip := range whitelist {
		exportData.Whitelist = append(exportData.Whitelist, ExportRule{
			Type: "whitelist",
			IP:   ip,
		})
	}

	// Get IP+Port rules / 获取 IP+端口规则
	ipportRules, _, err := s.Rule.ListIPPortRules(100000, "")
	if err != nil {
		return exportData, fmt.Errorf("failed to get IP+Port rules: %w", err)
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

	return exportData, nil
}

var ruleExportCmd = &cobra.Command{
	Use:   "export <file> [--format json|yaml|csv|binary]",
	Short: "Export rules to file",
	// Short: 导出规则到文件
	Long: `Export all firewall rules to a file in JSON, YAML, CSV, or binary format.
Examples:
  netxfw rule export rules.json
  netxfw rule export rules.yaml --format yaml
  netxfw rule export rules.csv --format csv
  netxfw rule export rules.deny.bin.zst --format binary`,
	// Long: 将所有防火墙规则导出为 JSON、YAML、CSV 或二进制格式的文件。
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
				} else if strings.HasSuffix(strings.ToLower(filePath), ".bin.zst") {
					format = "binary"
				} else {
					format = "json" // default
				}
			}

			// Export based on format
			switch format {
			case "binary":
				return exportToBinaryFile(s, filePath)
			case "yaml":
				return exportToStructuredFile(s, filePath, "yaml")
			case "csv":
				return exportToCSVFile(s, filePath)
			default: // json
				return exportToStructuredFile(s, filePath, "json")
			}
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

// exportToStructuredFile exports rules to structured format (JSON or YAML).
// exportToStructuredFile 将规则导出为结构化格式（JSON 或 YAML）。
func exportToStructuredFile(s *sdk.SDK, filePath, format string) error {
	// Collect all rules using common function
	// 使用公共函数收集所有规则
	exportData, err := collectExportData(s)
	if err != nil {
		return err
	}

	// Export based on format
	var data []byte
	var errMarshal error
	switch format {
	case "yaml":
		data, errMarshal = yaml.Marshal(exportData)
	default: // json
		data, errMarshal = json.MarshalIndent(exportData, "", "  ")
	}
	if errMarshal != nil {
		return fmt.Errorf("failed to marshal export data: %w", errMarshal)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	totalRules := len(exportData.Blacklist) + len(exportData.Whitelist) + len(exportData.IPPort)
	fmt.Printf("[OK] Exported %d rules to %s (format: %s)\n", totalRules, filePath, format)
	fmt.Printf("   Blacklist: %d entries\n", len(exportData.Blacklist))
	fmt.Printf("   Whitelist: %d entries\n", len(exportData.Whitelist))
	fmt.Printf("   IP+Port:   %d entries\n", len(exportData.IPPort))
	return nil
}

// exportToCSVFile exports rules to CSV format.
// exportToCSVFile 将规则导出为 CSV 格式。
func exportToCSVFile(s *sdk.SDK, filePath string) error {
	// Collect all rules using common function
	// 使用公共函数收集所有规则
	exportData, err := collectExportData(s)
	if err != nil {
		return err
	}

	data, err := exportToCSV(exportData)
	if err != nil {
		return fmt.Errorf("failed to generate CSV: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	totalRules := len(exportData.Blacklist) + len(exportData.Whitelist) + len(exportData.IPPort)
	fmt.Printf("[OK] Exported %d rules to %s (format: csv)\n", totalRules, filePath)
	fmt.Printf("   Blacklist: %d entries\n", len(exportData.Blacklist))
	fmt.Printf("   Whitelist: %d entries\n", len(exportData.Whitelist))
	fmt.Printf("   IP+Port:   %d entries\n", len(exportData.IPPort))
	return nil
}

// exportToBinaryFile exports blacklist entries to a binary file.
// exportToBinaryFile 将黑名单条目导出为二进制文件。
func exportToBinaryFile(s *sdk.SDK, filePath string) error {
	// Get blacklist
	// 获取黑名单
	blacklist, _, err := s.Blacklist.List(100000, "")
	if err != nil {
		return fmt.Errorf("failed to get blacklist: %w", err)
	}

	// Convert to binary records
	// 转换为二进制记录
	records := make([]binary.Record, 0, len(blacklist))
	for _, entry := range blacklist {
		// Parse IP, handling CIDR notation (e.g., "10.0.0.0/24" or "10.0.0.0")
		// 解析 IP，处理 CIDR 表示法（例如 "10.0.0.0/24" 或 "10.0.0.0"）
		var ip net.IP
		var prefixLen uint8

		// Check if entry contains CIDR notation
		// 检查条目是否包含 CIDR 表示法
		if strings.Contains(entry.IP, "/") {
			// Parse IP and CIDR separately
			// 分别解析 IP 和 CIDR
			ipStr, cidrNet, err := net.ParseCIDR(entry.IP)
			if err != nil {
				fmt.Printf("[WARN]  Invalid CIDR: %s\n", entry.IP)
				continue
			}
			ip = ipStr
			// Get prefix length from CIDR mask
			// 从 CIDR 掩码获取前缀长度
			ones, _ := cidrNet.Mask.Size()
			prefixLen = uint8(ones)
		} else {
			// Parse simple IP address
			// 解析简单 IP 地址
			ip = net.ParseIP(entry.IP)
			if ip == nil {
				fmt.Printf("[WARN]  Invalid IP: %s\n", entry.IP)
				continue
			}
			// Set default prefix length based on IP version
			// 根据 IP 版本设置默认前缀长度
			if ip.To4() != nil {
				prefixLen = 32
			} else {
				prefixLen = 128
			}
		}

		var isIPv6 bool
		if ip.To4() != nil {
			// IPv4
			// IPv4
			isIPv6 = false
			if prefixLen == 0 {
				prefixLen = 32
			}
		} else {
			// IPv6
			// IPv6
			isIPv6 = true
			if prefixLen == 0 {
				prefixLen = 128
			}
		}

		records = append(records, binary.Record{
			IP:        ip,
			PrefixLen: prefixLen,
			IsIPv6:    isIPv6,
		})
	}

	// Create output file
	// 创建输出文件
	tmpFile, err := os.CreateTemp("", "netxfw-binary-*.bin")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Encode to binary format
	// 编码为二进制格式
	if err := binary.Encode(tmpFile, records); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to encode binary data: %v", err)
	}
	tmpFile.Close()

	// Compress with zstd
	// 使用 zstd 压缩
	zstdCmd := exec.Command("zstd", "-f", "-o", filePath, tmpPath) // #nosec G204 // filePath is validated
	output, err := zstdCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to compress with zstd: %v\nOutput: %s", err, string(output))
	}

	totalRules := len(records)
	fmt.Printf("[OK] Exported %d blacklist entries to %s\n", totalRules, filePath)

	return nil
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

	// Add specific flags
	ruleExportCmd.Flags().StringP("format", "f", "", "Export format: json, yaml, csv (default: auto-detect from file extension)")
}
