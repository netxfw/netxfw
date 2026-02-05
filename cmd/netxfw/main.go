package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/livp123/netxfw/internal/version"
)

/**
 * isIPv6 checks if the given IP string (or CIDR) is IPv6.
 * isIPv6 检查给定的 IP 字符串（或 CIDR）是否为 IPv6。
 */
func isIPv6(ipStr string) bool {
	ip, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		ip = net.ParseIP(ipStr)
	}
	return ip != nil && ip.To4() == nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]
	switch command {
	case "help", "-h", "--help":
		printUsage()
	case "version", "-v", "--version":
		showVersion()
	case "init":
		initConfiguration()
	case "test":
		testConfiguration()
	case "sync":
		runSync(os.Args[2:])
	case "daemon":
		runDaemon()
	case "load":
		if len(os.Args) < 3 || os.Args[2] != "xdp" {
			printUsage()
			return
		}
		initConfiguration()
		installXDP()
	case "reload":
		if len(os.Args) < 3 || os.Args[2] != "xdp" {
			printUsage()
			return
		}
		reloadXDP()
	case "unload":
		if len(os.Args) < 3 || os.Args[2] != "xdp" {
			printUsage()
			return
		}
		removeXDP()

	// --- 规则管理 (rule) ---
	case "rule":
		handleRuleCommand(os.Args[2:])

	// --- 插件管理 (plugin) ---
	case "plugin":
		handlePluginCommand(os.Args[2:])

	// --- 端口管理 (port) ---
	case "port":
		handlePortCommand(os.Args[2:])

	// --- 系统管理 (system) ---
	case "system":
		handleSystemCommand(os.Args[2:])

	// --- 安全管理 (security) ---
	case "security":
		handleSecurityCommand(os.Args[2:])

	// --- 限速管理 (limit) ---
	case "limit":
		handleLimitCommand(os.Args[2:])

	// --- Web 管理界面 (web) ---
	case "web":
		handleWebCommand(os.Args[2:])

	// --- 连接追踪 (conntrack) ---
	case "conntrack":
		showConntrack()

	// --- 快捷方式 & 兼容旧命令 ---
	case "lock":
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing IP address")
		}
		syncLockMap(os.Args[2], true)
	case "unlock":
		if len(os.Args) < 3 {
			printUsage()
			return
		}
		syncLockMap(os.Args[2], false)
	case "unallow":
		if len(os.Args) < 3 {
			printUsage()
			return
		}
		syncWhitelistMap(os.Args[2], 0, false)
	case "allow":
		if len(os.Args) < 3 {
			printUsage()
			return
		}
		var port uint16
		if len(os.Args) > 3 {
			p, _ := strconv.ParseUint(os.Args[3], 10, 16)
			port = uint16(p)
		}
		syncWhitelistMap(os.Args[2], port, true)
	case "list":
		handleListCommand(os.Args[2:])
	case "allow-list":
		handleListCommand([]string{"whitelist"})
	case "list-rules":
		showIPPortRules(0, "")
	case "clear":
		clearBlacklist()
	case "import":
		if len(os.Args) < 4 {
			printUsage()
			return
		}
		handleRuleCommand([]string{"import", os.Args[2], os.Args[3]})

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
	}
}

func handleRuleCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ./netxfw rule [add|remove|list|import|clear]")
		return
	}

	switch args[0] {
	case "add":
		// rule add <ip> [port] [allow|deny]
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw rule add <ip> [port] [allow|deny]")
			return
		}
		ip := args[1]
		if len(args) == 2 {
			// 默认封禁
			syncLockMap(ip, true)
		} else if len(args) == 3 {
			// 判断是端口还是动作
			if args[2] == "allow" {
				syncWhitelistMap(ip, 0, true)
			} else if args[2] == "deny" {
				syncLockMap(ip, true)
			} else {
				// 认为是端口，默认允许
				port, _ := strconv.Atoi(args[2])
				syncWhitelistMap(ip, uint16(port), true)
			}
		} else if len(args) == 4 {
			port, _ := strconv.Atoi(args[2])
			actionStr := args[3]
			action := uint8(2) // default deny
			if actionStr == "allow" {
				action = 1
			}
			syncIPPortRule(ip, uint16(port), action, true)
		}

	case "remove":
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw rule remove <ip> [port|allow|deny]")
			return
		}
		ip := args[1]
		if len(args) == 2 {
			syncLockMap(ip, false)
			syncWhitelistMap(ip, 0, false)
		} else if len(args) == 3 {
			arg2 := args[2]
			if arg2 == "allow" {
				syncWhitelistMap(ip, 0, false)
			} else if arg2 == "deny" {
				syncLockMap(ip, false)
			} else {
				port, err := strconv.Atoi(arg2)
				if err == nil {
					syncIPPortRule(ip, uint16(port), 0, false)
				} else {
					fmt.Printf("❌ Invalid port or action: %s\n", arg2)
				}
			}
		}

	case "list":
		handleListCommand(args[1:])

	case "import":
		if len(args) < 3 {
			fmt.Println("Usage: ./netxfw rule import <lock|allow|rules> <file>")
			return
		}
		switch args[1] {
		case "lock":
			importLockListFromFile(args[2])
		case "allow":
			importWhitelistFromFile(args[2])
		case "rules":
			importIPPortRulesFromFile(args[2])
		}

	case "clear":
		clearBlacklist()

	default:
		fmt.Println("Unknown rule subcommand:", args[0])
	}
}

func handlePortCommand(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: ./netxfw port [add|remove] <port>")
		return
	}
	port, _ := strconv.Atoi(args[1])
	switch args[0] {
	case "add":
		syncAllowedPort(uint16(port), true)
	case "remove":
		syncAllowedPort(uint16(port), false)
	default:
		fmt.Println("Unknown port subcommand:", args[0])
	}
}

func handleListCommand(args []string) {
	limit := 100
	search := ""
	isWhitelist := false

	isIPPortRules := false

	if len(args) > 0 && (args[0] == "whitelist" || args[0] == "allow") {
		isWhitelist = true
		args = args[1:]
	} else if len(args) > 0 && (args[0] == "blacklist" || args[0] == "lock") {
		isWhitelist = false
		args = args[1:]
	} else if len(args) > 0 && args[0] == "rules" {
		isIPPortRules = true
		args = args[1:]
	} else if len(args) > 0 && args[0] == "conntrack" {
		showConntrack()
		return
	}

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

	if isIPPortRules {
		showIPPortRules(limit, search)
	} else if isWhitelist {
		showWhitelist(limit, search)
	} else {
		showLockList(limit, search)
	}
}

func handleWebCommand(args []string) {
	port := 11811
	if len(args) > 0 {
		if p, err := strconv.Atoi(args[0]); err == nil {
			port = p
		}
	}
	runWebServer(port)
}

func handleSystemCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ./netxfw system [status|init|test|sync|daemon|load|reload|unload|set-default-deny|ratelimit]")
		return
	}

	switch args[0] {
	case "status":
		showStatus()
	case "init":
		initConfiguration()
	case "test":
		testConfiguration()
	case "sync":
		runSync(args[1:])
	case "daemon":
		runDaemon()
	case "load":
		initConfiguration()
		installXDP()
	case "reload":
		reloadXDP()
	case "unload":
		removeXDP()
	case "set-default-deny":
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw system set-default-deny <true|false>")
			return
		}
		enable := args[1] == "true"
		syncDefaultDeny(enable)
	case "ratelimit":
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw system ratelimit <true|false>")
			return
		}
		enable := args[1] == "true"
		syncEnableRateLimit(enable)
	case "afxdp":
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw system afxdp <true|false>")
			return
		}
		enable := args[1] == "true"
		syncEnableAFXDP(enable)
	default:
		fmt.Println("Unknown system subcommand:", args[0])
	}
}

func handleLimitCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ./netxfw limit [add|remove|list]")
		return
	}

	switch args[0] {
	case "add":
		// limit add <ip> <rate> <burst>
		if len(args) < 4 {
			fmt.Println("Usage: ./netxfw limit add <ip> <rate> <burst>")
			return
		}
		ip := args[1]
		rate, _ := strconv.ParseUint(args[2], 10, 64)
		burst, _ := strconv.ParseUint(args[3], 10, 64)
		syncRateLimitRule(ip, rate, burst, true)

	case "remove":
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw limit remove <ip>")
			return
		}
		syncRateLimitRule(args[1], 0, 0, false)

	case "list":
		showRateLimitRules()

	default:
		fmt.Println("Unknown limit subcommand:", args[0])
	}
}

func handleSecurityCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ./netxfw security [fragments|strict-tcp|syn-limit|bogon] <true|false>")
		return
	}

	switch args[0] {
	case "fragments":
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw security fragments <true|false>")
			return
		}
		syncDropFragments(args[1] == "true")
	case "strict-tcp":
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw security strict-tcp <true|false>")
			return
		}
		syncStrictTCP(args[1] == "true")
	case "syn-limit":
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw security syn-limit <true|false>")
			return
		}
		syncSYNLimit(args[1] == "true")
	case "bogon":
		if len(args) < 2 {
			fmt.Println("Usage: ./netxfw security bogon <true|false>")
			return
		}
		syncBogonFilter(args[1] == "true")
	default:
		fmt.Println("Unknown security subcommand:", args[0])
	}
}

/**
 * askConfirmation asks the user for a y/n confirmation.
 */
func askConfirmation(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

/**
 * printUsage prints command line help.
 * printUsage 打印命令行帮助信息。
 */
func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  --- 系统命令 (system) ---")
	fmt.Println("  ./netxfw system status             # 查看运行状态和统计")
	fmt.Println("  ./netxfw system init               # 初始化配置文件")
	fmt.Println("  ./netxfw system test               # 测试配置有效性")
	fmt.Println("  ./netxfw system daemon             # 启动后台进程")
	fmt.Println("  ./netxfw system load               # 加载 XDP 驱动")
	fmt.Println("  ./netxfw system sync to-map        # 同步配置到 BPF maps")
	fmt.Println("  ./netxfw system sync to-config     # 同步 BPF maps 到配置文件")
	fmt.Println("  ./netxfw system reload             # 平滑重载 XDP (支持容量调整)")
	fmt.Println("  ./netxfw system unload             # 卸载 XDP 驱动")
	fmt.Println("  ./netxfw system set-default-deny <true|false> # 设置默认拦截策略")
	fmt.Println("  ./netxfw system ratelimit <true|false> # 开启/关闭通用限速")
	fmt.Println("  ./netxfw system afxdp <true|false> # 开启/关闭 AF_XDP 重定向")
	fmt.Println("")
	fmt.Println("  --- 安全管理 (security) ---")
	fmt.Println("  ./netxfw security fragments <true|false> # 丢弃分片包")
	fmt.Println("  ./netxfw security strict-tcp <true|false> # 严格 TCP 标志位校验")
	fmt.Println("  ./netxfw security syn-limit <true|false>  # 仅对 SYN 包应用限速")
	fmt.Println("  ./netxfw security bogon <true|false>     # 开启/关闭 Bogon 过滤")
	fmt.Println("")
	fmt.Println("  --- 限速管理 (limit) ---")
	fmt.Println("  ./netxfw limit add <ip> <rate> <burst> # 设置 IP 限速 (pps)")
	fmt.Println("  ./netxfw limit remove <ip>             # 移除 IP 限速")
	fmt.Println("  ./netxfw limit list                    # 查看限速规则")
	fmt.Println("")
	fmt.Println("  --- Web 管理界面 (web) ---")
	fmt.Println("  ./netxfw web [port]                # 启动 Web 管理界面 (默认 11811)")
	fmt.Println("")
	fmt.Println("  --- 规则管理 (rule) ---")
	fmt.Println("  ./netxfw rule add <ip> [allow|deny]      # 封禁或加白 IP")
	fmt.Println("  ./netxfw rule add <ip> <port> <allow|deny> # 精确规则")
	fmt.Println("  ./netxfw rule remove <ip> [port|allow|deny] # 移除 IP 或 IP+Port 规则")
	fmt.Println("  ./netxfw rule list [lock|allow|rules]    # 查看规则列表")
	fmt.Println("  ./netxfw rule import <type> <file>       # 批量导入 (lock/allow/rules)")
	fmt.Println("  ./netxfw rule clear                      # 清空黑名单")
	fmt.Println("")
	fmt.Println("  --- 快捷方式 ---")
	fmt.Println("  ./netxfw lock <ip>          # 快速封禁 IP")
	fmt.Println("  ./netxfw unlock <ip>        # 快速解封 IP (从黑名单移除)")
	fmt.Println("  ./netxfw allow <ip>         # 快速加白 IP")
	fmt.Println("  ./netxfw unallow <ip>       # 快速取消加白 (从白名单移除)")
	fmt.Println("  ./netxfw clear              # 快速清空黑名单")
	fmt.Println("")
	fmt.Println("  --- 同步管理 (sync) ---")
	fmt.Println("  ./netxfw sync to-map        # 将配置文件规则同步到内核 map")
	fmt.Println("  ./netxfw sync to-config     # 将内核 map 规则同步到配置文件")
	fmt.Println("")
	fmt.Println("  --- 插件管理 (plugin) ---")
	fmt.Println("  ./netxfw plugin load <path> <index>  # 动态加载 BPF 插件 (index: 2-15)")
	fmt.Println("  ./netxfw plugin remove <index>       # 动态卸载 BPF 插件")
	fmt.Println("")
	fmt.Println("  --- 端口管理 (port) ---")
	fmt.Println("  ./netxfw port add <port>    # 全局放行端口")
	fmt.Println("  ./netxfw port remove <port> # 移除全局放行")
	fmt.Println("")
	fmt.Println("  --- 连接追踪 (conntrack) ---")
	fmt.Println("  ./netxfw conntrack          # 查看当前活跃连接")
	fmt.Println("  ./netxfw version            # 查看版本和版型信息")
}

func showVersion() {
	fmt.Printf("netxfw %s\n", version.Version)
	showStatus() // showStatus now includes edition info
}
