package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
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
	case "help":
		printUsage()
	case "init":
		initConfiguration()
	case "test":
		testConfiguration()
	case "sync":
		runSync()
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

	// --- 端口管理 (port) ---
	case "port":
		handlePortCommand(os.Args[2:])

	// --- 系统管理 (system) ---
	case "system":
		handleSystemCommand(os.Args[2:])

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
			log.Fatal("❌ Missing IP address")
		}
		syncLockMap(os.Args[2], false)
	case "allow":
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing IP address")
		}
		var port uint16
		if len(os.Args) > 3 {
			p, _ := strconv.ParseUint(os.Args[3], 10, 16)
			port = uint16(p)
		}
		syncWhitelistMap(os.Args[2], port, true)
	case "unallow":
		if len(os.Args) < 3 {
			log.Fatal("❌ Missing IP address")
		}
		syncWhitelistMap(os.Args[2], 0, false)
	case "list":
		handleListCommand(os.Args[2:])
	case "allow-list":
		handleListCommand([]string{"whitelist"})
	case "list-rules":
		showIPPortRules()
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
			fmt.Println("Usage: ./netxfw rule remove <ip> [port]")
			return
		}
		ip := args[1]
		if len(args) == 2 {
			syncLockMap(ip, false)
			syncWhitelistMap(ip, 0, false)
		} else {
			port, _ := strconv.Atoi(args[2])
			syncIPPortRule(ip, uint16(port), 0, false)
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

	if len(args) > 0 && (args[0] == "whitelist" || args[0] == "allow") {
		isWhitelist = true
		args = args[1:]
	} else if len(args) > 0 && (args[0] == "blacklist" || args[0] == "lock") {
		isWhitelist = false
		args = args[1:]
	} else if len(args) > 0 && args[0] == "rules" {
		showIPPortRules()
		return
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

	if isWhitelist {
		showWhitelist(limit, search)
	} else {
		showLockList(limit, search)
	}
}

func handleSystemCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ./netxfw system [init|test|sync|daemon|load|reload|unload|set-default-deny]")
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
		runSync()
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
	default:
		fmt.Println("Unknown system subcommand:", args[0])
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
	fmt.Println("  ./netxfw system reload             # 平滑重载 XDP (支持容量调整)")
	fmt.Println("  ./netxfw system unload             # 卸载 XDP 驱动")
	fmt.Println("")
	fmt.Println("  --- 规则管理 (rule) ---")
	fmt.Println("  ./netxfw rule add <ip> [allow|deny]      # 封禁或加白 IP")
	fmt.Println("  ./netxfw rule add <ip> <port> <allow|deny> # 精确规则")
	fmt.Println("  ./netxfw rule remove <ip> [port]         # 移除 IP 或 IP+Port 规则")
	fmt.Println("  ./netxfw rule list [lock|allow|rules]    # 查看规则列表")
	fmt.Println("  ./netxfw rule import <type> <file>       # 批量导入 (lock/allow/rules)")
	fmt.Println("  ./netxfw rule clear                      # 清空黑名单")
	fmt.Println("")
	fmt.Println("  --- 快捷方式 ---")
	fmt.Println("  ./netxfw lock <ip>          # 快速封禁 IP")
	fmt.Println("  ./netxfw unlock <ip>        # 快速解封 IP")
	fmt.Println("  ./netxfw allow <ip>         # 快速加白 IP")
	fmt.Println("  ./netxfw clear              # 快速清空黑名单")
	fmt.Println("")
	fmt.Println("  --- 端口管理 (port) ---")
	fmt.Println("  ./netxfw port add <port>    # 全局放行端口")
	fmt.Println("  ./netxfw port remove <port> # 移除全局放行")
	fmt.Println("")
	fmt.Println("  --- 连接追踪 (conntrack) ---")
	fmt.Println("  ./netxfw conntrack          # 查看当前活跃连接")
}
