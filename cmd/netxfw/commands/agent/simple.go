package agent

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/core"
	"github.com/netxfw/netxfw/internal/daemon"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/fmtutil"
	"github.com/netxfw/netxfw/internal/utils/iputil"
	"github.com/netxfw/netxfw/internal/version"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

// SimpleStatusCmd 实现 'status' 命令
// SimpleStatusCmd implements the 'status' command
var SimpleStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system status",
	// Short: 显示系统状态
	Long: `Show system status including XDP program status and performance statistics
Use -v for verbose output with detailed statistics`,
	// Long: 显示系统状态，包括 XDP 程序状态和性能统计
	// 使用 -v 显示详细统计信息
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		verbose, _ := cmd.Flags().GetBool("verbose")

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			pass, drops, err := s.Stats.GetCounters()
			if err != nil {
				fmt.Printf("[WARN] Could not retrieve statistics: %v\n", err)
				return nil
			}

			if verbose {
				fmt.Println("[OK] XDP Program Status: Loaded and Running")
				showTrafficMetrics(pass, drops)
				showConntrackHealth(s.GetManager())
				showMapStatistics(s.GetManager())
				showConclusionStatistics(s.GetManager(), s.Stats)

				fmt.Println()
				fmt.Println("=== Verbose Status ===")
				showDropStatistics(s.Stats, drops, pass)
				showPassStatistics(s.Stats, pass, drops)
				showProtocolDistribution(s.Stats, pass, drops)
				showPolicyConfiguration()
				showAttachedInterfaces()
			} else {
				fmt.Println("[OK] Firewall Status: Running")
				fmt.Println()

				totalPackets := pass + drops
				passPercent := float64(pass) / float64(totalPackets) * 100
				fmt.Printf("[Stats] Traffic: %s packets (Pass: %.1f%%, Drop: %.1f%%)\n",
					fmtutil.FormatNumberWithComma(totalPackets), passPercent, 100-passPercent)

				trafficStats, err := xdp.LoadTrafficStats()
				if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
					fmt.Printf("[Rate] Current: %s pps (%s)\n",
						fmtutil.FormatNumberWithComma(trafficStats.CurrentPPS),
						fmtutil.FormatBPS(trafficStats.CurrentBPS))
				}

				blacklistCount, _ := s.GetManager().GetLockedIPCount()
				dynBlacklistCount, _ := s.GetManager().GetDynLockListCount()
				totalBlocked := uint64(blacklistCount) + uint64(dynBlacklistCount)
				if totalBlocked > 0 {
					fmt.Printf("[Block] Banned IPs: %s (Static: %s, Dynamic: %s)\n",
						fmtutil.FormatNumberWithComma(totalBlocked),
						fmtutil.FormatNumberWithComma(uint64(blacklistCount)),
						fmtutil.FormatNumberWithComma(uint64(dynBlacklistCount)))
				} else {
					fmt.Println("[Block] Banned IPs: 0")
				}

				connCount, _ := s.GetManager().GetConntrackCount()
				fmt.Printf("[Conn] Active connections: %s\n", fmtutil.FormatNumberWithComma(uint64(connCount)))

				whitelistCount, _ := s.GetManager().GetWhitelistCount()
				if whitelistCount > 0 {
					fmt.Printf("[Allow] Whitelisted IPs: %s\n", fmtutil.FormatNumberWithComma(uint64(whitelistCount)))
				}

				// Show compact map statistics / 显示紧凑的 Map 统计
				showCompactMapStatistics(s.GetManager())

				// Show top blocked attacker IPs / 显示被拦截最多的攻击 IP
				showTopBlockedIPs(s.Stats, drops)

				fmt.Println()
				fmt.Println("[Tip] Use 'netxfw status -v' for detailed info")
			}
			return nil
		})
	},
}

// SimpleStartCmd 实现 'start' 命令
// SimpleStartCmd implements the 'start' command
var SimpleStartCmd = &cobra.Command{
	Use:    "start",
	Short:  "Start netxfw firewall",
	Hidden: true,
	// Short: 启动 netxfw 防火墙
	Long: `Start netxfw firewall (load XDP driver and start agent)`,
	// Long: 启动 netxfw 防火墙（加载 XDP 驱动并启动 agent）
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			if err := app.InstallXDP(cmd.Context(), nil); err != nil {
				cmd.PrintErrln("[ERROR] Failed to start XDP program:", err)
				os.Exit(1)
			}

			if runtime.Mode == "agent" || runtime.Mode == "" {
				fmt.Println("[RELOAD] Starting agent...")
			}

			executor.PrintSuccess("netxfw started successfully")
			return nil
		})
	},
}

// SimpleStopCmd 实现 'stop' 命令
// SimpleStopCmd implements the 'stop' command
var SimpleStopCmd = &cobra.Command{
	Use:    "stop",
	Short:  "Stop netxfw firewall",
	Hidden: true,
	// Short: 停止 netxfw 防火墙
	Long: `Stop netxfw firewall (unload XDP driver and stop agent)`,
	// Long: 停止 netxfw 防火墙（卸载 XDP 驱动并停止 agent）
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			if runtime.Mode == "agent" || runtime.Mode == "" {
				fmt.Println("[RELOAD] Stopping agent...")
			}

			if err := app.RemoveXDP(cmd.Context(), nil); err != nil {
				cmd.PrintErrln("[ERROR] Failed to stop XDP program:", err)
				os.Exit(1)
			}

			executor.PrintSuccess("netxfw stopped successfully")
			return nil
		})
	},
}

// SimpleReloadCmd 实现 'reload' 命令
// SimpleReloadCmd implements the 'reload' command
var SimpleReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload configuration and sync to BPF maps",
	// Short: 重载配置并同步到 BPF Map
	Long: `Reload configuration and sync to BPF maps: reads configuration from files and updates BPF maps without reloading XDP program.
This is faster than full reload and maintains existing connections.
重载配置并同步到 BPF Map：从文件读取配置并更新 BPF Map，而不重新加载 XDP 程序。
这比完全重载更快，并且保持现有连接。`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithConfigManager(func(cfg *types.GlobalConfig, manager *xdp.Manager) error {
			if err := manager.SyncFromFiles(cfg, false); err != nil {
				return fmt.Errorf("[ERROR] Failed to sync configuration to BPF maps: %v", err)
			}
			executor.PrintSuccess("Configuration reloaded and synced to BPF maps successfully")
			return nil
		})
	},
}

// SimpleUpdateCmd 实现 'update' 命令
// SimpleUpdateCmd implements the 'update' command
var SimpleUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update netxfw software",
	// Short: 更新 netxfw 软件
	Long: `Check for the latest version on GitHub and install it`,
	// Long: 检查 GitHub 上的最新版本并安装
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			fmt.Println("[START] Checking for updates...")
			execCmd := "curl -sSL https://raw.githubusercontent.com/netxfw/netxfw/main/scripts/deploy.sh | bash"
			if err := fmtutil.RunShellCommand(execCmd); err != nil {
				return fmt.Errorf("[ERROR] Update failed: %v", err)
			}
			return nil
		})
	},
}

// SimpleVersionCmd 实现 'version' 命令
// SimpleVersionCmd implements the 'version' command
var SimpleVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	// Short: 显示版本信息
	Long: `Show version information`,
	// Long: 显示版本信息
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("netxfw version %s\n", version.Version)
	},
}

// SimpleWebCmd 实现 'web' 命令
// SimpleWebCmd implements the 'web' command
var SimpleWebCmd = &cobra.Command{
	Use:   "web",
	Short: "Show web interface information",
	// Short: 显示 Web 界面信息
	Long: `Show web interface information`,
	// Long: 显示 Web 界面信息
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			fmt.Println("[Web] Interface: http://localhost:8080")
			return nil
		})
	},
}

// SimpleInitCmd 实现 'init' 命令
// SimpleInitCmd implements the 'init' command
var SimpleInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration",
	// Short: 初始化配置
	Long: `Initialize configuration file`,
	// Long: 初始化配置文件
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			core.InitConfiguration(cmd.Context())
			executor.PrintSuccess("Configuration initialized")
			return nil
		})
	},
}

// SimpleTestCmd 实现 'test' 命令
// SimpleTestCmd implements the 'test' command
var SimpleTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration",
	// Short: 测试配置
	Long: `Test configuration file`,
	// Long: 测试配置文件
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			daemon.TestConfiguration(cmd.Context())
			executor.PrintSuccess("Configuration test passed")
			return nil
		})
	},
}

// SimpleBlockCmd 实现 'block' 命令（XDP 层封禁）
// SimpleBlockCmd implements the 'block' command (XDP layer blocking)
var SimpleBlockCmd = &cobra.Command{
	Use:    "block <ip>",
	Short:  "Block IP at XDP layer",
	Hidden: true,
	// Short: 在 XDP 层封禁 IP
	Long: `Block IP at XDP layer (highest performance, bypasses kernel network stack).
This is the recommended way to block IPs.
在 XDP 层封禁 IP（最高性能，绕过内核网络栈）。
这是推荐的封禁 IP 的方式。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		ip := args[0]
		durationStr, _ := cmd.Flags().GetString("duration")
		persistFile, _ := cmd.Flags().GetString("file")

		// 验证 IP 格式：必须是有效的 IPv4/IPv6 地址或 CIDR
		// Validate IP format: must be valid IPv4/IPv6 address or CIDR
		if err := common.ValidateIP(ip); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithManager(func(manager *xdp.Manager) error {
			defer manager.Close()

			var errBlock error
			if durationStr != "" {
				duration, err := common.ParseAndValidateTTL(durationStr)
				if err != nil {
					return err
				}
				errBlock = manager.BlockDynamic(ip, duration)
			} else if persistFile != "" {
				errBlock = manager.BlockStatic(ip, persistFile)
			} else {
				errBlock = manager.BlockStatic(ip, "")
			}

			if errBlock != nil {
				return fmt.Errorf("[ERROR] Failed to block IP: %v", errBlock)
			}
			executor.PrintSuccess("IP blocked at XDP layer: " + ip)
			return nil
		})
	},
}

// SimpleUnblockCmd 实现 'unblock' 命令（XDP 层解封）
// SimpleUnblockCmd implements the 'unblock' command (XDP layer unblocking)
var SimpleUnblockCmd = &cobra.Command{
	Use:    "unblock <ip>",
	Short:  "Unblock IP at XDP layer",
	Hidden: true,
	// Short: 在 XDP 层解封 IP
	Long: `Unblock IP at XDP layer.
在 XDP 层解封 IP。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		ip := args[0]

		// 验证 IP 格式：必须是有效的 IPv4/IPv6 地址或 CIDR
		// Validate IP format: must be valid IPv4/IPv6 address or CIDR
		if err := common.ValidateIP(ip); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithManager(func(manager *xdp.Manager) error {
			defer manager.Close()

			if err := xdp.UnlockIP(manager.LockList(), ip); err != nil {
				return fmt.Errorf("[ERROR] Failed to unblock IP: %v", err)
			}
			executor.PrintSuccess("IP unblocked at XDP layer: " + ip)
			return nil
		})
	},
}

// SimpleListCmd 实现 'list' 命令（查看封禁列表）
// SimpleListCmd implements the 'list' command (view blocked IPs list)
var SimpleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List blocked IPs",
	// Short: 列出封禁的 IP
	Long: `List blocked IPs at XDP layer.
列出 XDP 层封禁的 IP。`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		static, _ := cmd.Flags().GetBool("static")
		dynamic, _ := cmd.Flags().GetBool("dynamic")

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithManager(func(manager *xdp.Manager) error {
			defer manager.Close()

			if static {
				ips, _, err := xdp.ListBlockedIPs(manager.LockList(), false, 0, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list blocked IPs: %v", err)
				}
				cmd.Println("=== Static Blocked IPs ===")
				for _, ip := range ips {
					cmd.Printf("%s\n", ip.IP)
				}
			} else if dynamic {
				ips, _, err := xdp.ListBlockedIPs(manager.DynLockList(), false, 0, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list blocked IPs: %v", err)
				}
				cmd.Println("=== Dynamic Blocked IPs ===")
				for _, ip := range ips {
					cmd.Printf("%s (expires: %d)\n", ip.IP, ip.ExpiresAt)
				}
			} else {
				staticIPs, _, err := xdp.ListBlockedIPs(manager.LockList(), false, 0, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list static blocked IPs: %v", err)
				}
				dynamicIPs, _, err := xdp.ListBlockedIPs(manager.DynLockList(), false, 0, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list dynamic blocked IPs: %v", err)
				}

				cmd.Println("=== Blocked IPs ===")
				cmd.Println("--- Static ---")
				for _, ip := range staticIPs {
					cmd.Printf("%s\n", ip.IP)
				}
				cmd.Println("--- Dynamic ---")
				for _, ip := range dynamicIPs {
					cmd.Printf("%s (expires: %d)\n", ip.IP, ip.ExpiresAt)
				}
			}
			return nil
		})
	},
}

// SimpleClearCmd 实现 'clear' 命令（清空封禁列表）
// SimpleClearCmd implements the 'clear' command (clear blocked IPs list)
var SimpleClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all blocked IPs",
	// Short: 清空所有封禁的 IP
	Long: `Clear all blocked IPs at XDP layer.
清空 XDP 层所有封禁的 IP。

默认清空静态黑名单（永久封禁的 IP）。
使用 --dynamic 标志清空动态黑名单（临时封禁的 IP）。
使用 --force 标志跳过确认提示。

Examples:
  netxfw clear              # 清空静态黑名单
  netxfw clear --dynamic    # 清空动态黑名单
  netxfw clear --force      # 清空静态黑名单（跳过确认）`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		clearDynamic, _ := cmd.Flags().GetBool("dynamic")
		force, _ := cmd.Flags().GetBool("force")

		// 显示警告并确认（除非使用 --force）
		// Show warning and confirm (unless --force is used)
		if !force {
			if clearDynamic {
				fmt.Println("[WARNING] This will clear all IPs from dynamic blacklist!")
			} else {
				fmt.Println("[WARNING] This will clear all IPs from static blacklist!")
			}

			if !common.AskConfirmation("Are you sure you want to continue?") {
				fmt.Println("[CANCELLED] Clear cancelled")
				return
			}
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithManager(func(manager *xdp.Manager) error {
			defer manager.Close()

			if clearDynamic {
				// 清空动态黑名单
				// Clear dynamic blacklist
				if err := xdp.ClearBlacklistMap(manager.DynLockList()); err != nil {
					return fmt.Errorf("[ERROR] Failed to clear dynamic blacklist: %v", err)
				}
				executor.PrintSuccess("Dynamic blacklist cleared successfully")
			} else {
				// 默认清空静态黑名单
				// Default: clear static blacklist
				if err := xdp.ClearBlacklistMap(manager.LockList()); err != nil {
					return fmt.Errorf("[ERROR] Failed to clear static blacklist: %v", err)
				}
				executor.PrintSuccess("Static blacklist cleared successfully")
			}
			return nil
		})
	},
}

// SimpleAllowCmd 实现 'allow' 命令（白名单管理）
// SimpleAllowCmd implements the 'allow' command (whitelist management)
var SimpleAllowCmd = &cobra.Command{
	Use:   "allow [ip][:port]",
	Short: "Allow IP at XDP layer",
	// Short: 在 XDP 层允许 IP
	Long: `Allow IP at XDP layer (add to whitelist).
支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080
注意：IPv6 地址必须使用方括号包裹，如 [2001:db8::1]:8080

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

// allowAddCmd allow add 子命令
// allowAddCmd allow add subcommand
var allowAddCmd = &cobra.Command{
	Use:   "add <ip>[:port]",
	Short: "Add IP to whitelist",
	// Short: 添加 IP 到白名单
	Long: `Add IP to whitelist.
添加 IP 到白名单。

支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runAllowCommand(cmd, args[0])
	},
}

// allowListCmd allow list 子命令
// allowListCmd allow list subcommand
var allowListCmd = &cobra.Command{
	Use:   "list",
	Short: "List whitelist IPs",
	// Short: 列出白名单 IP
	Long: `List whitelist IPs.
列出白名单 IP。`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithManager(func(manager *xdp.Manager) error {
			defer manager.Close()

			whitelist := manager.Whitelist()
			if whitelist == nil {
				return fmt.Errorf("[ERROR] Whitelist map not available")
			}

			ips, _, err := xdp.ListBlockedIPs(whitelist, false, 0, "")
			if err != nil {
				return fmt.Errorf("[ERROR] Failed to list whitelist: %v", err)
			}

			if len(ips) == 0 {
				cmd.Println("[INFO] Whitelist is empty")
				return nil
			}

			cmd.Println("=== Whitelist IPs ===")
			for _, ip := range ips {
				cmd.Printf("  %s\n", ip.IP)
			}
			cmd.Printf("\n[INFO] Total: %d IPs\n", len(ips))
			return nil
		})
	},
}

// allowPortCmd allow port 子命令
// allowPortCmd allow port subcommand
var allowPortCmd = &cobra.Command{
	Use:   "port",
	Short: "IP+Port allow rule management",
	// Short: IP+Port 允许规则管理
	Long: `IP+Port allow rule management commands.\nIP+Port 允许规则管理命令。`,
}

// allowPortListCmd allow port list 子命令
// allowPortListCmd allow port list subcommand
var allowPortListCmd = &cobra.Command{
	Use:   "list",
	Short: "List IP+Port allow rules",
	// Short: 列出 IP+Port 允许规则
	Long: `List IP+Port allow rules.
列出 IP+Port 允许规则。`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithManager(func(manager *xdp.Manager) error {
			defer manager.Close()

			rules, _, err := manager.ListIPPortRules(false, 0, "")
			if err != nil {
				return fmt.Errorf("[ERROR] Failed to list IP+Port rules: %v", err)
			}

			// 使用公共函数过滤 allow 规则
			// Use common function to filter allow rules
			allowRules := common.FilterIPPortRules(rules, "allow")

			if len(allowRules) == 0 {
				cmd.Println("[INFO] No IP+Port allow rules")
				return nil
			}

			cmd.Println("=== IP+Port Allow Rules ===")
			for _, rule := range allowRules {
				cmd.Printf("  %s:%d\n", rule.IP, rule.Port)
			}
			cmd.Printf("\n[INFO] Total: %d rules\n", len(allowRules))
			return nil
		})
	},
}

// SimpleDenyCmd 实现 'deny' 命令（黑名单管理）
// SimpleDenyCmd implements the 'deny' command (blacklist management)
var SimpleDenyCmd = &cobra.Command{
	Use:   "deny [ip][:port]",
	Short: "Deny IP at XDP layer",
	// Short: 在 XDP 层拒绝 IP
	Long: `Deny IP at XDP layer (add to blacklist).
支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080
注意：IPv6 地址必须使用方括号包裹，如 [2001:db8::1]:8080

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

// denyAddCmd deny add 子命令
// denyAddCmd deny add subcommand
var denyAddCmd = &cobra.Command{
	Use:   "add <ip>[:port]",
	Short: "Add IP to blacklist",
	// Short: 添加 IP 到黑名单
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

// denyListCmd deny list 子命令
// denyListCmd deny list subcommand
var denyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List blacklist IPs",
	// Short: 列出黑名单 IP
	Long: `List blacklist IPs (both static and dynamic).
列出黑名单 IP（包括静态和动态）。`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		static, _ := cmd.Flags().GetBool("static")
		dynamic, _ := cmd.Flags().GetBool("dynamic")

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithManager(func(manager *xdp.Manager) error {
			defer manager.Close()

			if static {
				ips, _, err := xdp.ListBlockedIPs(manager.LockList(), false, 0, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list blocked IPs: %v", err)
				}
				cmd.Println("=== Static Blacklist ===")
				for _, ip := range ips {
					cmd.Printf("  %s\n", ip.IP)
				}
				cmd.Printf("\n[INFO] Total: %d IPs\n", len(ips))
			} else if dynamic {
				ips, _, err := xdp.ListDynamicBlockedIPs(manager.DynLockList(), 0, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list dynamic blocked IPs: %v", err)
				}
				cmd.Println("=== Dynamic Blacklist ===")
				for _, ip := range ips {
					cmd.Printf("  %s (expires: %d)\n", ip.IP, ip.ExpiresAt)
				}
				cmd.Printf("\n[INFO] Total: %d IPs\n", len(ips))
			} else {
				staticIPs, _, err := xdp.ListBlockedIPs(manager.LockList(), false, 0, "")
				if err != nil {
					return fmt.Errorf("[ERROR] Failed to list static blocked IPs: %v", err)
				}
				dynamicIPs, _, err := xdp.ListDynamicBlockedIPs(manager.DynLockList(), 0, "")
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
				cmd.Printf("\n[INFO] Total: %d static, %d dynamic\n", len(staticIPs), len(dynamicIPs))
			}
			return nil
		})
	},
}

// denyPortCmd deny port 子命令
// denyPortCmd deny port subcommand
var denyPortCmd = &cobra.Command{
	Use:   "port",
	Short: "IP+Port deny rule management",
	// Short: IP+Port 拒绝规则管理
	Long: `IP+Port deny rule management commands.\nIP+Port 拒绝规则管理命令。`,
}

// denyPortListCmd deny port list 子命令
// denyPortListCmd deny port list subcommand
var denyPortListCmd = &cobra.Command{
	Use:   "list",
	Short: "List IP+Port deny rules",
	// Short: 列出 IP+Port 拒绝规则
	Long: `List IP+Port deny rules.
列出 IP+Port 拒绝规则。`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithManager(func(manager *xdp.Manager) error {
			defer manager.Close()

			rules, _, err := manager.ListIPPortRules(false, 0, "")
			if err != nil {
				return fmt.Errorf("[ERROR] Failed to list IP+Port rules: %v", err)
			}

			// 使用公共函数过滤 deny 规则
			// Use common function to filter deny rules
			denyRules := common.FilterIPPortRules(rules, "deny")

			if len(denyRules) == 0 {
				cmd.Println("[INFO] No IP+Port deny rules")
				return nil
			}

			cmd.Println("=== IP+Port Deny Rules ===")
			for _, rule := range denyRules {
				cmd.Printf("  %s:%d\n", rule.IP, rule.Port)
			}
			cmd.Printf("\n[INFO] Total: %d rules\n", len(denyRules))
			return nil
		})
	},
}

// SimpleDeleteCmd 实现 'delete/del' 命令（删除规则，支持别名 del）
// SimpleDeleteCmd implements the 'delete/del' command (remove rules, supports alias 'del')
var SimpleDeleteCmd = &cobra.Command{
	Use:   "delete <ip>[:port]",
	Short: "Delete IP from whitelist or blacklist",
	// Short: 从白名单或黑名单删除 IP
	Long: `Delete IP from whitelist or blacklist at XDP layer.
支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080
注意：IPv6 地址必须使用方括号包裹，如 [2001:db8::1]:8080

此命令会尝试从白名单、黑名单和 IP+Port 规则中删除指定的 IP。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		input := args[0]

		// 使用公共函数解析并验证 IP 输入
		// Use common function to parse and validate IP input
		ip, port, err := parseAndValidateIPInput(input)
		if err != nil {
			cmd.PrintErrln("[ERROR] " + err.Error())
			os.Exit(1)
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			removed := false

			// 如果指定了端口，删除 IP+Port 规则
			// If port is specified, remove IP+Port rule
			if port > 0 {
				if err := s.Rule.RemoveIPPortRule(ip, port); err == nil {
					cmd.Printf("[OK] Removed IP+Port rule: %s:%d\n", ip, port)
					removed = true
				} else {
					cmd.Printf("[WARN]  IP+Port rule not found: %s:%d\n", ip, port)
				}
				if !removed {
					cmd.PrintErrln("[WARN]  Rule not found")
				}
				return nil
			}

			// 尝试从静态黑名单删除
			// Try to remove from static blacklist
			if err := s.Blacklist.Remove(ip); err == nil {
				cmd.Printf("[OK] Removed %s from static blacklist\n", ip)
				removed = true
			}

			// 尝试从动态黑名单删除
			// Try to remove from dynamic blacklist
			mgr := s.GetManager()
			if mgr != nil {
				dynList := mgr.DynLockList()
				if dynList != nil {
					if err := xdp.UnlockIP(dynList, ip); err == nil {
						cmd.Printf("[OK] Removed %s from dynamic blacklist\n", ip)
						removed = true
					}
				}
			}

			// 尝试从白名单删除
			// Try to remove from whitelist
			if err := s.Whitelist.Remove(ip); err == nil {
				cmd.Printf("[OK] Removed %s from whitelist\n", ip)
				removed = true
			}

			if !removed {
				cmd.PrintErrln("[WARN]  IP not found in any list")
			}
			return nil
		})
	},
}

// SimpleUnallowCmd 实现 'unallow' 命令（从白名单移除）
// SimpleUnallowCmd implements the 'unallow' command (remove from whitelist)
var SimpleUnallowCmd = &cobra.Command{
	Use:   "unallow <ip>",
	Short: "Unallow IP at XDP layer",
	// Short: 在 XDP 层不允许 IP
	Long: `Unallow IP at XDP layer (remove from whitelist).
在 XDP 层不允许 IP（从白名单移除）。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		ip := args[0]

		// 验证 IP 格式：必须是有效的 IPv4/IPv6 地址或 CIDR
		// Validate IP format: must be valid IPv4/IPv6 address or CIDR
		if err := common.ValidateIP(ip); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithManager(func(manager *xdp.Manager) error {
			defer manager.Close()

			if err := manager.RemoveAllowStatic(ip); err != nil {
				return fmt.Errorf("[ERROR] Failed to unallow IP: %v", err)
			}
			executor.PrintSuccess("IP unallowed at XDP layer: " + ip)
			return nil
		})
	},
}

// SimpleRuleCmd 实现 'rule' 命令组
// SimpleRuleCmd implements the 'rule' command group
var SimpleRuleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Rule management commands",
	// Short: 规则管理命令
}

// UfwEnableCmd 是 'enable' 命令（ufw 风格，启动防火墙）
// UfwEnableCmd is the 'enable' command (ufw-style, start firewall)
var UfwEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable/start firewall",
	// Short: 启用/启动防火墙
	Long: `Enable and start the firewall.
启用并启动防火墙。`,
	Run: func(cmd *cobra.Command, args []string) {
		SimpleStartCmd.Run(cmd, args)
	},
}

// UfwDisableCmd 是 'disable' 命令（ufw 风格，停止防火墙）
// UfwDisableCmd is the 'disable' command (ufw-style, stop firewall)
var UfwDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable/stop firewall",
	// Short: 禁用/停止防火墙
	Long: `Disable and stop the firewall.
禁用并停止防火墙。`,
	Run: func(cmd *cobra.Command, args []string) {
		SimpleStopCmd.Run(cmd, args)
	},
}

// UfwDenyCmd 是 'deny' 命令（ufw 风格，拒绝/封禁 IP）
// UfwDenyCmd is the 'deny' command (ufw-style, deny/block IP)
var UfwDenyCmd = &cobra.Command{
	Use:   "deny <ip>",
	Short: "Deny/block IP (alias for 'block')",
	// Short: 拒绝/封禁 IP（'block' 的别名）
	Long: `Deny/block an IP address (alias for 'block').
拒绝/封禁一个 IP 地址（'block' 的别名）。`,
	Args: SimpleBlockCmd.Args,
	Run:  SimpleBlockCmd.Run,
}

// UfwResetCmd 是 'reset' 命令（ufw 风格，重置防火墙，保留 SSH 端口）
// UfwResetCmd is the 'reset' command (ufw-style, reset firewall, preserve SSH port)
var UfwResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset firewall (clear all rules and blocked IPs, preserve SSH)",
	// Short: 重置防火墙（清空所有规则和封禁的 IP，保留 SSH）
	Long: `Reset the firewall by clearing all rules and blocked IPs.
重置防火墙，清空所有规则和封禁的 IP。

[WARN]  IMPORTANT: SSH port will be automatically preserved to prevent lockout.
[WARN]  重要：SSH 端口将被自动保留，以防止锁定。

The command will detect SSH port from /etc/ssh/sshd_config or use default port 22.
命令会从 /etc/ssh/sshd_config 检测 SSH 端口，或使用默认端口 22。`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[WARNING] This will clear all blocked IPs and rules!")

		// 检测 SSH 端口
		// Detect SSH port
		sshPort := detectSSHPort()
		fmt.Printf("[INFO] SSH port %d will be preserved to prevent lockout.\n", sshPort)
		fmt.Println()

		if !common.AskConfirmation("Are you sure you want to reset the firewall?") {
			fmt.Println("[CANCELLED] Reset cancelled")
			return
		}

		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			// 1. 清空静态黑名单
			// Clear static blacklist
			if err := s.Blacklist.Clear(); err != nil {
				cmd.PrintErrln("[WARN] Failed to clear static blacklist:", err)
			} else {
				fmt.Println("[OK] Static blacklist cleared")
			}

			// 2. 清空动态黑名单
			// Clear dynamic blacklist
			if err := xdp.ClearBlacklistMap(s.GetManager().DynLockList()); err != nil {
				cmd.PrintErrln("[WARN] Failed to clear dynamic blacklist:", err)
			} else {
				fmt.Println("[OK] Dynamic blacklist cleared")
			}

			// 3. 清空白名单
			// Clear whitelist
			if err := s.Whitelist.Clear(); err != nil {
				cmd.PrintErrln("[WARN] Failed to clear whitelist:", err)
			} else {
				fmt.Println("[OK] Whitelist cleared")
			}

			// 4. 清空 IP+Port 规则
			// Clear IP+Port rules
			if err := s.Rule.Clear(); err != nil {
				cmd.PrintErrln("[WARN] Failed to clear IP+Port rules:", err)
			} else {
				fmt.Println("[OK] IP+Port rules cleared")
			}

			// 5. 自动添加 SSH 端口到白名单，防止锁定
			// Automatically add SSH port to whitelist to prevent lockout
			if err := s.Whitelist.Add("0.0.0.0/0", sshPort); err != nil {
				cmd.PrintErrln("[WARN] Failed to preserve SSH port:", err)
			} else {
				fmt.Printf("[OK] SSH port %d preserved in whitelist\n", sshPort)
			}

			fmt.Println()
			fmt.Println("[OK] Firewall has been reset successfully")
			return nil
		})
	},
}

// detectSSHPort 从 SSH 配置文件检测端口，失败则返回默认端口 22
// detectSSHPort detects SSH port from config file, returns default port 22 on failure
func detectSSHPort() uint16 {
	// SSH 配置文件路径
	// SSH config file path
	sshConfigPath := "/etc/ssh/sshd_config"

	// 读取配置文件
	// Read config file
	data, err := os.ReadFile(sshConfigPath)
	if err != nil {
		// 读取失败，使用默认端口
		// Read failed, use default port
		return 22
	}

	// 解析配置文件查找 Port 配置
	// Parse config file to find Port setting
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 跳过注释行
		// Skip comment lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// 查找 Port 配置
		// Find Port configuration
		if strings.HasPrefix(line, "Port ") || strings.HasPrefix(line, "Port\t") {
			// 提取端口号
			// Extract port number
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				portStr := fields[1]
				port, err := strconv.Atoi(portStr)
				if err == nil && port > 0 && port <= 65535 {
					return uint16(port)
				}
			}
		}
	}

	// 未找到配置，使用默认端口
	// Configuration not found, use default port
	return 22
}

// UfwDeleteCmd 是 'delete' 命令（ufw 风格，删除规则/解封）
// UfwDeleteCmd is the 'delete' command (ufw-style, delete rule/unblock)
var UfwDeleteCmd = &cobra.Command{
	Use:   "delete <ip>",
	Short: "Delete/unblock IP (alias for 'unblock')",
	// Short: 删除/解封 IP（'unblock' 的别名）
	Long: `Delete/unblock an IP address (alias for 'unblock').
删除/解封一个 IP 地址（'unblock' 的别名）。`,
	Args: SimpleUnblockCmd.Args,
	Run:  SimpleUnblockCmd.Run,
}

func init() {
	// Register common flags for all simple commands
	// 为所有简单命令注册常用标志
	RegisterCommonFlags(SimpleStatusCmd)
	RegisterCommonFlags(SimpleStartCmd)
	RegisterCommonFlags(SimpleStopCmd)
	RegisterCommonFlags(SimpleReloadCmd)
	RegisterCommonFlags(SimpleUpdateCmd)
	RegisterCommonFlags(SimpleVersionCmd)
	RegisterCommonFlags(SimpleWebCmd)
	RegisterCommonFlags(SimpleInitCmd)
	RegisterCommonFlags(SimpleTestCmd)
	RegisterCommonFlags(SimpleListCmd)
	RegisterCommonFlags(SimpleClearCmd)
	RegisterCommonFlags(SimpleAllowCmd)
	RegisterCommonFlags(SimpleDenyCmd)
	RegisterCommonFlags(SimpleDeleteCmd)
	RegisterCommonFlags(SimpleRuleCmd)
	RegisterCommonFlags(UfwEnableCmd)
	RegisterCommonFlags(UfwDisableCmd)
	RegisterCommonFlags(UfwResetCmd)

	// Register allow subcommands
	// 注册 allow 子命令
	RegisterCommonFlags(allowAddCmd)
	RegisterCommonFlags(allowListCmd)
	RegisterCommonFlags(allowPortCmd)
	RegisterCommonFlags(allowPortListCmd)
	SimpleAllowCmd.AddCommand(allowAddCmd)
	SimpleAllowCmd.AddCommand(allowListCmd)
	allowPortCmd.AddCommand(allowPortListCmd)
	SimpleAllowCmd.AddCommand(allowPortCmd)

	// Register deny subcommands
	// 注册 deny 子命令
	RegisterCommonFlags(denyAddCmd)
	RegisterCommonFlags(denyListCmd)
	RegisterCommonFlags(denyPortCmd)
	RegisterCommonFlags(denyPortListCmd)
	SimpleDenyCmd.AddCommand(denyAddCmd)
	SimpleDenyCmd.AddCommand(denyListCmd)
	denyPortCmd.AddCommand(denyPortListCmd)
	SimpleDenyCmd.AddCommand(denyPortCmd)

	// Add specific flags for deny command (TTL for dynamic blacklist)
	// 为 deny 命令添加特定标志（动态黑名单的 TTL）
	SimpleDenyCmd.Flags().StringP("ttl", "t", "", "Time-to-live for dynamic blacklist (e.g., 1h, 30m, 1d)")
	denyAddCmd.Flags().StringP("ttl", "t", "", "Time-to-live for dynamic blacklist (e.g., 1h, 30m, 1d)")

	// Add specific flags for deny list command
	// 为 deny list 命令添加特定标志
	denyListCmd.Flags().Bool("static", false, "Show only static blacklist")
	denyListCmd.Flags().Bool("dynamic", false, "Show only dynamic blacklist")

	// Add specific flags for list command
	// 为 list 命令添加特定标志
	SimpleListCmd.Flags().Bool("static", false, "Show only static blacklist")
	SimpleListCmd.Flags().Bool("dynamic", false, "Show only dynamic blacklist")

	// Add specific flags for clear command
	// 为 clear 命令添加特定标志
	SimpleClearCmd.Flags().Bool("dynamic", false, "Clear dynamic blacklist instead of static")

	// Keep old commands hidden for backward compatibility
	// 保留旧命令但隐藏，向后兼容
	RegisterCommonFlags(SimpleBlockCmd)
	RegisterCommonFlags(SimpleUnblockCmd)
	RegisterCommonFlags(SimpleUnallowCmd)
	RegisterCommonFlags(UfwDenyCmd)
	RegisterCommonFlags(UfwDeleteCmd)

	// Add specific flags for block command (legacy)
	// 为 block 命令添加特定标志（旧版）
	SimpleBlockCmd.Flags().StringP("duration", "d", "", "Block duration (e.g., 1h, 30m)")
	SimpleBlockCmd.Flags().StringP("file", "f", "", "Persist blocked IPs to file")

	// Add force flag for clear command to skip confirmation
	// 为 clear 命令添加 force 标志以跳过确认
	SimpleClearCmd.Flags().Bool("force", false, "Skip confirmation prompt")
}

// parseIPInput 解析 IP 输入，支持 IPv4/IPv6/CIDR 格式
// parseIPInput parses IP input, supports IPv4/IPv6/CIDR format
// 返回: ip (IP地址或CIDR), port (端口号，0表示无端口), err (错误信息)
// Returns: ip (IP address or CIDR), port (port number, 0 means no port), err (error message)
func parseIPInput(input string) (ip string, port uint16, err error) {
	host, pVal, parseErr := iputil.ParseIPPort(input)
	if parseErr != nil {
		// 尝试解析为纯 IP（无端口）
		// Try to parse as pure IP (no port)
		if iputil.IsValidCIDR(input) {
			return input, 0, nil
		}
		// 检查是否是 IPv6 没有方括号
		// Check if IPv6 without brackets
		if strings.Contains(input, ":") && !strings.HasPrefix(input, "[") {
			return "", 0, fmt.Errorf("IPv6 地址必须使用方括号包裹，例如: [2001:db8::1]:8080 / IPv6 address must be wrapped in brackets, e.g., [2001:db8::1]:8080")
		}
		return "", 0, fmt.Errorf("无效的输入格式，必须是 <ip>[:port]，例如: 1.2.3.4:8080 或 [2001:db8::1]:8080 / invalid input format, must be <ip>[:port], e.g., 1.2.3.4:8080 or [2001:db8::1]:8080")
	}
	return host, pVal, nil
}

// parseAndValidateIPInput 解析并验证 IP 输入
// parseAndValidateIPInput parses and validates IP input
// 返回: ip (IP地址或CIDR), port (端口号，0表示无端口)
// Returns: ip (IP address or CIDR), port (port number, 0 means no port)
func parseAndValidateIPInput(input string) (string, uint16, error) {
	ip, port, err := parseIPInput(input)
	if err != nil {
		return "", 0, err
	}

	// 验证 IP 格式：必须是有效的 IPv4/IPv6 地址或 CIDR
	// Validate IP format: must be valid IPv4/IPv6 address or CIDR
	if err := common.ValidateIP(ip); err != nil {
		return "", 0, err
	}

	return ip, port, nil
}

// runAllowCommand 执行 allow 命令的通用逻辑
// runAllowCommand executes common logic for allow command
func runAllowCommand(cmd *cobra.Command, input string) {
	configFile, _ := cmd.Flags().GetString("config")

	ip, port, err := parseAndValidateIPInput(input)
	if err != nil {
		cmd.PrintErrln("[ERROR] " + err.Error())
		os.Exit(1)
	}

	executor := NewCommandExecutor(cmd).WithConfig(configFile)

	executor.ExecuteWithManager(func(manager *xdp.Manager) error {
		defer manager.Close()

		if err := manager.AllowStatic(ip, port); err != nil {
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

// runDenyCommand 执行 deny 命令的通用逻辑
// runDenyCommand executes common logic for deny command
func runDenyCommand(cmd *cobra.Command, input string) {
	configFile, _ := cmd.Flags().GetString("config")
	ttlStr, _ := cmd.Flags().GetString("ttl")

	ip, port, err := parseAndValidateIPInput(input)
	if err != nil {
		cmd.PrintErrln("[ERROR] " + err.Error())
		os.Exit(1)
	}

	executor := NewCommandExecutor(cmd).WithConfig(configFile)

	executor.ExecuteWithSDK(func(s *sdk.SDK) error {
		if port > 0 {
			if ttlStr != "" {
				cmd.PrintErrln("[WARN]  WARNING: TTL parameter is ignored for IP+Port rules")
				cmd.PrintErrln("[WARN]  警告：TTL 参数对 IP+Port 规则无效")
			}
			if err := s.Rule.AddIPPortRule(ip, port, 2); err != nil {
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
			if err := s.Blacklist.Add(ip); err != nil {
				return fmt.Errorf("[ERROR] Failed to add to static blacklist: %v", err)
			}
			executor.PrintSuccess("[BLOCK] IP added to static blacklist: " + ip)
		}
		return nil
	})
}
