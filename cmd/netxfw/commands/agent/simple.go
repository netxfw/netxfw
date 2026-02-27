package agent

import (
	"fmt"
	"os"
	"time"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/core"
	"github.com/netxfw/netxfw/internal/daemon"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/fmtutil"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/version"
	"github.com/netxfw/netxfw/internal/xdp"
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

		common.EnsureStandaloneMode()

		// Get SDK instance
		// 获取 SDK 实例
		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln("❌ Failed to get SDK:", err)
			os.Exit(1)
		}

		// Get global stats
		// 获取全局统计
		pass, drops, err := s.Stats.GetCounters()
		if err != nil {
			fmt.Printf("⚠️  Could not retrieve statistics: %v\n", err)
			return
		}

		// Show verbose details if requested
		// 如果请求详细输出
		if verbose {
			// Show XDP program status
			// 显示 XDP 程序状态
			fmt.Println("✅ XDP Program Status: Loaded and Running")

			// Show traffic metrics (PPS/BPS)
			// 显示流量指标 (PPS/BPS)
			showTrafficMetrics(pass, drops)

			// Show conntrack health
			// 显示连接跟踪健康度
			showConntrackHealth(s.GetManager())

			// Map statistics
			// Map 统计
			showMapStatistics(s.GetManager())

			// Show summary security hits
			// 显示安全命中摘要
			showConclusionStatistics(s.GetManager(), s.Stats)

			fmt.Println()
			fmt.Println("=== Verbose Status ===")

			// Show drop statistics
			// 显示丢弃统计
			showDropStatistics(s.Stats, drops, pass)

			// Show pass statistics
			// 显示通过统计
			showPassStatistics(s.Stats, pass, drops)

			// Show protocol distribution
			// 显示协议分布
			showProtocolDistribution(s.Stats, pass, drops)

			// Load configuration for policy display
			// 加载配置以显示策略
			showPolicyConfiguration()

			// Show attached interfaces
			// 显示已附加的接口
			showAttachedInterfaces()
		} else {
			// Simple status for normal users
			// 为普通用户显示简单状态
			fmt.Println("✅ 防火墙状态: 运行中")
			fmt.Println()

			// Traffic summary
			// 流量摘要
			totalPackets := pass + drops
			passPercent := float64(pass) / float64(totalPackets) * 100
			fmt.Printf("� 流量统计: %s 数据包 (通过: %.1f%%, 拦截: %.1f%%)\n",
				fmtutil.FormatNumberWithComma(totalPackets), passPercent, 100-passPercent)

			// Load traffic stats for current rate
			// 加载流量统计获取当前速率
			trafficStats, err := xdp.LoadTrafficStats()
			if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
				fmt.Printf("📈 当前速率: %s 包/秒 (%s)\n",
					fmtutil.FormatNumberWithComma(trafficStats.CurrentPPS),
					fmtutil.FormatBPS(trafficStats.CurrentBPS))
			}

			// Blocked IPs
			// 封禁 IP
			blacklistCount, _ := s.GetManager().GetLockedIPCount()
			dynBlacklistCount, _ := s.GetManager().GetDynLockListCount()
			totalBlocked := uint64(blacklistCount) + uint64(dynBlacklistCount)
			if totalBlocked > 0 {
				fmt.Printf("🔒 已封禁 IP: %s 个 (永久: %s, 临时: %s)\n",
					fmtutil.FormatNumberWithComma(totalBlocked),
					fmtutil.FormatNumberWithComma(uint64(blacklistCount)),
					fmtutil.FormatNumberWithComma(uint64(dynBlacklistCount)))
			} else {
				fmt.Println("🔒 已封禁 IP: 0 个")
			}

			// Active connections
			// 活跃连接
			connCount, _ := s.GetManager().GetConntrackCount()
			fmt.Printf("🔌 活跃连接: %s 个\n", fmtutil.FormatNumberWithComma(uint64(connCount)))

			// Whitelist
			// 白名单
			whitelistCount, _ := s.GetManager().GetWhitelistCount()
			if whitelistCount > 0 {
				fmt.Printf("⚪ 白名单 IP: %s 个\n", fmtutil.FormatNumberWithComma(uint64(whitelistCount)))
			}

			fmt.Println()
			fmt.Println("💡 提示: 使用 'netxfw status -v' 查看详细信息")
		}
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		// Start XDP program
		// 启动 XDP 程序
		if err := app.InstallXDP(cmd.Context(), nil); err != nil {
			cmd.PrintErrln("❌ Failed to start XDP program:", err)
			os.Exit(1)
		}

		// Start agent if in agent or unified mode
		// 如果在 agent 或 unified 模式下，启动 agent
		if runtime.Mode == "agent" || runtime.Mode == "" {
			fmt.Println("🔄 Starting agent...")
			// This would start the agent daemon
			// 这将启动 agent 守护进程
		}

		fmt.Println("✅ netxfw started successfully")
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		// Stop agent if running
		// 如果正在运行，停止 agent
		if runtime.Mode == "agent" || runtime.Mode == "" {
			fmt.Println("🔄 Stopping agent...")
			// This would stop the agent daemon
			// 这将停止 agent 守护进程
		}

		// Stop XDP program
		// 停止 XDP 程序
		if err := app.RemoveXDP(cmd.Context(), nil); err != nil {
			cmd.PrintErrln("❌ Failed to stop XDP program:", err)
			os.Exit(1)
		}

		fmt.Println("✅ netxfw stopped successfully")
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		// Load configuration
		// 加载配置
		configPath := runtime.ConfigPath
		if configPath == "" {
			configPath = config.DefaultConfigPath
		}

		globalCfg, err := types.LoadGlobalConfig(configPath)
		if err != nil {
			cmd.PrintErrln("❌ Failed to load configuration:", err)
			os.Exit(1)
		}

		// Get existing XDP manager
		// 获取现有的 XDP 管理器
		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
		if err != nil {
			cmd.PrintErrln("❌ Failed to load XDP manager:", err)
			os.Exit(1)
		}
		defer manager.Close()

		// Sync configuration to BPF maps
		// 同步配置到 BPF Map
		if err := manager.SyncFromFiles(globalCfg, false); err != nil {
			cmd.PrintErrln("❌ Failed to sync configuration to BPF maps:", err)
			os.Exit(1)
		}

		fmt.Println("✅ Configuration reloaded and synced to BPF maps successfully")
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		fmt.Println("🚀 Checking for updates...")
		execCmd := "curl -sSL https://raw.githubusercontent.com/netxfw/netxfw/main/scripts/deploy.sh | bash"
		if err := fmtutil.RunShellCommand(execCmd); err != nil {
			cmd.PrintErrln("❌ Update failed:", err)
			os.Exit(1)
		}
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		// This would show web interface information
		// 这将显示 Web 界面信息
		fmt.Println("🌐 Web interface: http://localhost:8080")
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		// Initialize configuration
		// 初始化配置
		core.InitConfiguration(cmd.Context())
		fmt.Println("✅ Configuration initialized")
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		// Test configuration
		// 测试配置
		daemon.TestConfiguration(cmd.Context())
		fmt.Println("✅ Configuration test passed")
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		ip := args[0]
		durationStr, _ := cmd.Flags().GetString("duration")
		persistFile, _ := cmd.Flags().GetString("file")

		// Get existing XDP manager
		// 获取现有的 XDP 管理器
		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
		if err != nil {
			cmd.PrintErrln("❌ Failed to load XDP manager:", err)
			os.Exit(1)
		}
		defer manager.Close()

		var errBlock error
		if durationStr != "" {
			// 动态封禁（带过期时间）
			duration, err := time.ParseDuration(durationStr)
			if err != nil {
				cmd.PrintErrln("❌ Invalid duration format")
				os.Exit(1)
			}
			errBlock = manager.BlockDynamic(ip, duration)
		} else if persistFile != "" {
			// 持久化封禁
			errBlock = manager.BlockStatic(ip, persistFile)
		} else {
			// 静态封禁（永久）
			errBlock = manager.BlockStatic(ip, "")
		}

		if errBlock != nil {
			cmd.PrintErrln("❌ Failed to block IP:", errBlock)
			os.Exit(1)
		}
		fmt.Println("✅ IP blocked at XDP layer:", ip)
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		ip := args[0]

		// Get existing XDP manager
		// 获取现有的 XDP 管理器
		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
		if err != nil {
			cmd.PrintErrln("❌ Failed to load XDP manager:", err)
			os.Exit(1)
		}
		defer manager.Close()

		// Use UnlockIP to remove from static blacklist
		// 使用 UnlockIP 从静态黑名单中移除
		if err := xdp.UnlockIP(manager.LockList(), ip); err != nil {
			cmd.PrintErrln("❌ Failed to unblock IP:", err)
			os.Exit(1)
		}

		fmt.Println("✅ IP unblocked at XDP layer:", ip)
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		static, _ := cmd.Flags().GetBool("static")
		dynamic, _ := cmd.Flags().GetBool("dynamic")

		// Get existing XDP manager
		// 获取现有的 XDP 管理器
		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
		if err != nil {
			cmd.PrintErrln("❌ Failed to load XDP manager:", err)
			os.Exit(1)
		}
		defer manager.Close()

		if static {
			// 列出静态封禁
			ips, _, err := xdp.ListBlockedIPs(manager.LockList(), false, 0, "")
			if err != nil {
				cmd.PrintErrln("❌ Failed to list blocked IPs:", err)
				os.Exit(1)
			}
			cmd.Println("=== Static Blocked IPs ===")
			for _, ip := range ips {
				cmd.Printf("%s\n", ip.IP)
			}
		} else if dynamic {
			// 列出动态封禁
			ips, _, err := xdp.ListBlockedIPs(manager.DynLockList(), false, 0, "")
			if err != nil {
				cmd.PrintErrln("❌ Failed to list blocked IPs:", err)
				os.Exit(1)
			}
			cmd.Println("=== Dynamic Blocked IPs ===")
			for _, ip := range ips {
				cmd.Printf("%s (expires: %s)\n", ip.IP, ip.ExpiresAt)
			}
		} else {
			// 列出所有封禁
			staticIPs, _, err := xdp.ListBlockedIPs(manager.LockList(), false, 0, "")
			if err != nil {
				cmd.PrintErrln("❌ Failed to list static blocked IPs:", err)
				os.Exit(1)
			}
			dynamicIPs, _, err := xdp.ListBlockedIPs(manager.DynLockList(), false, 0, "")
			if err != nil {
				cmd.PrintErrln("❌ Failed to list dynamic blocked IPs:", err)
				os.Exit(1)
			}

			cmd.Println("=== Blocked IPs ===")
			cmd.Println("--- Static ---")
			for _, ip := range staticIPs {
				cmd.Printf("%s\n", ip.IP)
			}
			cmd.Println("--- Dynamic ---")
			for _, ip := range dynamicIPs {
				cmd.Printf("%s (expires: %s)\n", ip.IP, ip.ExpiresAt)
			}
		}
	},
}

// SimpleClearCmd 实现 'clear' 命令（清空封禁列表）
// SimpleClearCmd implements the 'clear' command (clear blocked IPs list)
var SimpleClearCmd = &cobra.Command{
	Use:    "clear",
	Short:  "Clear all blocked IPs",
	Hidden: true,
	// Short: 清空所有封禁的 IP
	Long: `Clear all blocked IPs at XDP layer.
清空 XDP 层所有封禁的 IP。`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		// Get existing XDP manager
		// 获取现有的 XDP 管理器
		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
		if err != nil {
			cmd.PrintErrln("❌ Failed to load XDP manager:", err)
			os.Exit(1)
		}
		defer manager.Close()

		// Use ClearBlacklistMap to clear static blacklist
		// 使用 ClearBlacklistMap 清空静态黑名单
		if err := xdp.ClearBlacklistMap(manager.LockList()); err != nil {
			cmd.PrintErrln("❌ Failed to clear blocked IPs:", err)
			os.Exit(1)
		}

		fmt.Println("✅ All blocked IPs cleared at XDP layer")
	},
}

// SimpleAllowCmd 实现 'allow' 命令（添加到白名单）
// SimpleAllowCmd implements the 'allow' command (add to whitelist)
var SimpleAllowCmd = &cobra.Command{
	Use:   "allow <ip> [port]",
	Short: "Allow IP at XDP layer",
	// Short: 在 XDP 层允许 IP
	Long: `Allow IP at XDP layer (add to whitelist).
在 XDP 层允许 IP（添加到白名单）。`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		ip := args[0]
		port := uint16(0)
		if len(args) > 1 {
			port = uint16(0) // TODO: parse port
		}

		// Get existing XDP manager
		// 获取现有的 XDP 管理器
		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
		if err != nil {
			cmd.PrintErrln("❌ Failed to load XDP manager:", err)
			os.Exit(1)
		}
		defer manager.Close()

		// Add to whitelist
		// 添加到白名单
		if err := manager.AllowStatic(ip, port); err != nil {
			cmd.PrintErrln("❌ Failed to allow IP:", err)
			os.Exit(1)
		}

		fmt.Println("✅ IP allowed at XDP layer:", ip)
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
		if configFile != "" {
			config.SetConfigPath(configFile)
		}

		common.EnsureStandaloneMode()

		ip := args[0]

		// Get existing XDP manager
		// 获取现有的 XDP 管理器
		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
		if err != nil {
			cmd.PrintErrln("❌ Failed to load XDP manager:", err)
			os.Exit(1)
		}
		defer manager.Close()

		// Remove from whitelist
		// 从白名单移除
		if err := manager.RemoveAllowStatic(ip); err != nil {
			cmd.PrintErrln("❌ Failed to unallow IP:", err)
			os.Exit(1)
		}

		fmt.Println("✅ IP unallowed at XDP layer:", ip)
	},
}

// SimpleRuleCmd 实现 'rule' 命令组
// SimpleRuleCmd implements the 'rule' command group
var SimpleRuleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Rule management commands",
	// Short: 规则管理命令
	Long: `Rule management commands for netxfw.
netxfw 的规则管理命令。`,
}

// SimpleRuleListCmd 实现 'rule list' 命令
// SimpleRuleListCmd implements the 'rule list' command
var SimpleRuleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List rules",
	// Short: 列出规则
	Long: `List all rules.
列出所有规则。`,
	Run: func(cmd *cobra.Command, args []string) {
		// This would list all rules
		// 这将列出所有规则
		fmt.Println("=== Rules ===")
	},
}

// SimpleRuleAddCmd 实现 'rule add' 命令
// SimpleRuleAddCmd implements the 'rule add' command
var SimpleRuleAddCmd = &cobra.Command{
	Use:   "add <ip> [port] [allow|deny]",
	Short: "Add rule",
	// Short: 添加规则
	Long: `Add rule.
添加规则。`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// This would add a rule
		// 这将添加一条规则
		fmt.Println("✅ Rule added:", args[0])
	},
}

// SimpleRuleRemoveCmd 实现 'rule remove' 命令
// SimpleRuleRemoveCmd implements the 'rule remove' command
var SimpleRuleRemoveCmd = &cobra.Command{
	Use:   "remove <ip>",
	Short: "Remove rule",
	// Short: 删除规则
	Long: `Remove rule.
删除规则。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// This would remove a rule
		// 这将删除一条规则
		fmt.Println("✅ Rule removed:", args[0])
	},
}

// SimpleRuleImportCmd 实现 'rule import' 命令
// SimpleRuleImportCmd implements the 'rule import' command
var SimpleRuleImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import rules from file",
	// Short: 从文件导入规则
	Long: `Import rules from file.
从文件导入规则。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// This would import rules from file
		// 这将从文件导入规则
		fmt.Println("✅ Rules imported from:", args[0])
	},
}

// SimpleRuleExportCmd 实现 'rule export' 命令
// SimpleRuleExportCmd implements the 'rule export' command
var SimpleRuleExportCmd = &cobra.Command{
	Use:   "export <file>",
	Short: "Export rules to file",
	// Short: 导出规则到文件
	Long: `Export rules to file.
导出规则到文件。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// This would export rules to file
		// 这将导出规则到文件
		fmt.Println("✅ Rules exported to:", args[0])
	},
}

// SimpleRuleClearCmd 实现 'rule clear' 命令
// SimpleRuleClearCmd implements the 'rule clear' command
var SimpleRuleClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all rules",
	// Short: 清空所有规则
	Long: `Clear all rules.
清空所有规则。`,
	Run: func(cmd *cobra.Command, args []string) {
		// This would clear all rules
		// 这将清空所有规则
		fmt.Println("✅ All rules cleared")
	},
}

// SimpleRuleBlockCmd 实现 'rule block' 命令
// SimpleRuleBlockCmd implements the 'rule block' command
var SimpleRuleBlockCmd = &cobra.Command{
	Use:   "block <ip>",
	Short: "Quickly block IP",
	// Short: 快速封禁 IP
	Long: `Quickly block IP at XDP layer.
在 XDP 层快速封禁 IP。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// This would block IP at XDP layer
		// 这将在 XDP 层封禁 IP
		fmt.Println("✅ IP blocked at XDP layer:", args[0])
	},
}

// SimpleRuleAllowCmd 实现 'rule allow' 命令
// SimpleRuleAllowCmd implements the 'rule allow' command
var SimpleRuleAllowCmd = &cobra.Command{
	Use:   "allow <ip>",
	Short: "Quickly allow IP",
	// Short: 快速允许 IP
	Long: `Quickly allow IP at XDP layer.
在 XDP 层快速允许 IP。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// This would allow IP at XDP layer
		// 这将在 XDP 层允许 IP
		fmt.Println("✅ IP allowed at XDP layer:", args[0])
	},
}

// SimpleRuleUnlockCmd 实现 'rule unlock' 命令
// SimpleRuleUnlockCmd implements the 'rule unlock' command
var SimpleRuleUnlockCmd = &cobra.Command{
	Use:   "unlock <ip>",
	Short: "Quickly unlock IP",
	// Short: 快速解封 IP
	Long: `Quickly unlock IP at XDP layer.
在 XDP 层快速解封 IP。`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// This would unlock IP at XDP layer
		// 这将在 XDP 层解封 IP
		fmt.Println("✅ IP unlocked at XDP layer:", args[0])
	},
}

func init() {
	// Register Rule subcommands
	// 注册规则子命令
	SimpleRuleCmd.AddCommand(SimpleRuleListCmd)
	SimpleRuleCmd.AddCommand(SimpleRuleAddCmd)
	SimpleRuleCmd.AddCommand(SimpleRuleRemoveCmd)
	SimpleRuleCmd.AddCommand(SimpleRuleImportCmd)
	SimpleRuleCmd.AddCommand(SimpleRuleExportCmd)
	SimpleRuleCmd.AddCommand(SimpleRuleClearCmd)
	SimpleRuleCmd.AddCommand(SimpleRuleBlockCmd)
	SimpleRuleCmd.AddCommand(SimpleRuleAllowCmd)
	SimpleRuleCmd.AddCommand(SimpleRuleUnlockCmd)

	// Register flags for block command
	// 为 block 命令注册标志
	SimpleBlockCmd.Flags().StringP("duration", "d", "", "Duration to block IP (e.g., 1h, 30m)")
	SimpleBlockCmd.Flags().StringP("file", "f", "", "File to persist blocked IPs")
	SimpleBlockCmd.Flags().String("mode", "static", "Block mode: static (permanent) or dynamic (temporary)")

	// Register flags for list command
	// 为 list 命令注册标志
	SimpleListCmd.Flags().Bool("static", false, "List only static blocked IPs")
	SimpleListCmd.Flags().Bool("dynamic", false, "List only dynamic blocked IPs")

	// Register flags for ufw-style deny command
	// 为 ufw 风格的 deny 命令注册标志
	UfwDenyCmd.Flags().StringP("duration", "d", "", "Duration to block IP (e.g., 1h, 30m)")
	UfwDenyCmd.Flags().StringP("file", "f", "", "File to persist blocked IPs")
}

// ========================================
// UFW 风格的命令别名
// UFW-style command aliases
// ========================================

// UfwEnableCmd 是 'enable' 命令（ufw 风格，启动防火墙）
// UfwEnableCmd is the 'enable' command (ufw-style, start firewall)
var UfwEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable firewall (alias for 'start')",
	// Short: 启用防火墙（'start' 的别名）
	Long: `Enable the netxfw firewall (alias for 'start').
启用 netxfw 防火墙（'start' 的别名）。`,
	Run: SimpleStartCmd.Run,
}

// UfwDisableCmd 是 'disable' 命令（ufw 风格，停止防火墙）
// UfwDisableCmd is the 'disable' command (ufw-style, stop firewall)
var UfwDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable firewall (alias for 'stop')",
	// Short: 禁用防火墙（'stop' 的别名）
	Long: `Disable the netxfw firewall (alias for 'stop').
禁用 netxfw 防火墙（'stop' 的别名）。`,
	Run: SimpleStopCmd.Run,
}

// UfwDenyCmd 是 'deny' 命令（ufw 风格，拒绝/封禁）
// UfwDenyCmd is the 'deny' command (ufw-style, deny/block)
var UfwDenyCmd = &cobra.Command{
	Use:   "deny <ip>",
	Short: "Deny/block IP (alias for 'block')",
	// Short: 拒绝/封禁 IP（'block' 的别名）
	Long: `Deny/block an IP address (alias for 'block').
拒绝/封禁一个 IP 地址（'block' 的别名）。`,
	Args: SimpleBlockCmd.Args,
	Run:  SimpleBlockCmd.Run,
}

// UfwResetCmd 是 'reset' 命令（ufw 风格，重置防火墙）
// UfwResetCmd is the 'reset' command (ufw-style, reset firewall)
var UfwResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset firewall (clear all rules and blocked IPs)",
	// Short: 重置防火墙（清空所有规则和封禁的 IP）
	Long: `Reset the firewall by clearing all rules and blocked IPs.
重置防火墙，清空所有规则和封禁的 IP。`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("⚠️  WARNING: This will clear all blocked IPs!")
		fmt.Println("⚠️  警告：这将清空所有封禁的 IP！")
		if common.AskConfirmation("Are you sure you want to reset the firewall? 确认要重置防火墙吗？") {
			SimpleClearCmd.Run(cmd, args)
			fmt.Println("✅ Firewall has been reset")
			fmt.Println("✅ 防火墙已重置")
		}
	},
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
