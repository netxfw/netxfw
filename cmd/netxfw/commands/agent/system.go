package agent

import (
	"context"
	"fmt"
	"os"
	"sort"
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
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var SystemCmd = &cobra.Command{
	Use:   "system",
	Short: "System management commands",
	// Short: 系统管理命令
	Long: `System management commands for netxfw`,
	// Long: netxfw 的系统管理命令
}

// initCommand 初始化命令的通用设置（设置配置文件路径和确保独立模式）
// initCommand initializes common settings for commands (sets config path and ensures standalone mode)
func initCommand(cmd *cobra.Command) {
	configFile, _ := cmd.Flags().GetString("config")
	if configFile != "" {
		config.SetConfigPath(configFile)
	}
	common.EnsureStandaloneMode()
}

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	// Short: 初始化配置文件
	Long: `Initialize default configuration file in /root/netxfw/`,
	// Long: 在 /root/netxfw/ 中初始化默认配置文件
	Run: func(cmd *cobra.Command, args []string) {
		initCommand(cmd)
		core.InitConfiguration(cmd.Context())
	},
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show runtime status and statistics",
	// Short: 显示运行时状态和统计信息
	Long: `Show current runtime status and statistics`,
	// Long: 显示当前的运行时状态和统计信息
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			// Show system status
			// 显示系统状态
			return showStatus(cmd.Context(), s)
		})
	},
}

var systemTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration validity",
	// Short: 测试配置有效性
	Long: `Test configuration validity`,
	// Long: 测试配置有效性
	Run: func(cmd *cobra.Command, args []string) {
		initCommand(cmd)
		daemon.TestConfiguration(cmd.Context())
	},
}

var systemDaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background process",
	// Short: 启动后台进程
	Long: `Start background process`,
	// Long: 启动后台进程
	Run: func(cmd *cobra.Command, args []string) {
		initCommand(cmd)
		app.RunDaemon(cmd.Context())
	},
}

var interfaces []string

var systemLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load XDP driver",
	// Short: 加载 XDP 驱动
	Long: `Load XDP driver`,
	// Long: 加载 XDP 驱动
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		if err := app.InstallXDP(cmd.Context(), interfaces); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

var systemUnloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Unload XDP driver",
	// Short: 卸载 XDP 驱动
	Long: `Unload XDP driver`,
	// Long: 卸载 XDP 驱动
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		if err := app.RemoveXDP(cmd.Context(), interfaces); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

var systemReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload configuration and sync to BPF maps",
	// Short: 重载配置并同步到 BPF Map
	Long: `Reload configuration and sync to BPF maps: reads configuration from files and updates BPF maps without reloading XDP program.
This is faster than full reload and maintains existing connections.
重载配置并同步到 BPF Map：从文件读取配置并更新 BPF Map，而不重新加载 XDP 程序。
这比完全重载更快，并且保持现有连接。`,
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		// Load configuration
		// 加载配置
		configPath := runtime.ConfigPath
		if configPath == "" {
			configPath = config.DefaultConfigPath
		}

		globalCfg, err := types.LoadGlobalConfig(configPath)
		if err != nil {
			cmd.PrintErrln("[ERROR] Failed to load configuration:", err)
			os.Exit(1)
		}

		// Get existing XDP manager
		// 获取现有的 XDP 管理器
		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
		if err != nil {
			cmd.PrintErrln("[ERROR] Failed to load XDP manager:", err)
			os.Exit(1)
		}
		defer manager.Close()

		// Sync configuration to BPF maps
		// 同步配置到 BPF Map
		if err := manager.SyncFromFiles(globalCfg, false); err != nil {
			cmd.PrintErrln("[ERROR] Failed to sync configuration to BPF maps:", err)
			os.Exit(1)
		}

		fmt.Println("[OK] Configuration reloaded and synced to BPF maps successfully")
	},
}

// systemOnCmd is an alias for systemLoadCmd
// systemOnCmd 是 systemLoadCmd 的别名
var systemOnCmd = &cobra.Command{
	Use:   "on [interface...]",
	Short: "Load XDP driver (alias for 'load')",
	// Short: 加载 XDP 驱动（load 的别名）
	Long: `Load XDP driver. This is an alias for 'system load'.

Examples:
  netxfw system on              # Load with default interfaces from config
  netxfw system on eth0         # Load on eth0
  netxfw system on eth0 eth1    # Load on multiple interfaces`,
	// Long: 加载 XDP 驱动。这是 'system load' 的别名。
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		// Use positional args as interfaces if provided
		// 如果提供了位置参数，使用它们作为接口
		ifaceList := interfaces
		if len(args) > 0 {
			ifaceList = args
		}

		if err := app.InstallXDP(cmd.Context(), ifaceList); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

// systemOffCmd is an alias for systemUnloadCmd
// systemOffCmd 是 systemUnloadCmd 的别名
var systemOffCmd = &cobra.Command{
	Use:   "off [interface...]",
	Short: "Unload XDP driver (alias for 'unload')",
	// Short: 卸载 XDP 驱动（unload 的别名）
	Long: `Unload XDP driver. This is an alias for 'system unload'.

Examples:
  netxfw system off              # Unload from all interfaces
  netxfw system off eth0         # Unload from eth0
  netxfw system off eth0 eth1    # Unload from multiple interfaces`,
	// Long: 卸载 XDP 驱动。这是 'system unload' 的别名。
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		// Use positional args as interfaces if provided
		// 如果提供了位置参数，使用它们作为接口
		ifaceList := interfaces
		if len(args) > 0 {
			ifaceList = args
		}

		if err := app.RemoveXDP(cmd.Context(), ifaceList); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

var systemUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check and install updates",
	// Short: 检查并安装更新
	Long: `Check for the latest version on GitHub and install it.
This will restart the netxfw service if an update is performed.`,
	// Long: 检查 GitHub 上的最新版本并安装。如果执行了更新，将重新启动 netxfw 服务。
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[START] Checking for updates...")
		// Execute the deploy.sh script from GitHub
		// This is a simple and effective way to update
		execCmd := "curl -sSL https://raw.githubusercontent.com/netxfw/netxfw/main/scripts/deploy.sh | bash"
		if err := fmtutil.RunShellCommand(execCmd); err != nil {
			fmt.Printf("[ERROR] Update failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	SystemCmd.AddCommand(systemInitCmd)
	SystemCmd.AddCommand(systemStatusCmd)
	SystemCmd.AddCommand(systemTestCmd)
	SystemCmd.AddCommand(systemDaemonCmd)
	SystemCmd.AddCommand(systemUpdateCmd)

	systemLoadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to attach XDP to")
	SystemCmd.AddCommand(systemLoadCmd)

	systemUnloadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to detach XDP from")
	SystemCmd.AddCommand(systemUnloadCmd)

	systemReloadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to attach XDP to")
	SystemCmd.AddCommand(systemReloadCmd)

	// Add on/off aliases
	// 添加 on/off 别名
	SystemCmd.AddCommand(systemOnCmd)
	SystemCmd.AddCommand(systemOffCmd)

	RegisterCommonFlags(systemInitCmd)
	RegisterCommonFlags(systemStatusCmd)
	RegisterCommonFlags(systemTestCmd)
	RegisterCommonFlags(systemDaemonCmd)
	RegisterCommonFlags(systemUpdateCmd)
	RegisterCommonFlags(systemOnCmd)
	RegisterCommonFlags(systemOffCmd)
}

// showStatus displays the system status including statistics and configuration
// showStatus 显示系统状态，包括统计信息和配置
func showStatus(ctx context.Context, s *sdk.SDK) error {
	fmt.Println("[OK] XDP Program Status: Loaded and Running")

	mgr := s.GetManager()

	// Get global stats
	// 获取全局统计
	pass, drops, err := s.Stats.GetCounters()
	if err != nil {
		fmt.Printf("[WARN]  Could not retrieve statistics: %v\n", err)
		return nil
	}

	// Show traffic metrics (PPS/BPS)
	// 显示流量指标 (PPS/BPS)
	showTrafficMetrics(pass, drops)

	// Show drop statistics
	// 显示丢弃统计
	showDropStatistics(s.Stats, drops, pass)

	// Show pass statistics
	// 显示通过统计
	showPassStatistics(s.Stats, pass, drops)

	// Show conntrack health
	// 显示连接跟踪健康度
	showConntrackHealth(mgr)

	// Map statistics
	// Map 统计
	showMapStatistics(mgr)

	// Show protocol distribution
	// 显示协议分布
	showProtocolDistribution(s.Stats, pass, drops)

	// Load configuration for policy display
	// 加载配置以显示策略
	showPolicyConfiguration()

	// Show attached interfaces
	// 显示已附加的接口
	showAttachedInterfaces()

	// Show conclusion statistics
	// 显示结论统计
	showConclusionStatistics(mgr, s.Stats)

	return nil
}

// StatsAPI interface for statistics operations (for testing and decoupling)
// StatsAPI 统计操作接口（用于测试和解耦）
type StatsAPI interface {
	GetDropDetails() ([]sdk.DropDetailEntry, error)
	GetPassDetails() ([]sdk.DropDetailEntry, error)
}

// showDropStatistics 显示带百分比的丢弃统计
func showDropStatistics(s StatsAPI, drops, pass uint64) {
	// Load traffic stats for rate calculation / 加载流量统计用于速率计算
	trafficStats, err := xdp.LoadTrafficStats()
	var currentDropPPS uint64
	if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
		currentDropPPS = trafficStats.CurrentDropPPS
	}

	// Show detailed drop stats
	// 显示详细丢弃统计
	dropDetails, err := s.GetDropDetails()
	if err != nil || len(dropDetails) == 0 {
		// No drop details available / 没有可用的丢弃详情
		return
	}

	// Wrap drop details for generic function / 包装丢弃详情用于泛型函数
	wrappedDetails := make([]DropDetailEntryWrapper, len(dropDetails))
	for i, d := range dropDetails {
		wrappedDetails[i] = DropDetailEntryWrapper{d}
	}

	// Use generic function to display statistics / 使用泛型函数显示统计
	showDetailStatistics(wrappedDetails, detailStatsConfig{
		title:      "[BLOCK] Drop Statistics:",
		subTitle:   "[BLOCK] Top Drops by Reason & Source:",
		reasonFunc: dropReasonToString,
		totalCount: drops,
		currentPPS: currentDropPPS,
		showRate:   true,
	})
}

// showPassStatistics displays pass statistics with percentages
// showPassStatistics 显示带百分比的通过统计
func showPassStatistics(s StatsAPI, pass, drops uint64) {
	// Load traffic stats for rate calculation / 加载流量统计用于速率计算
	trafficStats, err := xdp.LoadTrafficStats()
	var currentPassPPS uint64
	if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
		currentPassPPS = trafficStats.CurrentPassPPS
	}

	// Show detailed pass stats
	// 显示详细通过统计
	passDetails, err := s.GetPassDetails()
	if err != nil || len(passDetails) == 0 {
		// No pass details available / 没有可用的通过详情
		return
	}

	// Wrap pass details for generic function / 包装通过详情用于泛型函数
	wrappedDetails := make([]PassDetailEntryWrapper, len(passDetails))
	for i, d := range passDetails {
		wrappedDetails[i] = PassDetailEntryWrapper{d}
	}

	// Use generic function to display statistics / 使用泛型函数显示统计
	showDetailStatistics(wrappedDetails, detailStatsConfig{
		title:      "[OK] Pass Statistics:",
		subTitle:   "[OK] Top Allowed by Reason & Source:",
		reasonFunc: passReasonToString,
		totalCount: pass,
		currentPPS: currentPassPPS,
		showRate:   true,
	})
}

// showMapStatistics displays BPF map statistics
// showMapStatistics 显示 BPF Map 统计和使用率
func showMapStatistics(mgr sdk.ManagerInterface) {
	fmt.Println()
	fmt.Println("[DATA] Map Statistics:")

	// Get capacity configuration from config manager / 从配置管理器获取容量配置
	cfgManager := config.GetConfigManager()
	var capacityCfg *types.CapacityConfig
	if err := cfgManager.LoadConfig(); err == nil {
		capacityCfg = cfgManager.GetCapacityConfig()
	}

	// Get map counts / 获取 Map 计数
	blacklistCount, _ := mgr.GetLockedIPCount()
	whitelistCount, _ := mgr.GetWhitelistCount()
	dynBlacklistCount, _ := mgr.GetDynLockListCount()

	// Get rate limit rules / 获取限速规则
	rateLimitRules, _, _ := mgr.ListRateLimitRules(0, "")

	// Get IP+Port rules / 获取 IP+端口规则
	ipPortRules, _, _ := mgr.ListIPPortRules(false, 0, "")

	// Get allowed ports / 获取允许端口
	allowedPorts, _ := mgr.ListAllowedPorts()

	// Get max capacities from config or use defaults from CapacityConfig
	// 从配置获取最大容量或使用 CapacityConfig 默认值
	maxBlacklist := 2000000
	maxWhitelist := 65536
	maxDynBlacklist := 2000000
	maxIPPortRules := 65536
	maxRateLimits := 1000

	if capacityCfg != nil {
		if capacityCfg.LockList > 0 {
			maxBlacklist = capacityCfg.LockList
		}
		if capacityCfg.Whitelist > 0 {
			maxWhitelist = capacityCfg.Whitelist
		}
		if capacityCfg.DynLockList > 0 {
			maxDynBlacklist = capacityCfg.DynLockList
		}
		if capacityCfg.IPPortRules > 0 {
			maxIPPortRules = capacityCfg.IPPortRules
		}
		if capacityCfg.RateLimits > 0 {
			maxRateLimits = capacityCfg.RateLimits
		}
	}

	// Show compact table with progress bar / 显示带进度条的紧凑表格
	fmt.Printf("   %-18s %12s / %-12s %s\n", "Map", "Used", "Max", "Usage")
	fmt.Printf("   %s\n", strings.Repeat("-", 70))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[LOCK] Blacklist", blacklistCount, maxBlacklist,
		renderUsageBar(blacklistCount, maxBlacklist, 20))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[UNLOCK] Dyn Blacklist", dynBlacklistCount, maxDynBlacklist,
		renderUsageBar(int(dynBlacklistCount), maxDynBlacklist, 20))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[WHITE] Whitelist", whitelistCount, maxWhitelist,
		renderUsageBar(whitelistCount, maxWhitelist, 20))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[INFO] IP+Port Rules", len(ipPortRules), maxIPPortRules,
		renderUsageBar(len(ipPortRules), maxIPPortRules, 20))
	fmt.Printf("   %-18s %12d / %-12d %s\n",
		"[TIME]  Rate Limits", len(rateLimitRules), maxRateLimits,
		renderUsageBar(len(rateLimitRules), maxRateLimits, 20))
	fmt.Printf("   %-18s %12d\n", "[UNLOCK] Allowed Ports", len(allowedPorts))
}

// renderUsageBar renders a visual progress bar like top command
// renderUsageBar 渲染类似 top 命令的可视化进度条
func renderUsageBar(current, maximum int, width int) string {
	if maximum == 0 {
		return "[ N/A ]"
	}

	usage := float64(current) / float64(maximum) * 100
	filled := int(usage / 100 * float64(width))
	if filled > width {
		filled = width
	}

	// Build progress bar / 构建进度条
	var bar strings.Builder
	bar.WriteString("[")
	for i := 0; i < width; i++ {
		if i < filled {
			bar.WriteString("#")
		} else {
			bar.WriteString("-")
		}
	}
	bar.WriteString("] ")

	// Add percentage and status indicator / 添加百分比和状态指示器
	critical, high, medium := getThresholdsFromConfig()
	var status string
	if usage >= float64(critical) {
		status = "[CRITICAL]"
	} else if usage >= float64(high) {
		status = "[HIGH]"
	} else if usage >= float64(medium) {
		status = "[MEDIUM]"
	} else {
		status = "[OK]"
	}

	return fmt.Sprintf("%s %5.1f%% %s", bar.String(), usage, status)
}

// showCompactMapStatistics displays compact map statistics in single line format
// showCompactMapStatistics 以紧凑格式显示 Map 统计
func showCompactMapStatistics(mgr sdk.ManagerInterface) {
	// Get capacity configuration from config manager / 从配置管理器获取容量配置
	cfgManager := config.GetConfigManager()
	var capacityCfg *types.CapacityConfig
	if err := cfgManager.LoadConfig(); err == nil {
		capacityCfg = cfgManager.GetCapacityConfig()
	}

	// Get map counts / 获取 Map 计数
	blacklistCount, _ := mgr.GetLockedIPCount()
	whitelistCount, _ := mgr.GetWhitelistCount()
	dynBlacklistCount, _ := mgr.GetDynLockListCount()
	rateLimitRules, _, _ := mgr.ListRateLimitRules(0, "")
	ipPortRules, _, _ := mgr.ListIPPortRules(false, 0, "")

	// Get max capacities / 获取最大容量
	maxBlacklist := 2000000
	maxWhitelist := 65536
	maxDynBlacklist := 2000000
	maxIPPortRules := 65536
	maxRateLimits := 1000

	if capacityCfg != nil {
		if capacityCfg.LockList > 0 {
			maxBlacklist = capacityCfg.LockList
		}
		if capacityCfg.Whitelist > 0 {
			maxWhitelist = capacityCfg.Whitelist
		}
		if capacityCfg.DynLockList > 0 {
			maxDynBlacklist = capacityCfg.DynLockList
		}
		if capacityCfg.IPPortRules > 0 {
			maxIPPortRules = capacityCfg.IPPortRules
		}
		if capacityCfg.RateLimits > 0 {
			maxRateLimits = capacityCfg.RateLimits
		}
	}

	// Show compact multi-line map stats / 显示紧凑的多行 Map 统计
	fmt.Println()
	fmt.Println("[DATA] Map Usage:")
	fmt.Printf("   %-16s %s\n", "[LOCK] Blacklist:", renderMiniBar(blacklistCount, maxBlacklist))
	fmt.Printf("   %-16s %s\n", "[UNLOCK] Dyn:", renderMiniBar(int(dynBlacklistCount), maxDynBlacklist))
	fmt.Printf("   %-16s %s\n", "[WHITE] Whitelist:", renderMiniBar(whitelistCount, maxWhitelist))
	fmt.Printf("   %-16s %s\n", "[INFO] IP+Port:", renderMiniBar(len(ipPortRules), maxIPPortRules))
	fmt.Printf("   %-16s %s\n", "[TIME] RateLimit:", renderMiniBar(len(rateLimitRules), maxRateLimits))
}

// renderMiniBar renders a mini progress bar for compact display
// renderMiniBar 渲染用于紧凑显示的迷你进度条
func renderMiniBar(current, maximum int) string {
	if maximum == 0 {
		return "N/A"
	}

	usage := float64(current) / float64(maximum) * 100
	filled := int(usage / 100 * 10) // 10-char mini bar
	if filled > 10 {
		filled = 10
	}

	var bar strings.Builder
	for i := 0; i < 10; i++ {
		if i < filled {
			bar.WriteString("#")
		} else {
			bar.WriteString("-")
		}
	}

	return fmt.Sprintf("[%s] %d/%d", bar.String(), current, maximum)
}

// showTopBlockedIPs displays top blocked attacker IPs
// showTopBlockedIPs 显示被拦截最多的攻击 IP
func showTopBlockedIPs(s StatsAPI, drops uint64) {
	if drops == 0 {
		return
	}

	dropDetails, err := s.GetDropDetails()
	if err != nil || len(dropDetails) == 0 {
		return
	}

	// Aggregate by source IP / 按源 IP 聚合
	ipCounts := make(map[string]uint64)
	for _, d := range dropDetails {
		ipCounts[d.SrcIP] += d.Count
	}

	// Sort by count / 按计数排序
	type ipCount struct {
		ip    string
		count uint64
	}
	var sorted []ipCount
	for ip, count := range ipCounts {
		sorted = append(sorted, ipCount{ip, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	// Show top 3 attackers / 显示前 3 个攻击者
	if len(sorted) > 0 {
		fmt.Println()
		fmt.Println("[ALERT] Top Blocked Attackers:")
		maxShow := 3
		if len(sorted) < maxShow {
			maxShow = len(sorted)
		}
		for i := 0; i < maxShow; i++ {
			percent := float64(sorted[i].count) / float64(drops) * 100
			fmt.Printf("   %d. %s - %s drops (%.1f%%)\n", i+1, sorted[i].ip,
				fmtutil.FormatNumberWithComma(sorted[i].count), percent)
		}
	}
}

// showPolicyConfiguration displays policy configuration
// showPolicyConfiguration 显示策略配置
func showPolicyConfiguration() {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err != nil {
		return
	}

	cfg := cfgManager.GetConfig()
	if cfg == nil {
		return
	}

	fmt.Println()
	fmt.Println("[CONFIG]  Policy Configuration:")

	// Default deny policy
	// 默认拒绝策略
	if cfg.Base.DefaultDeny {
		fmt.Println("   ├─ [SHIELD]  Default Deny: Enabled (Deny by default)")
	} else {
		fmt.Println("   ├─ [SHIELD]  Default Deny: Disabled (Allow by default)")
	}

	// Return traffic
	// 回程流量
	if cfg.Base.AllowReturnTraffic {
		fmt.Println("   ├─ [RELOAD] Allow Return Traffic: Enabled")
	} else {
		fmt.Println("   ├─ [RELOAD] Allow Return Traffic: Disabled")
	}

	// ICMP
	// ICMP
	if cfg.Base.AllowICMP {
		fmt.Println("   ├─ [PING] Allow ICMP (Ping): Enabled")
	} else {
		fmt.Println("   ├─ [PING] Allow ICMP (Ping): Disabled")
	}

	// Strict TCP
	// 严格 TCP
	if cfg.Base.StrictTCP {
		fmt.Println("   ├─ [LOCK] Strict TCP: Enabled")
	} else {
		fmt.Println("   ├─ [LOCK] Strict TCP: Disabled")
	}

	// SYN Limit
	// SYN 限制
	if cfg.Base.SYNLimit {
		fmt.Println("   ├─ [PROTECT] SYN Flood Protection: Enabled")
	} else {
		fmt.Println("   ├─ [PROTECT] SYN Flood Protection: Disabled")
	}

	// Bogon Filter
	// Bogon 过滤
	if cfg.Base.BogonFilter {
		fmt.Println("   ├─ [WEB] Bogon Filter: Enabled")
	} else {
		fmt.Println("   ├─ [WEB] Bogon Filter: Disabled")
	}

	// Connection tracking
	// 连接跟踪
	if cfg.Conntrack.Enabled {
		fmt.Println("   ├─ [TRACK]  Connection Tracking: Enabled")
		if cfg.Conntrack.TCPTimeout != "" {
			fmt.Printf("   │     └─ TCP Timeout: %s\n", cfg.Conntrack.TCPTimeout)
		}
		if cfg.Conntrack.UDPTimeout != "" {
			fmt.Printf("   │     └─ UDP Timeout: %s\n", cfg.Conntrack.UDPTimeout)
		}
	} else {
		fmt.Println("   ├─ [TRACK]  Connection Tracking: Disabled")
	}

	// Rate limiting
	// 速率限制
	if cfg.RateLimit.Enabled {
		fmt.Println("   ├─ [START] Rate Limiting: Enabled")
		if cfg.RateLimit.AutoBlock {
			fmt.Printf("   │     └─ Auto Block: Enabled (Expiry: %s)\n", cfg.RateLimit.AutoBlockExpiry)
		}
	} else {
		fmt.Println("   ├─ [START] Rate Limiting: Disabled")
	}

	// Log Engine
	// 日志引擎
	if cfg.LogEngine.Enabled {
		fmt.Printf("   ├─ [LOG] Log Engine: Enabled (%d rules)\n", len(cfg.LogEngine.Rules))
	} else {
		fmt.Println("   ├─ [LOG] Log Engine: Disabled")
	}

	// Web Interface
	// Web 界面
	if cfg.Web.Enabled {
		fmt.Printf("   └─ [WEB] Web Interface: Enabled (Port: %d)\n", cfg.Web.Port)
	} else {
		fmt.Println("   └─ [WEB] Web Interface: Disabled")
	}
}

// showAttachedInterfaces displays attached network interfaces
// showAttachedInterfaces 显示已附加的网络接口
func showAttachedInterfaces() {
	fmt.Println("\n[LINK] Attached Interfaces:")
	ifaceInfos, err := xdp.GetAttachedInterfacesWithInfo(config.GetPinPath())
	if err == nil && len(ifaceInfos) > 0 {
		for _, info := range ifaceInfos {
			// Format load time / 格式化加载时间
			loadTimeStr := "N/A"
			if !info.LoadTime.IsZero() {
				duration := time.Since(info.LoadTime)
				loadTimeStr = fmtutil.FormatDuration(duration)
			}
			fmt.Printf("  - %s (Mode: %s, ProgID: %d, Uptime: %s)\n", info.Name, info.Mode, info.ProgramID, loadTimeStr)
		}
	} else {
		fmt.Println("  - None")
	}
}

// showTrafficMetrics displays PPS/BPS traffic metrics
// showTrafficMetrics 显示 PPS/BPS 流量指标
func showTrafficMetrics(pass, drops uint64) {
	fmt.Println()
	fmt.Println("[RATE] Traffic Rate:")

	totalPackets := pass + drops

	// Show total counts first / 首先显示总计数
	fmt.Printf("   ├─ Total RX: %s packets\n", fmtutil.FormatNumberWithComma(totalPackets))
	fmt.Printf("   ├─ Total Pass: %s (%.2f%%)\n", fmtutil.FormatNumberWithComma(pass), calculatePercentGeneric(pass, totalPackets))
	fmt.Printf("   ├─ Total Drop: %s (%.2f%%)\n", fmtutil.FormatNumberWithComma(drops), calculatePercentGeneric(drops, totalPackets))

	// Try to load traffic stats from shared file (updated by daemon)
	// 尝试从共享文件加载流量统计（由守护进程更新）
	trafficStats, err := xdp.LoadTrafficStats()
	if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
		// We have valid traffic stats from daemon
		// 我们有来自守护进程的有效流量统计
		currentPPS := trafficStats.CurrentPPS
		currentBPS := trafficStats.CurrentBPS
		dropPPS := trafficStats.CurrentDropPPS
		passPPS := trafficStats.CurrentPassPPS

		if currentPPS > 0 || currentBPS > 0 {
			// Calculate rates / 计算比率
			var dropRate, passRate float64
			if currentPPS > 0 {
				dropRate = float64(dropPPS) / float64(currentPPS) * 100
				passRate = float64(passPPS) / float64(currentPPS) * 100
			}

			fmt.Printf("   ├─ PPS: %s pkt/s\n", fmtutil.FormatNumberWithComma(currentPPS))
			fmt.Printf("   ├─ BPS: %s\n", fmtutil.FormatBPS(currentBPS))
			fmt.Printf("   ├─ Pass PPS: %s pkt/s\n", fmtutil.FormatNumberWithComma(passPPS))
			fmt.Printf("   ├─ Pass Rate: %.2f%%\n", passRate)
			fmt.Printf("   ├─ Drop PPS: %s pkt/s\n", fmtutil.FormatNumberWithComma(dropPPS))
			fmt.Printf("   └─ Drop Rate: %.2f%%\n", dropRate)
			return
		}
	}

	fmt.Println("   └─ Real-time rates: Unavailable (daemon not running)")
}

// formatNumber formats a number with thousand separators
// formatNumber 格式化数字，添加千位分隔符
// showConntrackHealth displays conntrack health metrics
// showConntrackHealth 显示连接跟踪健康度指标
func showConntrackHealth(mgr sdk.ManagerInterface) {
	fmt.Println()
	fmt.Println("[TRACK]  Conntrack Health:")

	conntrackCount, err := mgr.GetConntrackCount()
	if err != nil {
		fmt.Println("   └─ Status: Unavailable")
		return
	}

	maxConntrack := getConntrackMax()

	// Get conntrack entries for protocol breakdown / 获取连接跟踪条目以进行协议分布
	entries, err := mgr.ListAllConntrackEntries()
	if err != nil {
		fmt.Printf("   ├─ Active Connections: %d / %d (%.1f%%)\n", conntrackCount, maxConntrack, calculatePercentGeneric(conntrackCount, uint64(maxConntrack))) // #nosec G115 // count is always valid
		fmt.Println("   └─ Protocol Breakdown: Unavailable")
		return
	}

	// Count by protocol / 按协议计数
	tcpCount, udpCount, icmpCount, otherCount := getConntrackProtocolStats(entries)

	fmt.Printf("   ├─ Active Connections: %d / %d (%.1f%%)\n", conntrackCount, maxConntrack, calculatePercentGeneric(conntrackCount, uint64(maxConntrack))) // #nosec G115 // count is always valid
	fmt.Printf("   ├─ TCP Connections: %d (%.1f%%)\n", tcpCount, calculatePercentGeneric(uint64(tcpCount), uint64(conntrackCount)))                         // #nosec G115 // count is always valid
	fmt.Printf("   ├─ UDP Connections: %d (%.1f%%)\n", udpCount, calculatePercentGeneric(uint64(udpCount), uint64(conntrackCount)))                         // #nosec G115 // count is always valid
	fmt.Printf("   ├─ ICMP Connections: %d (%.1f%%)\n", icmpCount, calculatePercentGeneric(uint64(icmpCount), uint64(conntrackCount)))                      // #nosec G115 // count is always valid

	// Try to load traffic stats for new/evict rates / 尝试加载流量统计获取新建/淘汰速率
	trafficStats, err := xdp.LoadTrafficStats()
	hasRateData := err == nil && trafficStats.LastUpdateTime.After(time.Time{})

	if hasRateData {
		fmt.Printf("   ├─ Other Connections: %d (%.1f%%)\n", otherCount, calculatePercentGeneric(uint64(otherCount), uint64(conntrackCount))) // #nosec G115 // count is always valid
		fmt.Printf("   ├─ New/s: %s conn/s\n", fmtutil.FormatNumberWithComma(trafficStats.CurrentConntrackNew))
	} else {
		fmt.Printf("   └─ Other Connections: %d (%.1f%%)\n", otherCount, calculatePercentGeneric(uint64(otherCount), uint64(conntrackCount))) // #nosec G115 // count is always valid
	}

	// Determine health status / 确定健康状态
	statusMsg := getConntrackHealthStatus(uint64(conntrackCount), uint64(maxConntrack), hasRateData, trafficStats)

	if hasRateData {
		fmt.Printf("   ├─ Evict/s: %s conn/s\n", fmtutil.FormatNumberWithComma(trafficStats.CurrentConntrackEvict))
		fmt.Printf("   └─ %s\n", statusMsg)
	} else {
		fmt.Printf("   └─ %s\n", statusMsg)
	}
}

// getConntrackMax returns max capacity for conntrack from config or default
func getConntrackMax() int {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err == nil {
		capacityCfg := cfgManager.GetCapacityConfig()
		if capacityCfg != nil && capacityCfg.Conntrack > 0 {
			return capacityCfg.Conntrack
		}
	}
	return 100000 // Default from CapacityConfig
}

// getConntrackProtocolStats counts connections by protocol
func getConntrackProtocolStats(entries []sdk.ConntrackEntry) (tcp, udp, icmp, other int) {
	for _, entry := range entries {
		switch entry.Protocol {
		case 6:
			tcp++
		case 17:
			udp++
		case 1:
			icmp++
		default:
			other++
		}
	}
	return
}

// getConntrackHealthStatus determines the health message for conntrack
func getConntrackHealthStatus(count uint64, maxVal uint64, hasRate bool, stats xdp.TrafficStats) string {
	usagePercent := calculatePercentGeneric(count, maxVal)
	critical, high, _ := getThresholdsFromConfig()

	// Conntrack is LRU
	if hasRate && stats.CurrentConntrackEvict > uint64(maxVal/10) {
		return "[WARN]  Status: STRESSED - High eviction rate"
	} else if usagePercent >= 99.9 {
		return "[OK] Status: Healthy (LRU Full)"
	} else if usagePercent >= float64(high) {
		return "[OK] Status: Healthy (LRU Warming up)"
	} else if usagePercent >= float64(critical) {
		return "[WARN]  Status: CRITICAL - Near capacity"
	} else if usagePercent >= float64(high) {
		return "[WARN]  Status: HIGH - Approaching capacity"
	}
	return "[OK] Status: Healthy"
}

// showProtocolDistribution displays protocol distribution statistics
// showProtocolDistribution 显示协议分布统计
func showProtocolDistribution(s StatsAPI, pass, drops uint64) {
	fmt.Println()
	fmt.Println("[PROTO] Protocol Distribution:")

	totalPackets := pass + drops

	// Get drop details for protocol analysis / 获取丢弃详情以进行协议分析
	dropDetails, err := s.GetDropDetails()
	if err != nil {
		fmt.Println("   └─ Status: Unavailable")
		return
	}

	// Get pass details / 获取通过详情
	passDetails, err := s.GetPassDetails()
	if err != nil {
		fmt.Println("   └─ Status: Unavailable")
		return
	}

	// Count by protocol / 按协议计数
	protoStats := make(map[uint8]struct {
		dropped uint64
		passed  uint64
	})

	for _, d := range dropDetails {
		stats := protoStats[d.Protocol]
		stats.dropped += d.Count
		protoStats[d.Protocol] = stats
	}

	for _, p := range passDetails {
		stats := protoStats[p.Protocol]
		stats.passed += p.Count
		protoStats[p.Protocol] = stats
	}

	// Show protocol breakdown / 显示协议分布
	if len(protoStats) > 0 {
		fmt.Printf("   %-10s %-15s %-15s %-10s\n", "Protocol", "Dropped", "Passed", "Percent")
		fmt.Printf("   %s\n", strings.Repeat("-", 50))

		// Convert to slice for sorting / 转换为切片以便排序
		type protoStat struct {
			proto   uint8
			dropped uint64
			passed  uint64
			total   uint64
		}
		var statsSlice []protoStat
		for proto, stats := range protoStats {
			statsSlice = append(statsSlice, protoStat{
				proto:   proto,
				dropped: stats.dropped,
				passed:  stats.passed,
				total:   stats.dropped + stats.passed,
			})
		}

		// Sort by total count descending / 按总数降序排序
		sort.Slice(statsSlice, func(i, j int) bool {
			return statsSlice[i].total > statsSlice[j].total
		})

		for _, s := range statsSlice {
			percent := calculatePercentGeneric(s.total, totalPackets)
			fmt.Printf("   %-10s %-15d %-15d %.1f%%\n",
				protocolToString(s.proto),
				s.dropped,
				s.passed,
				percent)
		}
	} else {
		fmt.Println("   └─ No protocol data available")
	}
}

// getUsageIndicator returns a visual indicator based on usage level
// getUsageIndicator 根据使用级别返回可视化指示器
func getUsageIndicator(current, maximum int, isLRU bool) string {
	if maximum == 0 {
		return ""
	}
	usage := float64(current) / float64(maximum) * 100
	critical, high, medium := getThresholdsFromConfig()

	if isLRU && usage >= 99.0 {
		return "[OK (LRU Full)]"
	}

	if usage >= float64(critical) {
		return "[CRITICAL]"
	} else if usage >= float64(high) {
		return "[HIGH] [HIGH]"
	} else if usage >= float64(medium) {
		return "[MEDIUM]"
	}
	return "[OK]"
}

// Numeric is a type constraint for numeric types that can be converted to float64.
// Numeric 是可以转换为 float64 的数值类型的类型约束。
type Numeric interface {
	~int | ~int64 | ~uint | ~uint64 | ~int32 | ~uint32 | ~float64
}

// calculatePercentGeneric calculates percentage safely using generics.
// calculatePercentGeneric 使用泛型安全地计算百分比。
func calculatePercentGeneric[T Numeric, U Numeric](part T, total U) float64 {
	t := float64(total)
	if t == 0 {
		return 0
	}
	return float64(part) / t * 100
}

// calculateRateGeneric calculates rate per second based on percentage.
// calculateRateGeneric 根据百分比计算每秒速率。
func calculateRateGeneric[T Numeric](totalRate T, percent float64) uint64 {
	return uint64(float64(totalRate) * percent / 100)
}

// DetailEntry is a generic interface for detail entries with common fields.
// DetailEntry 是具有公共字段的详细条目的泛型接口。
type DetailEntry interface {
	GetReason() uint32
	GetProtocol() uint8
	GetSrcIP() string
	GetDstPort() uint16
	GetCount() uint64
}

// DropDetailEntryWrapper wraps sdk.DropDetailEntry to implement DetailEntry.
// DropDetailEntryWrapper 包装 sdk.DropDetailEntry 以实现 DetailEntry。
type DropDetailEntryWrapper struct {
	sdk.DropDetailEntry
}

func (d DropDetailEntryWrapper) GetReason() uint32  { return d.Reason }
func (d DropDetailEntryWrapper) GetProtocol() uint8 { return d.Protocol }
func (d DropDetailEntryWrapper) GetSrcIP() string   { return d.SrcIP }
func (d DropDetailEntryWrapper) GetDstPort() uint16 { return d.DstPort }
func (d DropDetailEntryWrapper) GetCount() uint64   { return d.Count }

// PassDetailEntryWrapper wraps sdk.DropDetailEntry for pass details.
// PassDetailEntryWrapper 为通过详情包装 sdk.DropDetailEntry。
type PassDetailEntryWrapper struct {
	sdk.DropDetailEntry
}

func (p PassDetailEntryWrapper) GetReason() uint32  { return p.Reason }
func (p PassDetailEntryWrapper) GetProtocol() uint8 { return p.Protocol }
func (p PassDetailEntryWrapper) GetSrcIP() string   { return p.SrcIP }
func (p PassDetailEntryWrapper) GetDstPort() uint16 { return p.DstPort }
func (p PassDetailEntryWrapper) GetCount() uint64   { return p.Count }

// detailStatsConfig holds configuration for displaying detail statistics.
// detailStatsConfig 保存显示详细统计的配置。
type detailStatsConfig struct {
	title      string
	subTitle   string
	reasonFunc func(uint32) string
	totalCount uint64
	currentPPS uint64
	showRate   bool
}

// showDetailStatistics displays detailed statistics using generics.
// showDetailStatistics 使用泛型显示详细统计。
func showDetailStatistics[T DetailEntry](details []T, cfg detailStatsConfig) {
	if len(details) == 0 {
		return
	}

	fmt.Printf("\n%s\n", cfg.title)
	// Sort by count descending
	// 按计数降序排序
	sort.Slice(details, func(i, j int) bool {
		return details[i].GetCount() > details[j].GetCount()
	})

	// Get top N from config / 从配置获取 Top N
	maxShow := getTopNFromConfig()
	if len(details) < maxShow {
		maxShow = len(details)
	}

	fmt.Printf("\n   %s\n", cfg.subTitle)
	// Add Rate column if we have PPS data / 如果有 PPS 数据则添加速率列
	if cfg.showRate && cfg.currentPPS > 0 {
		fmt.Printf("   %-20s %-8s %-40s %-8s %-10s %-10s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count", "Rate/s", "Percent")
		fmt.Printf("   %s\n", strings.Repeat("-", 115))
	} else {
		fmt.Printf("   %-20s %-8s %-40s %-8s %-10s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count", "Percent")
		fmt.Printf("   %s\n", strings.Repeat("-", 100))
	}

	for i := 0; i < maxShow; i++ {
		d := details[i]
		percent := calculatePercentGeneric(d.GetCount(), cfg.totalCount)

		if cfg.showRate && cfg.currentPPS > 0 {
			ratePerSec := calculateRateGeneric(cfg.currentPPS, percent)
			fmt.Printf("   %-20s %-8s %-40s %-8d %-10d %-10s %.2f%%\n",
				cfg.reasonFunc(d.GetReason()),
				protocolToString(d.GetProtocol()),
				d.GetSrcIP(),
				d.GetDstPort(),
				d.GetCount(),
				fmtutil.FormatNumberWithComma(ratePerSec),
				percent)
		} else {
			fmt.Printf("   %-20s %-8s %-40s %-8d %-10d %.2f%%\n",
				cfg.reasonFunc(d.GetReason()),
				protocolToString(d.GetProtocol()),
				d.GetSrcIP(),
				d.GetDstPort(),
				d.GetCount(),
				percent)
		}
	}
	if len(details) > 10 {
		fmt.Printf("   ... and more\n")
	}

	// Show reason summary
	// 显示原因汇总
	showReasonSummary(details, cfg)
}

// showReasonSummary displays a summary of reasons using generics.
// showReasonSummary 使用泛型显示原因汇总。
func showReasonSummary[T DetailEntry](details []T, cfg detailStatsConfig) {
	reasonSummary := make(map[string]uint64)
	for _, d := range details {
		reason := cfg.reasonFunc(d.GetReason())
		reasonSummary[reason] += d.GetCount()
	}
	if len(reasonSummary) > 0 {
		fmt.Println("\n   [RATE] Reason Summary:")
		for reason, count := range reasonSummary {
			percent := calculatePercentGeneric(count, cfg.totalCount)
			// Show rate if available / 如果有速率数据则显示
			if cfg.showRate && cfg.currentPPS > 0 {
				ratePerSec := calculateRateGeneric(cfg.currentPPS, percent)
				fmt.Printf("      %s: %d (%.2f%%) - %s/s\n", reason, count, percent, fmtutil.FormatNumberWithComma(ratePerSec))
			} else {
				fmt.Printf("      %s: %d (%.2f%%)\n", reason, count, percent)
			}
		}
	}
}

// getTopNFromConfig returns the top N value from config, defaulting to 10
// getTopNFromConfig 从配置获取 Top N 值，默认为 10
func getTopNFromConfig() int {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err == nil {
		cfg := cfgManager.GetConfig()
		if cfg != nil && cfg.Metrics.TopN > 0 {
			return cfg.Metrics.TopN
		}
	}
	return 10 // Default value / 默认值
}

// getThresholdsFromConfig returns usage thresholds from config
// getThresholdsFromConfig 从配置获取使用率阈值
func getThresholdsFromConfig() (critical, high, medium int) {
	cfgManager := config.GetConfigManager()
	if err := cfgManager.LoadConfig(); err == nil {
		cfg := cfgManager.GetConfig()
		if cfg != nil {
			if cfg.Metrics.ThresholdCritical > 0 {
				critical = cfg.Metrics.ThresholdCritical
			} else {
				critical = 90
			}
			if cfg.Metrics.ThresholdHigh > 0 {
				high = cfg.Metrics.ThresholdHigh
			} else {
				high = 75
			}
			if cfg.Metrics.ThresholdMedium > 0 {
				medium = cfg.Metrics.ThresholdMedium
			} else {
				medium = 50
			}
			return
		}
	}
	return 90, 75, 50 // Default values / 默认值
}

// showConclusionStatistics displays summary statistics at the end
// showConclusionStatistics 在末尾显示汇总统计
func showConclusionStatistics(mgr sdk.ManagerInterface, s StatsAPI) {
	// Get drop details for security analysis / 获取丢弃详情用于安全分析
	dropDetails, err := s.GetDropDetails()
	if err != nil {
		fmt.Println()
		fmt.Println("[INFO] Summary Security Hits:")
		fmt.Println("   └─ Status: Unavailable")
		return
	}

	// Count by drop reason / 按丢弃原因计数
	var secHits, blacklistHits, rateLimitHits uint64
	for _, d := range dropDetails {
		switch d.Reason {
		case DropReasonBlacklist:
			blacklistHits += d.Count
		case DropReasonRatelimit:
			rateLimitHits += d.Count
		case DropReasonStrictTCP, DropReasonBogon, DropReasonFragment,
			DropReasonBadHeader, DropReasonTCPFlags, DropReasonSpoof,
			DropReasonLandAttack:
			secHits += d.Count
		}
	}

	// Get blacklist counts / 获取黑名单计数
	staticBlacklistCount, _ := mgr.GetLockedIPCount()
	dynBlacklistCount, _ := mgr.GetDynLockListCount()

	// Get critical blacklist count / 获取危机封锁计数
	criticalBlacklistCount := uint64(0)
	if adapter, ok := mgr.(*xdp.Adapter); ok {
		// Access the underlying manager to get critical blacklist count
		// 访问底层管理器获取危机封锁计数
		criticalBlacklistCount, _ = adapter.GetCriticalBlacklistCount()
	}

	// Get auto-block status from config / 从配置获取自动封禁状态
	cfgManager := config.GetConfigManager()
	var autoBlockEnabled bool
	var autoBlockedCount uint64
	if err := cfgManager.LoadConfig(); err == nil {
		cfg := cfgManager.GetConfig()
		if cfg != nil && cfg.RateLimit.AutoBlock {
			autoBlockEnabled = true
			autoBlockedCount = dynBlacklistCount
		}
	}

	// Display summary / 显示汇总
	fmt.Println()
	fmt.Println("[STATS] Summary Security Hits:")

	// Static Blacklist hits / 静态黑名单命中
	fmt.Printf("   ├─ [LOCK] Static Blacklist:    %s entries\n", fmtutil.FormatNumberWithComma(uint64(staticBlacklistCount))) // #nosec G115 // count is always valid

	// Dynamic Blacklist hits / 动态黑名单命中
	fmt.Printf("   ├─ [UNLOCK] Dynamic Blacklist:   %s entries\n", fmtutil.FormatNumberWithComma(dynBlacklistCount))

	// Critical Lock hits / 危机封锁命中
	fmt.Printf("   ├─ [ALERT] Critical Lock:       %s entries\n", fmtutil.FormatNumberWithComma(criticalBlacklistCount))

	// Rate Limit hits / 速率限制命中
	fmt.Printf("   ├─ [TIME]  Rate Limit Hits:     %s\n", fmtutil.FormatNumberWithComma(rateLimitHits))

	// Auto Blocked / 自动封禁
	if autoBlockEnabled {
		fmt.Printf("   └─ [AUTO] Auto Blocked:        %s IPs (enabled)\n", fmtutil.FormatNumberWithComma(autoBlockedCount))
	} else {
		fmt.Printf("   └─ [AUTO] Auto Blocked:        disabled\n")
	}
}
