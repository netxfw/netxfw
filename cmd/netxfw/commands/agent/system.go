package agent

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/internal/app"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/fmtutil"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var SystemCmd = &cobra.Command{
	Use:   "system",
	Short: "System management commands",
	// Short: 系统管理命令
	Long: `System management commands for netxfw`,
	// Long: netxfw 的系统管理命令
}

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	// Short: 初始化配置文件
	Long: `Initialize default configuration file in /root/netxfw/`,
	// Long: 在 /root/netxfw/ 中初始化默认配置文件
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize configuration
		// 初始化配置
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
		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		// Show system status
		// 显示系统状态
		if err := showStatus(cmd.Context(), s); err != nil {
			cmd.PrintErrln(err)
		}
	},
}

var systemTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration validity",
	// Short: 测试配置有效性
	Long: `Test configuration validity`,
	// Long: 测试配置有效性
	Run: func(cmd *cobra.Command, args []string) {
		// Test configuration
		// 测试配置
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
		// Run as daemon
		// 以守护进程方式运行
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
	Short: "Hot-reload XDP program with new configuration",
	// Short: 使用新配置热重载 XDP 程序
	Long: `Hot-reload XDP program: applies new configuration without dropping connections.
Supports capacity changes with state migration.`,
	// Long: 热重载 XDP 程序：应用新配置而不中断连接。支持容量变更时的状态迁移。
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		if err := app.ReloadXDP(cmd.Context(), interfaces); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		fmt.Println("✅ XDP program reloaded successfully")
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

func init() {
	SystemCmd.AddCommand(systemInitCmd)
	SystemCmd.AddCommand(systemStatusCmd)
	SystemCmd.AddCommand(systemTestCmd)
	SystemCmd.AddCommand(systemDaemonCmd)

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
}

// showStatus displays the system status including statistics and configuration
// showStatus 显示系统状态，包括统计信息和配置
func showStatus(ctx context.Context, s *sdk.SDK) error {
	fmt.Println("✅ XDP Program Status: Loaded and Running")

	mgr := s.GetManager()

	// Get global stats
	// 获取全局统计
	pass, drops, err := s.Stats.GetCounters()
	if err != nil {
		fmt.Printf("⚠️  Could not retrieve statistics: %v\n", err)
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
		title:      "🚫 Drop Statistics:",
		subTitle:   "🚫 Top Drops by Reason & Source:",
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
		title:      "✅ Pass Statistics:",
		subTitle:   "✅ Top Allowed by Reason & Source:",
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
	fmt.Println("📦 Map Statistics:")

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

	// Show compact table / 显示紧凑表格
	fmt.Printf("   %-16s %10s / %-10s %-8s %s\n", "Map", "Used", "Max", "Usage", "Status")
	fmt.Printf("   %s\n", strings.Repeat("-", 55))
	fmt.Printf("   %-16s %10d / %-10d %-8s %s\n",
		"🔒 Blacklist", blacklistCount, maxBlacklist,
		fmt.Sprintf("%.1f%%", calculatePercentGeneric(blacklistCount, uint64(maxBlacklist))),
		getUsageIndicator(blacklistCount, maxBlacklist))
	fmt.Printf("   %-16s %10d / %-10d %-8s %s\n",
		"🔓 Dyn Blacklist", dynBlacklistCount, maxDynBlacklist,
		fmt.Sprintf("%.1f%%", calculatePercentGeneric(dynBlacklistCount, uint64(maxDynBlacklist))),
		getUsageIndicator(int(dynBlacklistCount), maxDynBlacklist))
	fmt.Printf("   %-16s %10d / %-10d %-8s %s\n",
		"⚪ Whitelist", whitelistCount, maxWhitelist,
		fmt.Sprintf("%.1f%%", calculatePercentGeneric(whitelistCount, uint64(maxWhitelist))),
		getUsageIndicator(whitelistCount, maxWhitelist))
	// Conntrack is shown in detail in Conntrack Health section, skip here
	// Conntrack 在 Conntrack Health 部分详细显示，此处跳过
	fmt.Printf("   %-16s %10d / %-10d %-8s %s\n",
		"📋 IP+Port Rules", len(ipPortRules), maxIPPortRules,
		fmt.Sprintf("%.1f%%", calculatePercentGeneric(uint64(len(ipPortRules)), uint64(maxIPPortRules))),
		getUsageIndicator(len(ipPortRules), maxIPPortRules))
	fmt.Printf("   %-16s %10d / %-10d %-8s %s\n",
		"⏱️  Rate Limits", len(rateLimitRules), maxRateLimits,
		fmt.Sprintf("%.1f%%", calculatePercentGeneric(uint64(len(rateLimitRules)), uint64(maxRateLimits))),
		getUsageIndicator(len(rateLimitRules), maxRateLimits))
	fmt.Printf("   %-16s %10d\n", "🔓 Allowed Ports", len(allowedPorts))
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
	fmt.Println("⚙️  Policy Configuration:")

	// Default deny policy
	// 默认拒绝策略
	if cfg.Base.DefaultDeny {
		fmt.Println("   ├─ 🛡️  Default Deny: Enabled (Deny by default)")
	} else {
		fmt.Println("   ├─ 🛡️  Default Deny: Disabled (Allow by default)")
	}

	// Return traffic
	// 回程流量
	if cfg.Base.AllowReturnTraffic {
		fmt.Println("   ├─ 🔄 Allow Return Traffic: Enabled")
	} else {
		fmt.Println("   ├─ 🔄 Allow Return Traffic: Disabled")
	}

	// ICMP
	// ICMP
	if cfg.Base.AllowICMP {
		fmt.Println("   ├─ 🏓 Allow ICMP (Ping): Enabled")
	} else {
		fmt.Println("   ├─ 🏓 Allow ICMP (Ping): Disabled")
	}

	// Strict TCP
	// 严格 TCP
	if cfg.Base.StrictTCP {
		fmt.Println("   ├─ 🔒 Strict TCP: Enabled")
	} else {
		fmt.Println("   ├─ 🔒 Strict TCP: Disabled")
	}

	// SYN Limit
	// SYN 限制
	if cfg.Base.SYNLimit {
		fmt.Println("   ├─ 🚧 SYN Flood Protection: Enabled")
	} else {
		fmt.Println("   ├─ 🚧 SYN Flood Protection: Disabled")
	}

	// Bogon Filter
	// Bogon 过滤
	if cfg.Base.BogonFilter {
		fmt.Println("   ├─ 🌐 Bogon Filter: Enabled")
	} else {
		fmt.Println("   ├─ 🌐 Bogon Filter: Disabled")
	}

	// Connection tracking
	// 连接跟踪
	if cfg.Conntrack.Enabled {
		fmt.Println("   ├─ 🕵️  Connection Tracking: Enabled")
		if cfg.Conntrack.TCPTimeout != "" {
			fmt.Printf("   │     └─ TCP Timeout: %s\n", cfg.Conntrack.TCPTimeout)
		}
		if cfg.Conntrack.UDPTimeout != "" {
			fmt.Printf("   │     └─ UDP Timeout: %s\n", cfg.Conntrack.UDPTimeout)
		}
	} else {
		fmt.Println("   ├─ 🕵️  Connection Tracking: Disabled")
	}

	// Rate limiting
	// 速率限制
	if cfg.RateLimit.Enabled {
		fmt.Println("   ├─ 🚀 Rate Limiting: Enabled")
		if cfg.RateLimit.AutoBlock {
			fmt.Printf("   │     └─ Auto Block: Enabled (Expiry: %s)\n", cfg.RateLimit.AutoBlockExpiry)
		}
	} else {
		fmt.Println("   ├─ 🚀 Rate Limiting: Disabled")
	}

	// Log Engine
	// 日志引擎
	if cfg.LogEngine.Enabled {
		fmt.Printf("   ├─ 📝 Log Engine: Enabled (%d rules)\n", len(cfg.LogEngine.Rules))
	} else {
		fmt.Println("   ├─ 📝 Log Engine: Disabled")
	}

	// Web Interface
	// Web 界面
	if cfg.Web.Enabled {
		fmt.Printf("   └─ 🌐 Web Interface: Enabled (Port: %d)\n", cfg.Web.Port)
	} else {
		fmt.Println("   └─ 🌐 Web Interface: Disabled")
	}
}

// showAttachedInterfaces displays attached network interfaces
// showAttachedInterfaces 显示已附加的网络接口
func showAttachedInterfaces() {
	fmt.Println("\n🔗 Attached Interfaces:")
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
	fmt.Println("📈 Traffic Rate:")

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
	fmt.Println("🕵️  Conntrack Health:")

	conntrackCount, err := mgr.GetConntrackCount()
	if err != nil {
		fmt.Println("   └─ Status: Unavailable")
		return
	}

	// Get capacity configuration from config manager / 从配置管理器获取容量配置
	cfgManager := config.GetConfigManager()
	var maxConntrack int
	if err := cfgManager.LoadConfig(); err == nil {
		capacityCfg := cfgManager.GetCapacityConfig()
		if capacityCfg != nil && capacityCfg.Conntrack > 0 {
			maxConntrack = capacityCfg.Conntrack
		}
	}
	if maxConntrack == 0 {
		maxConntrack = 100000 // Default from CapacityConfig / 来自 CapacityConfig 的默认值
	}

	// Get conntrack entries for protocol breakdown / 获取连接跟踪条目以进行协议分布
	entries, err := mgr.ListAllConntrackEntries()
	if err != nil {
		fmt.Printf("   ├─ Active Connections: %d / %d (%.1f%%)\n", conntrackCount, maxConntrack, calculatePercentGeneric(conntrackCount, uint64(maxConntrack)))
		fmt.Println("   └─ Protocol Breakdown: Unavailable")
		return
	}

	// Count by protocol / 按协议计数
	var tcpCount, udpCount, icmpCount, otherCount int
	for _, entry := range entries {
		switch entry.Protocol {
		case 6: // TCP
			tcpCount++
		case 17: // UDP
			udpCount++
		case 1: // ICMP
			icmpCount++
		default:
			otherCount++
		}
	}

	fmt.Printf("   ├─ Active Connections: %d / %d (%.1f%%)\n", conntrackCount, maxConntrack, calculatePercentGeneric(conntrackCount, uint64(maxConntrack)))
	fmt.Printf("   ├─ TCP Connections: %d (%.1f%%)\n", tcpCount, calculatePercentGeneric(uint64(tcpCount), uint64(conntrackCount)))
	fmt.Printf("   ├─ UDP Connections: %d (%.1f%%)\n", udpCount, calculatePercentGeneric(uint64(udpCount), uint64(conntrackCount)))
	fmt.Printf("   ├─ ICMP Connections: %d (%.1f%%)\n", icmpCount, calculatePercentGeneric(uint64(icmpCount), uint64(conntrackCount)))

	// Try to load traffic stats for new/evict rates / 尝试加载流量统计获取新建/淘汰速率
	trafficStats, err := xdp.LoadTrafficStats()
	hasRateData := err == nil && trafficStats.LastUpdateTime.After(time.Time{})

	if hasRateData {
		fmt.Printf("   ├─ Other Connections: %d (%.1f%%)\n", otherCount, calculatePercentGeneric(uint64(otherCount), uint64(conntrackCount)))
		fmt.Printf("   ├─ New/s: %s conn/s\n", fmtutil.FormatNumberWithComma(trafficStats.CurrentConntrackNew))
	} else {
		fmt.Printf("   └─ Other Connections: %d (%.1f%%)\n", otherCount, calculatePercentGeneric(uint64(otherCount), uint64(conntrackCount)))
	}

	// Determine health status / 确定健康状态
	usagePercent := calculatePercentGeneric(conntrackCount, uint64(maxConntrack))
	critical, high, _ := getThresholdsFromConfig()
	if hasRateData {
		fmt.Printf("   ├─ Evict/s: %s conn/s\n", fmtutil.FormatNumberWithComma(trafficStats.CurrentConntrackEvict))
		if usagePercent >= float64(critical) {
			fmt.Println("   └─ ⚠️  Status: CRITICAL - Near capacity")
		} else if usagePercent >= float64(high) {
			fmt.Println("   └─ ⚠️  Status: HIGH - Approaching capacity")
		} else {
			fmt.Println("   └─ ✅ Status: Healthy")
		}
	} else {
		if usagePercent >= float64(critical) {
			fmt.Println("   ⚠️  Status: CRITICAL - Near capacity")
		} else if usagePercent >= float64(high) {
			fmt.Println("   ⚠️  Status: HIGH - Approaching capacity")
		} else {
			fmt.Println("   ✅ Status: Healthy")
		}
	}
}

// showProtocolDistribution displays protocol distribution statistics
// showProtocolDistribution 显示协议分布统计
func showProtocolDistribution(s StatsAPI, pass, drops uint64) {
	fmt.Println()
	fmt.Println("📡 Protocol Distribution:")

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
func getUsageIndicator(current, max int) string {
	if max == 0 {
		return ""
	}
	usage := float64(current) / float64(max) * 100
	critical, high, medium := getThresholdsFromConfig()
	if usage >= float64(critical) {
		return "🔴 [CRITICAL]"
	} else if usage >= float64(high) {
		return "🟠 [HIGH]"
	} else if usage >= float64(medium) {
		return "🟡 [MEDIUM]"
	}
	return "🟢 [OK]"
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
		fmt.Println("\n   📈 Reason Summary:")
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

// calculatePercent calculates percentage safely (legacy wrapper for backward compatibility).
// calculatePercent 安全地计算百分比（向后兼容的传统包装器）。
func calculatePercent(part, total any) float64 {
	var p, t float64
	switch v := part.(type) {
	case int:
		p = float64(v)
	case uint64:
		p = float64(v)
	case int64:
		p = float64(v)
	default:
		return 0
	}
	switch v := total.(type) {
	case int:
		t = float64(v)
	case uint64:
		t = float64(v)
	case int64:
		t = float64(v)
	default:
		return 0
	}
	if t == 0 {
		return 0
	}
	return p / t * 100
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
		fmt.Println("📋 Summary Security Hits:")
		fmt.Println("   └─ Status: Unavailable")
		return
	}

	// Count by drop reason / 按丢弃原因计数
	var secHits, blacklistHits, rateLimitHits uint64
	for _, d := range dropDetails {
		switch d.Reason {
		case DROP_REASON_BLACKLIST:
			blacklistHits += d.Count
		case DROP_REASON_RATELIMIT:
			rateLimitHits += d.Count
		case DROP_REASON_STRICT_TCP, DROP_REASON_BOGON, DROP_REASON_FRAGMENT,
			DROP_REASON_BAD_HEADER, DROP_REASON_TCP_FLAGS, DROP_REASON_SPOOF,
			DROP_REASON_LAND_ATTACK:
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
	fmt.Println("📊 Summary Security Hits:")

	// Static Blacklist hits / 静态黑名单命中
	fmt.Printf("   ├─ 🔒 Static Blacklist:    %s entries\n", fmtutil.FormatNumberWithComma(uint64(staticBlacklistCount)))

	// Dynamic Blacklist hits / 动态黑名单命中
	fmt.Printf("   ├─ 🔓 Dynamic Blacklist:   %s entries\n", fmtutil.FormatNumberWithComma(dynBlacklistCount))

	// Critical Lock hits / 危机封锁命中
	fmt.Printf("   ├─ 🚨 Critical Lock:       %s entries\n", fmtutil.FormatNumberWithComma(criticalBlacklistCount))

	// Rate Limit hits / 速率限制命中
	fmt.Printf("   ├─ ⏱️  Rate Limit Hits:     %s\n", fmtutil.FormatNumberWithComma(rateLimitHits))

	// Auto Blocked / 自动封禁
	if autoBlockEnabled {
		fmt.Printf("   └─ 🤖 Auto Blocked:        %s IPs (enabled)\n", fmtutil.FormatNumberWithComma(autoBlockedCount))
	} else {
		fmt.Printf("   └─ 🤖 Auto Blocked:        disabled\n")
	}
}
