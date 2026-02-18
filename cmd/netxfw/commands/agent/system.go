package agent

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/internal/app"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/plugins/types"
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

func init() {
	SystemCmd.AddCommand(systemInitCmd)
	SystemCmd.AddCommand(systemStatusCmd)
	SystemCmd.AddCommand(systemTestCmd)
	SystemCmd.AddCommand(systemDaemonCmd)

	systemLoadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to attach XDP to")
	SystemCmd.AddCommand(systemLoadCmd)

	systemReloadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to attach XDP to")
	SystemCmd.AddCommand(systemReloadCmd)
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
	showTrafficMetrics(mgr, pass, drops)

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

	// Show map usage
	// 显示 Map 使用率
	showMapUsage(mgr)

	// Show protocol distribution
	// 显示协议分布
	showProtocolDistribution(s.Stats, pass, drops)

	// Load configuration for policy display
	// 加载配置以显示策略
	showPolicyConfiguration()

	// Show attached interfaces
	// 显示已附加的接口
	showAttachedInterfaces()

	return nil
}

// StatsAPI interface for statistics operations (for testing and decoupling)
// StatsAPI 统计操作接口（用于测试和解耦）
type StatsAPI interface {
	GetDropDetails() ([]sdk.DropDetailEntry, error)
	GetPassDetails() ([]sdk.DropDetailEntry, error)
}

// showDropStatistics displays drop statistics with percentages
// showDropStatistics 显示带百分比的丢弃统计
func showDropStatistics(s StatsAPI, drops, pass uint64) {
	totalPackets := pass + drops
	dropPercent := float64(0)
	if totalPackets > 0 {
		dropPercent = float64(drops) / float64(totalPackets) * 100
	}
	fmt.Printf("\n📊 Global Drop Count: %d packets (%.2f%%)\n", drops, dropPercent)

	// Show detailed drop stats
	// 显示详细丢弃统计
	dropDetails, err := s.GetDropDetails()
	if err == nil && len(dropDetails) > 0 {
		// Sort by count descending
		// 按计数降序排序
		sort.Slice(dropDetails, func(i, j int) bool {
			return dropDetails[i].Count > dropDetails[j].Count
		})

		// Limit to top 10
		// 限制显示前 10 条
		maxShow := 10
		if len(dropDetails) < maxShow {
			maxShow = len(dropDetails)
		}

		fmt.Println("\n   🚫 Top Drops by Reason & Source:")
		fmt.Printf("   %-20s %-8s %-40s %-8s %-10s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count", "Percent")
		fmt.Printf("   %s\n", strings.Repeat("-", 100))

		for i := 0; i < maxShow; i++ {
			d := dropDetails[i]
			percent := float64(0)
			if drops > 0 {
				percent = float64(d.Count) / float64(drops) * 100
			}
			fmt.Printf("   %-20s %-8s %-40s %-8d %-10d %.2f%%\n",
				dropReasonToString(d.Reason),
				protocolToString(d.Protocol),
				d.SrcIP,
				d.DstPort,
				d.Count,
				percent)
		}
		if len(dropDetails) > 10 {
			fmt.Printf("   ... and more\n")
		}

		// Show drop reason summary
		// 显示丢弃原因汇总
		showDropReasonSummary(dropDetails, drops)
	}
}

// showDropReasonSummary displays a summary of drop reasons
// showDropReasonSummary 显示丢弃原因汇总
func showDropReasonSummary(dropDetails []sdk.DropDetailEntry, drops uint64) {
	dropReasonSummary := make(map[string]uint64)
	for _, d := range dropDetails {
		reason := dropReasonToString(d.Reason)
		dropReasonSummary[reason] += d.Count
	}
	if len(dropReasonSummary) > 0 {
		fmt.Println("\n   📈 Drop Reason Summary:")
		for reason, count := range dropReasonSummary {
			percent := float64(0)
			if drops > 0 {
				percent = float64(count) / float64(drops) * 100
			}
			fmt.Printf("      %s: %d (%.2f%%)\n", reason, count, percent)
		}
	}
}

// showPassStatistics displays pass statistics with percentages
// showPassStatistics 显示带百分比的通过统计
func showPassStatistics(s StatsAPI, pass, drops uint64) {
	totalPackets := pass + drops
	passPercent := float64(0)
	if totalPackets > 0 {
		passPercent = float64(pass) / float64(totalPackets) * 100
	}
	fmt.Printf("\n📊 Global Pass Count: %d packets (%.2f%%)\n", pass, passPercent)

	// Show detailed pass stats
	// 显示详细通过统计
	passDetails, err := s.GetPassDetails()
	if err == nil && len(passDetails) > 0 {
		// Sort by count descending
		// 按计数降序排序
		sort.Slice(passDetails, func(i, j int) bool {
			return passDetails[i].Count > passDetails[j].Count
		})

		// Limit to top 10
		// 限制显示前 10 条
		maxShow := 10
		if len(passDetails) < maxShow {
			maxShow = len(passDetails)
		}

		fmt.Println("\n   ✅ Top Allowed by Reason & Source:")
		fmt.Printf("   %-20s %-8s %-40s %-8s %-10s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count", "Percent")
		fmt.Printf("   %s\n", strings.Repeat("-", 100))

		for i := 0; i < maxShow; i++ {
			d := passDetails[i]
			percent := float64(0)
			if pass > 0 {
				percent = float64(d.Count) / float64(pass) * 100
			}
			fmt.Printf("   %-20s %-8s %-40s %-8d %-10d %.2f%%\n",
				passReasonToString(d.Reason),
				protocolToString(d.Protocol),
				d.SrcIP,
				d.DstPort,
				d.Count,
				percent)
		}
		if len(passDetails) > 10 {
			fmt.Printf("   ... and more\n")
		}

		// Show pass reason summary
		// 显示通过原因汇总
		showPassReasonSummary(passDetails, pass)
	}
}

// showPassReasonSummary displays a summary of pass reasons
// showPassReasonSummary 显示通过原因汇总
func showPassReasonSummary(passDetails []sdk.DropDetailEntry, pass uint64) {
	passReasonSummary := make(map[string]uint64)
	for _, d := range passDetails {
		reason := passReasonToString(d.Reason)
		passReasonSummary[reason] += d.Count
	}
	if len(passReasonSummary) > 0 {
		fmt.Println("\n   📈 Pass Reason Summary:")
		for reason, count := range passReasonSummary {
			percent := float64(0)
			if pass > 0 {
				percent = float64(count) / float64(pass) * 100
			}
			fmt.Printf("      %s: %d (%.2f%%)\n", reason, count, percent)
		}
	}
}

// showMapStatistics displays BPF map statistics
// showMapStatistics 显示 BPF Map 统计
func showMapStatistics(mgr sdk.ManagerInterface) {
	fmt.Println()
	fmt.Println("📦 Map Statistics:")

	blacklistCount, _ := mgr.GetLockedIPCount()
	fmt.Printf("   ├─ 🔒 Blacklist Entries: %d\n", blacklistCount)

	dynBlacklist, _, _ := mgr.ListDynamicBlacklistIPs(0, "")
	fmt.Printf("   ├─ 🔒 Dynamic Blacklist: %d\n", len(dynBlacklist))

	whitelistCount, _ := mgr.GetWhitelistCount()
	fmt.Printf("   ├─ ⚪ Whitelist Entries: %d\n", whitelistCount)

	conntrackCount, _ := mgr.GetConntrackCount()
	fmt.Printf("   ├─ 🕵️  Active Connections: %d\n", conntrackCount)

	// IP+Port rules
	// IP+端口规则
	ipPortRules, _, _ := mgr.ListIPPortRules(false, 0, "")
	fmt.Printf("   ├─ 📋 IP+Port Rules: %d\n", len(ipPortRules))

	// Allowed ports
	// 允许端口
	allowedPorts, _ := mgr.ListAllowedPorts()
	fmt.Printf("   ├─ 🔓 Allowed Ports: %d\n", len(allowedPorts))

	// Rate limit rules
	// 速率限制规则
	rateLimitRules, _, _ := mgr.ListRateLimitRules(0, "")
	fmt.Printf("   └─ ⏱️  Rate Limit Rules: %d\n", len(rateLimitRules))
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
	attachedIfaces, err := xdp.GetAttachedInterfaces(config.GetPinPath())
	if err == nil && len(attachedIfaces) > 0 {
		for _, iface := range attachedIfaces {
			fmt.Printf("  - %s (Mode: Native)\n", iface)
		}
	} else {
		fmt.Println("  - None")
	}
}

// showTrafficMetrics displays PPS/BPS traffic metrics
// showTrafficMetrics 显示 PPS/BPS 流量指标
func showTrafficMetrics(mgr sdk.ManagerInterface, pass, drops uint64) {
	fmt.Println()
	fmt.Println("📈 Traffic Rate:")

	totalPackets := pass + drops

	// Get performance stats if available / 如果可用，获取性能统计
	perfStats := mgr.PerfStats()
	if perfStats != nil {
		// Try to get traffic stats from performance tracker / 尝试从性能跟踪器获取流量统计
		if ts, ok := perfStats.(interface {
			GetTrafficStats() interface{}
		}); ok {
			stats := ts.GetTrafficStats()
			if trafficStats, ok := stats.(interface {
				GetCurrentPPS() uint64
				GetCurrentBPS() uint64
				GetPeakPPS() uint64
				GetPeakBPS() uint64
				GetCurrentDropPPS() uint64
			}); ok && trafficStats != nil {
				currentPPS := trafficStats.GetCurrentPPS()
				currentBPS := trafficStats.GetCurrentBPS()
				dropPPS := trafficStats.GetCurrentDropPPS()

				// Calculate drop rate / 计算丢弃率
				var dropRate float64
				if currentPPS > 0 {
					dropRate = float64(dropPPS) / float64(currentPPS) * 100
				}

				fmt.Printf("   ├─ PPS: %s pkt/s\n", formatNumberWithComma(currentPPS))
				fmt.Printf("   ├─ BPS: %s\n", formatBPS(currentBPS))
				fmt.Printf("   ├─ Drop PPS: %s pkt/s\n", formatNumberWithComma(dropPPS))
				fmt.Printf("   └─ Drop Rate: %.2f%%\n", dropRate)
				return
			}
		}
	}

	// Fallback: show basic packet stats / 回退：显示基本数据包统计
	dropRate := calculatePercent(drops, totalPackets)
	fmt.Printf("   ├─ Total Packets: %s\n", formatNumberWithComma(totalPackets))
	fmt.Printf("   ├─ Pass Rate: %.2f%%\n", calculatePercent(pass, totalPackets))
	fmt.Printf("   └─ Drop Rate: %.2f%%\n", dropRate)
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

	// Get conntrack entries for protocol breakdown / 获取连接跟踪条目以进行协议分布
	entries, err := mgr.ListAllConntrackEntries()
	if err != nil {
		fmt.Printf("   ├─ Active Connections: %d\n", conntrackCount)
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

	fmt.Printf("   ├─ Active Connections: %d\n", conntrackCount)
	fmt.Printf("   ├─ TCP Connections: %d (%.1f%%)\n", tcpCount, calculatePercent(uint64(tcpCount), uint64(conntrackCount)))
	fmt.Printf("   ├─ UDP Connections: %d (%.1f%%)\n", udpCount, calculatePercent(uint64(udpCount), uint64(conntrackCount)))
	fmt.Printf("   ├─ ICMP Connections: %d (%.1f%%)\n", icmpCount, calculatePercent(uint64(icmpCount), uint64(conntrackCount)))
	fmt.Printf("   └─ Other Connections: %d (%.1f%%)\n", otherCount, calculatePercent(uint64(otherCount), uint64(conntrackCount)))

	// Determine health status / 确定健康状态
	if conntrackCount > 10000 {
		fmt.Println("   ⚠️  Status: High connection count")
	} else {
		fmt.Println("   ✅ Status: Healthy")
	}
}

// showMapUsage displays BPF map usage statistics
// showMapUsage 显示 BPF Map 使用率统计
// showMapUsage displays BPF map usage statistics with capacity info
// showMapUsage 显示 BPF Map 使用率统计，包含容量信息
func showMapUsage(mgr sdk.ManagerInterface) {
	fmt.Println()
	fmt.Println("📊 Map Usage:")

	// Get capacity configuration from config manager / 从配置管理器获取容量配置
	cfgManager := config.GetConfigManager()
	var capacityCfg *types.CapacityConfig
	if err := cfgManager.LoadConfig(); err == nil {
		capacityCfg = cfgManager.GetCapacityConfig()
	}

	// Get map counts / 获取 Map 计数
	blacklistCount, _ := mgr.GetLockedIPCount()
	whitelistCount, _ := mgr.GetWhitelistCount()
	conntrackCount, _ := mgr.GetConntrackCount()
	dynBlacklistCount, _ := mgr.GetDynLockListCount()

	// Get rate limit rules / 获取限速规则
	rateLimitRules, _, _ := mgr.ListRateLimitRules(0, "")

	// Get IP+Port rules / 获取 IP+端口规则
	ipPortRules, _, _ := mgr.ListIPPortRules(false, 0, "")

	// Get max capacities from config or use defaults / 从配置获取最大容量或使用默认值
	maxBlacklist := 10000
	maxWhitelist := 10000
	maxConntrack := 50000
	maxDynBlacklist := 10000
	maxIPPortRules := 1000
	maxRateLimits := 1000

	if capacityCfg != nil {
		if capacityCfg.LockList > 0 {
			maxBlacklist = capacityCfg.LockList
		}
		if capacityCfg.Whitelist > 0 {
			maxWhitelist = capacityCfg.Whitelist
		}
		if capacityCfg.Conntrack > 0 {
			maxConntrack = capacityCfg.Conntrack
		}
		if capacityCfg.DynLockList > 0 {
			maxDynBlacklist = capacityCfg.DynLockList
		}
		if capacityCfg.IPPortRules > 0 {
			maxIPPortRules = capacityCfg.IPPortRules
		}
	}

	// Show usage with current/max and percentage / 显示当前/最大值和百分比
	fmt.Printf("   ├─ Blacklist:      %d / %d (%.1f%%) %s\n",
		blacklistCount, maxBlacklist,
		calculatePercent(blacklistCount, uint64(maxBlacklist)),
		getUsageIndicator(blacklistCount, maxBlacklist))
	fmt.Printf("   ├─ Whitelist:      %d / %d (%.1f%%) %s\n",
		whitelistCount, maxWhitelist,
		calculatePercent(whitelistCount, uint64(maxWhitelist)),
		getUsageIndicator(whitelistCount, maxWhitelist))
	fmt.Printf("   ├─ Conntrack:      %d / %d (%.1f%%) %s\n",
		conntrackCount, maxConntrack,
		calculatePercent(conntrackCount, uint64(maxConntrack)),
		getUsageIndicator(conntrackCount, maxConntrack))
	fmt.Printf("   ├─ Dyn Blacklist:  %d / %d (%.1f%%) %s\n",
		dynBlacklistCount, maxDynBlacklist,
		calculatePercent(dynBlacklistCount, uint64(maxDynBlacklist)),
		getUsageIndicator(int(dynBlacklistCount), maxDynBlacklist))
	fmt.Printf("   ├─ Rate Limits:    %d / %d (%.1f%%) %s\n",
		len(rateLimitRules), maxRateLimits,
		calculatePercent(uint64(len(rateLimitRules)), uint64(maxRateLimits)),
		getUsageIndicator(len(rateLimitRules), maxRateLimits))
	fmt.Printf("   └─ IP+Port Rules:  %d / %d (%.1f%%) %s\n",
		len(ipPortRules), maxIPPortRules,
		calculatePercent(uint64(len(ipPortRules)), uint64(maxIPPortRules)),
		getUsageIndicator(len(ipPortRules), maxIPPortRules))
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

		for proto, stats := range protoStats {
			total := stats.dropped + stats.passed
			percent := calculatePercent(total, totalPackets)
			fmt.Printf("   %-10s %-15d %-15d %.1f%%\n",
				protocolToString(proto),
				stats.dropped,
				stats.passed,
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
	if usage >= 90 {
		return "🔴 [CRITICAL]"
	} else if usage >= 75 {
		return "🟠 [HIGH]"
	} else if usage >= 50 {
		return "🟡 [MEDIUM]"
	}
	return "🟢 [OK]"
}

// calculatePercent calculates percentage safely
// calculatePercent 安全地计算百分比
func calculatePercent(part, total interface{}) float64 {
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

// formatNumberWithComma formats a number with thousand separators
// formatNumberWithComma 格式化数字，添加千位分隔符
func formatNumberWithComma(n uint64) string {
	s := fmt.Sprintf("%d", n)
	result := ""
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result += ","
		}
		result += string(c)
	}
	return result
}
