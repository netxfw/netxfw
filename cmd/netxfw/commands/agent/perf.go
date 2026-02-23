package agent

import (
	"fmt"
	"os"
	"time"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/utils/fmtutil"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

// PerfCmd represents the performance monitoring command
// PerfCmd 表示性能监控命令
var PerfCmd = &cobra.Command{
	Use:   "perf",
	Short: "Performance monitoring commands",
	// Short: 性能监控命令
	Long: `Performance monitoring commands for netxfw.
Shows map operation latency, cache hit rates, and real-time traffic statistics.`,
	// Long: netxfw 性能监控命令。显示 Map 操作延迟、缓存命中率和实时流量统计。
}

// perfShowCmd shows all performance statistics
// perfShowCmd 显示所有性能统计
var perfShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show performance statistics",
	// Short: 显示性能统计
	Long: `Show all performance statistics including map latency, cache hit rates, and traffic stats.`,
	// Long: 显示所有性能统计，包括 Map 延迟、缓存命中率和流量统计。
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		if err := showPerformanceStats(s); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

// perfLatencyCmd shows map operation latency statistics
// perfLatencyCmd 显示 Map 操作延迟统计
var perfLatencyCmd = &cobra.Command{
	Use:   "latency",
	Short: "Show map operation latency",
	// Short: 显示 Map 操作延迟
	Long: `Show map operation latency statistics.`,
	// Long: 显示 Map 操作延迟统计。
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		if err := showMapLatency(s); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

// perfCacheCmd shows cache hit rate statistics
// perfCacheCmd 显示缓存命中率统计
var perfCacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Show cache hit rates",
	// Short: 显示缓存命中率
	Long: `Show cache hit rate statistics.`,
	// Long: 显示缓存命中率统计。
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		if err := showCacheHitRates(s); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

// perfTrafficCmd shows real-time traffic statistics
// perfTrafficCmd 显示实时流量统计
var perfTrafficCmd = &cobra.Command{
	Use:   "traffic",
	Short: "Show real-time traffic statistics",
	// Short: 显示实时流量统计
	Long: `Show real-time traffic statistics including PPS, BPS, and drop rates.`,
	// Long: 显示实时流量统计，包括 PPS、BPS 和丢弃速率。
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		if err := showTrafficStats(s); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

// perfResetCmd resets performance statistics
// perfResetCmd 重置性能统计
var perfResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset performance statistics",
	// Short: 重置性能统计
	Long: `Reset all performance statistics counters.`,
	// Long: 重置所有性能统计计数器。
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		perfStats, err := getPerfStats(s)
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		perfStats.Reset()
		fmt.Println("✅ Performance statistics reset successfully")
	},
}

// watchFlag indicates if stats should be continuously displayed
// watchFlag 指示是否持续显示统计
var watchFlag bool

func init() {
	PerfCmd.AddCommand(perfShowCmd)
	PerfCmd.AddCommand(perfLatencyCmd)
	PerfCmd.AddCommand(perfCacheCmd)
	PerfCmd.AddCommand(perfTrafficCmd)
	PerfCmd.AddCommand(perfResetCmd)

	// Add watch flag for continuous monitoring
	// 为持续监控添加 watch 标志
	perfShowCmd.Flags().BoolVarP(&watchFlag, "watch", "w", false, "Continuously display stats")
	perfTrafficCmd.Flags().BoolVarP(&watchFlag, "watch", "w", false, "Continuously display stats")
}

// getPerfStats retrieves the performance stats from the manager
// getPerfStats 从 manager 获取性能统计
func getPerfStats(s *sdk.SDK) (*xdp.PerformanceStats, error) {
	mgr := s.GetManager()
	if mgr == nil {
		return nil, fmt.Errorf("manager not available")
	}

	perfInterface := mgr.PerfStats()
	if perfInterface == nil {
		return nil, fmt.Errorf("performance statistics not available")
	}

	perfStats, ok := perfInterface.(*xdp.PerformanceStats)
	if !ok {
		return nil, fmt.Errorf("invalid performance statistics type")
	}

	return perfStats, nil
}

// showPerformanceStats displays all performance statistics
// showPerformanceStats 显示所有性能统计
func showPerformanceStats(s *sdk.SDK) error {
	perfStats, err := getPerfStats(s)
	if err != nil {
		return err
	}

	stats := perfStats.GetStats()

	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Performance Statistics Summary                  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	// Uptime / 运行时间
	uptime := time.Duration(stats.Traffic.UptimeSeconds) * time.Second // #nosec G115 // uptime is always reasonable value
	fmt.Printf("\n⏱️  Uptime: %v\n", uptime.Round(time.Second))

	// Map Latency Summary / Map 延迟摘要
	fmt.Println("\n📊 Map Operation Latency:")
	fmt.Printf("   Total Operations: %d\n", stats.MapLatency.TotalOperations)
	fmt.Printf("   Total Errors:     %d\n", stats.MapLatency.TotalErrors)
	if stats.MapLatency.AvgLatencyNs > 0 {
		fmt.Printf("   Average Latency:  %s\n", fmtutil.FormatLatency(stats.MapLatency.AvgLatencyNs))
		fmt.Printf("   Min Latency:      %s\n", fmtutil.FormatLatency(stats.MapLatency.MinLatencyNs))
		fmt.Printf("   Max Latency:      %s\n", fmtutil.FormatLatency(stats.MapLatency.MaxLatencyNs))
	}

	// Cache Hit Rate Summary / 缓存命中率摘要
	fmt.Println("\n💾 Cache Hit Rates:")
	fmt.Printf("   Total Hit Rate:   %.2f%% (%d hits / %d misses)\n",
		stats.CacheHitRate.TotalHitRate*100,
		stats.CacheHitRate.TotalHits,
		stats.CacheHitRate.TotalMisses)
	fmt.Printf("   Global Stats:     %.2f%%\n", stats.CacheHitRate.GlobalStatsHitRate*100)
	fmt.Printf("   Drop Details:     %.2f%%\n", stats.CacheHitRate.DropDetailsHitRate*100)
	fmt.Printf("   Pass Details:     %.2f%%\n", stats.CacheHitRate.PassDetailsHitRate*100)
	fmt.Printf("   Map Counts:       %.2f%%\n", stats.CacheHitRate.MapCountsHitRate*100)

	// Traffic Summary / 流量摘要
	fmt.Println("\n🚦 Traffic Statistics:")
	fmt.Printf("   Current PPS:      %s\n", fmtutil.FormatNumber(stats.Traffic.CurrentPPS))
	fmt.Printf("   Peak PPS:         %s\n", fmtutil.FormatNumber(stats.Traffic.PeakPPS))
	fmt.Printf("   Average PPS:      %s\n", fmtutil.FormatNumber(stats.Traffic.AveragePPS))
	fmt.Printf("   Current BPS:      %s/s\n", fmtutil.FormatBytes(stats.Traffic.CurrentBPS))
	fmt.Printf("   Peak BPS:         %s/s\n", fmtutil.FormatBytes(stats.Traffic.PeakBPS))
	fmt.Printf("   Current Drop PPS: %s\n", fmtutil.FormatNumber(stats.Traffic.CurrentDropPPS))
	fmt.Printf("   Current Pass PPS: %s\n", fmtutil.FormatNumber(stats.Traffic.CurrentPassPPS))

	return nil
}

// showMapLatency displays detailed map operation latency statistics
// showMapLatency 显示详细的 Map 操作延迟统计
func showMapLatency(s *sdk.SDK) error {
	perfStats, err := getPerfStats(s)
	if err != nil {
		return err
	}

	stats := perfStats.GetStats()

	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Map Operation Latency Statistics                ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	// Overall statistics / 总体统计
	fmt.Println("\n📈 Overall Statistics:")
	fmt.Printf("   Total Operations: %d\n", stats.MapLatency.TotalOperations)
	fmt.Printf("   Total Errors:     %d\n", stats.MapLatency.TotalErrors)
	if stats.MapLatency.TotalOperations > 0 {
		fmt.Printf("   Error Rate:       %.4f%%\n",
			float64(stats.MapLatency.TotalErrors)/float64(stats.MapLatency.TotalOperations)*100)
	}

	// Per-operation type statistics / 按操作类型统计
	fmt.Println("\n📋 By Operation Type:")
	printOpStats("Read", stats.MapLatency.ReadOps)
	printOpStats("Write", stats.MapLatency.WriteOps)
	printOpStats("Delete", stats.MapLatency.DeleteOps)
	printOpStats("Iterate", stats.MapLatency.IterOps)

	// Per-map statistics / 按 Map 统计
	fmt.Println("\n🗂️  By Map:")
	printOpStats("Blacklist", stats.MapLatency.BlacklistOps)
	printOpStats("Whitelist", stats.MapLatency.WhitelistOps)
	printOpStats("Conntrack", stats.MapLatency.ConntrackOps)
	printOpStats("Rate Limit", stats.MapLatency.RateLimitOps)
	printOpStats("Rule Map", stats.MapLatency.RuleMapOps)
	printOpStats("Stats Map", stats.MapLatency.StatsMapOps)

	return nil
}

// showCacheHitRates displays cache hit rate statistics
// showCacheHitRates 显示缓存命中率统计
func showCacheHitRates(s *sdk.SDK) error {
	perfStats, err := getPerfStats(s)
	if err != nil {
		return err
	}

	stats := perfStats.GetStats()

	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  Cache Hit Rate Statistics                   ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	// Total statistics / 总计统计
	fmt.Println("\n📊 Overall Cache Performance:")
	fmt.Printf("   Total Hits:    %d\n", stats.CacheHitRate.TotalHits)
	fmt.Printf("   Total Misses:  %d\n", stats.CacheHitRate.TotalMisses)
	fmt.Printf("   Hit Rate:      %.2f%%\n", stats.CacheHitRate.TotalHitRate*100)

	// Per-cache statistics / 各缓存统计
	fmt.Println("\n💾 By Cache Type:")
	printCacheStats("Global Stats", stats.CacheHitRate.GlobalStatsHits, stats.CacheHitRate.GlobalStatsMisses, stats.CacheHitRate.GlobalStatsHitRate)
	printCacheStats("Drop Details", stats.CacheHitRate.DropDetailsHits, stats.CacheHitRate.DropDetailsMisses, stats.CacheHitRate.DropDetailsHitRate)
	printCacheStats("Pass Details", stats.CacheHitRate.PassDetailsHits, stats.CacheHitRate.PassDetailsMisses, stats.CacheHitRate.PassDetailsHitRate)
	printCacheStats("Map Counts", stats.CacheHitRate.MapCountsHits, stats.CacheHitRate.MapCountsMisses, stats.CacheHitRate.MapCountsHitRate)

	return nil
}

// showTrafficStats displays real-time traffic statistics
// showTrafficStats 显示实时流量统计
func showTrafficStats(s *sdk.SDK) error {
	perfStats, err := getPerfStats(s)
	if err != nil {
		return err
	}

	// Update traffic stats with current global stats
	// 使用当前全局统计更新流量统计
	pass, drops, err := s.Stats.GetCounters()
	if err != nil {
		return fmt.Errorf("failed to get counters: %w", err)
	}

	totalPackets := pass + drops
	// Estimate bytes (average packet size ~500 bytes for estimation)
	// 估算字节数（平均包大小约 500 字节用于估算）
	totalBytes := totalPackets * 500

	perfStats.UpdateTrafficStats(totalPackets, totalBytes, drops, pass)

	stats := perfStats.GetStats()

	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                Real-time Traffic Statistics                  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	// Uptime / 运行时间
	uptime := time.Duration(stats.Traffic.UptimeSeconds) * time.Second // #nosec G115 // uptime is always reasonable value
	fmt.Printf("\n⏱️  Uptime: %v\n", uptime.Round(time.Second))

	// Packet rates / 数据包速率
	fmt.Println("\n📦 Packet Rates:")
	fmt.Printf("   Current PPS:      %s pps\n", fmtutil.FormatNumber(stats.Traffic.CurrentPPS))
	fmt.Printf("   Peak PPS:         %s pps\n", fmtutil.FormatNumber(stats.Traffic.PeakPPS))
	fmt.Printf("   Average PPS:      %s pps\n", fmtutil.FormatNumber(stats.Traffic.AveragePPS))

	// Byte rates / 字节速率
	fmt.Println("\n📊 Bandwidth:")
	fmt.Printf("   Current BPS:      %s/s\n", fmtutil.FormatBytes(stats.Traffic.CurrentBPS))
	fmt.Printf("   Peak BPS:         %s/s\n", fmtutil.FormatBytes(stats.Traffic.PeakBPS))
	fmt.Printf("   Average BPS:      %s/s\n", fmtutil.FormatBytes(stats.Traffic.AverageBPS))

	// Drop/Pass rates / 丢弃/通过速率
	fmt.Println("\n🚦 Decision Rates:")
	fmt.Printf("   Current Drop PPS: %s pps\n", fmtutil.FormatNumber(stats.Traffic.CurrentDropPPS))
	fmt.Printf("   Peak Drop PPS:    %s pps\n", fmtutil.FormatNumber(stats.Traffic.PeakDropPPS))
	fmt.Printf("   Current Pass PPS: %s pps\n", fmtutil.FormatNumber(stats.Traffic.CurrentPassPPS))
	fmt.Printf("   Peak Pass PPS:    %s pps\n", fmtutil.FormatNumber(stats.Traffic.PeakPassPPS))

	// Totals / 总计
	fmt.Println("\n📈 Totals:")
	fmt.Printf("   Total Packets:    %s\n", fmtutil.FormatNumber(totalPackets))
	fmt.Printf("   Total Drops:      %s\n", fmtutil.FormatNumber(drops))
	fmt.Printf("   Total Passes:     %s\n", fmtutil.FormatNumber(pass))
	if totalPackets > 0 {
		fmt.Printf("   Drop Rate:        %.2f%%\n", float64(drops)/float64(totalPackets)*100)
	}

	return nil
}

// printOpStats prints operation statistics
// printOpStats 打印操作统计
func printOpStats(name string, stats xdp.OperationStats) {
	if stats.Count == 0 {
		return
	}
	fmt.Printf("   %-12s: %d ops, avg %s, errors %d\n",
		name,
		stats.Count,
		fmtutil.FormatLatency(stats.AvgLatency),
		stats.Errors)
}

// printCacheStats prints cache statistics
// printCacheStats 打印缓存统计
func printCacheStats(name string, hits, misses uint64, rate float64) {
	fmt.Printf("   %-12s: %.2f%% (%d hits / %d misses)\n", name, rate*100, hits, misses)
}
