package agent

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// StatsAPI interface for statistics operations (for testing and decoupling)
// StatsAPI 统计操作接口（用于测试和解耦）
type StatsAPI interface {
	GetDropDetails() ([]sdk.DropDetailEntry, error)
	GetPassDetails() ([]sdk.DropDetailEntry, error)
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
func showDetailStatistics[T DetailEntry](w io.Writer, details []T, cfg detailStatsConfig) {
	if len(details) == 0 {
		return
	}

	fmt.Fprintf(w, "\n%s\n", cfg.title)
	sort.Slice(details, func(i, j int) bool {
		return details[i].GetCount() > details[j].GetCount()
	})

	maxShow := getTopNFromConfig()
	if len(details) < maxShow {
		maxShow = len(details)
	}

	fmt.Fprintf(w, "\n   %s\n", cfg.subTitle)
	if cfg.showRate && cfg.currentPPS > 0 {
		fmt.Fprintf(w, "   %-20s %-8s %-40s %-8s %-10s %-10s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count", "Rate/s", "Percent")
		fmt.Fprintf(w, "   %s\n", strings.Repeat("-", 115))
	} else {
		fmt.Fprintf(w, "   %-20s %-8s %-40s %-8s %-10s %s\n", "Reason", "Proto", "Source IP", "DstPort", "Count", "Percent")
		fmt.Fprintf(w, "   %s\n", strings.Repeat("-", 100))
	}

	for i := 0; i < maxShow; i++ {
		d := details[i]
		percent := calculatePercentGeneric(d.GetCount(), cfg.totalCount)

		if cfg.showRate && cfg.currentPPS > 0 {
			ratePerSec := calculateRateGeneric(cfg.currentPPS, percent)
			fmt.Fprintf(w, "   %-20s %-8s %-40s %-8d %-10d %-10s %.2f%%\n",
				cfg.reasonFunc(d.GetReason()),
				protocolToString(d.GetProtocol()),
				d.GetSrcIP(),
				d.GetDstPort(),
				d.GetCount(),
				app.FormatNumberWithComma(ratePerSec),
				percent)
		} else {
			fmt.Fprintf(w, "   %-20s %-8s %-40s %-8d %-10d %.2f%%\n",
				cfg.reasonFunc(d.GetReason()),
				protocolToString(d.GetProtocol()),
				d.GetSrcIP(),
				d.GetDstPort(),
				d.GetCount(),
				percent)
		}
	}
	if len(details) > 10 {
		fmt.Fprintf(w, "   ... and more\n")
	}

	showReasonSummary(w, details, cfg)
}

// showReasonSummary displays a summary of reasons using generics.
// showReasonSummary 使用泛型显示原因汇总。
func showReasonSummary[T DetailEntry](w io.Writer, details []T, cfg detailStatsConfig) {
	reasonSummary := make(map[string]uint64)
	for _, d := range details {
		reason := cfg.reasonFunc(d.GetReason())
		reasonSummary[reason] += d.GetCount()
	}
	if len(reasonSummary) > 0 {
		fmt.Fprintln(w, "\n   [RATE] Reason Summary:")
		for reason, count := range reasonSummary {
			percent := calculatePercentGeneric(count, cfg.totalCount)
			if cfg.showRate && cfg.currentPPS > 0 {
				ratePerSec := calculateRateGeneric(cfg.currentPPS, percent)
				fmt.Fprintf(w, "      %s: %d (%.2f%%) - %s/s\n", reason, count, percent, app.FormatNumberWithComma(ratePerSec))
			} else {
				fmt.Fprintf(w, "      %s: %d (%.2f%%)\n", reason, count, percent)
			}
		}
	}
}

// getTopNFromConfig returns the top N value from config, defaulting to 10
// getTopNFromConfig 从配置获取 Top N 值，默认为 10
func getTopNFromConfig() int {
	cfg, err := app.LoadConfig()
	if err == nil && cfg != nil && cfg.Metrics.TopN > 0 {
		return cfg.Metrics.TopN
	}
	return 10
}

// getThresholdsFromConfig returns usage thresholds from config
// getThresholdsFromConfig 从配置获取使用率阈值
func getThresholdsFromConfig() (critical, high, medium int) {
	cfg, err := app.LoadConfig()
	if err == nil && cfg != nil {
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
	return 90, 75, 50
}
