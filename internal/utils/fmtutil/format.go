// Package fmtutil provides formatting utilities for human-readable output.
// Package fmtutil 提供用于人类可读输出的格式化工具。
package fmtutil

import (
	"fmt"
	"math"
	"time"
)

// FormatNumber formats large numbers with K/M/G suffixes.
// FormatNumber 使用 K/M/G 后缀格式化大数字。
func FormatNumber(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.2fK", float64(n)/1000)
	}
	if n < 1000000000 {
		return fmt.Sprintf("%.2fM", float64(n)/1000000)
	}
	return fmt.Sprintf("%.2fG", float64(n)/1000000000)
}

// FormatNumberWithComma formats a number with thousand separators.
// FormatNumberWithComma 格式化数字，添加千位分隔符。
func FormatNumberWithComma(n uint64) string {
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

// FormatBytes formats bytes to human readable format.
// FormatBytes 将字节格式化为可读格式。
func FormatBytes(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%dB", b)
	}
	if b < 1048576 {
		return fmt.Sprintf("%.2fKB", float64(b)/1024)
	}
	if b < 1073741824 {
		return fmt.Sprintf("%.2fMB", float64(b)/1048576)
	}
	return fmt.Sprintf("%.2fGB", float64(b)/1073741824)
}

// FormatLatency formats latency in nanoseconds to human readable format.
// FormatLatency 将纳秒延迟格式化为可读格式。
func FormatLatency(ns uint64) string {
	if ns == 0 {
		return "0ns"
	}
	if ns < 1000 {
		return fmt.Sprintf("%dns", ns)
	}
	if ns < 1000000 {
		return fmt.Sprintf("%.2fµs", float64(ns)/1000)
	}
	if ns < 1000000000 {
		return fmt.Sprintf("%.2fms", float64(ns)/1000000)
	}
	return fmt.Sprintf("%.2fs", float64(ns)/1000000000)
}

// FormatDuration formats a duration to human readable format.
// FormatDuration 将持续时间格式化为可读格式。
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return d.String()
	}

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	result := ""
	for i, part := range parts {
		if i > 0 {
			result += " "
		}
		result += part
	}
	return result
}

// FormatPercent formats a percentage value with proper precision.
// FormatPercent 格式化百分比值，使用适当的精度。
func FormatPercent(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "0.00%"
	}
	return fmt.Sprintf("%.2f%%", value)
}

// FormatBPS formats bytes per second to human readable format (in bits).
// FormatBPS 将每秒字节数格式化为人类可读格式（以比特为单位）。
func FormatBPS(bps uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	bits := bps * 8 // Convert to bits / 转换为比特
	switch {
	case bits >= GB*8:
		return fmt.Sprintf("%.1f Gbps", float64(bits)/float64(GB*8))
	case bits >= MB*8:
		return fmt.Sprintf("%.1f Mbps", float64(bits)/float64(MB*8))
	case bits >= KB*8:
		return fmt.Sprintf("%.1f Kbps", float64(bits)/float64(KB*8))
	default:
		return fmt.Sprintf("%d bps", bits)
	}
}

// FormatRate formats a rate value with appropriate unit.
// FormatRate 格式化速率值，使用适当的单位。
func FormatRate(rate float64, unit string) string {
	if rate < 1000 {
		return fmt.Sprintf("%.2f %s", rate, unit)
	}
	if rate < 1000000 {
		return fmt.Sprintf("%.2f K%s", rate/1000, unit)
	}
	if rate < 1000000000 {
		return fmt.Sprintf("%.2f M%s", rate/1000000, unit)
	}
	return fmt.Sprintf("%.2f G%s", rate/1000000000, unit)
}
