package app

import (
	"time"

	"github.com/netxfw/netxfw/internal/utils/fmtutil"
)

// FormatNumber formats a number to a compact human readable string.
func FormatNumber(n uint64) string {
	return fmtutil.FormatNumber(n)
}

// FormatNumberWithComma formats a number with thousand separators.
func FormatNumberWithComma(n uint64) string {
	return fmtutil.FormatNumberWithComma(n)
}

// FormatBytes formats bytes to a human readable string.
func FormatBytes(b uint64) string {
	return fmtutil.FormatBytes(b)
}

// FormatBPS formats bytes per second to human readable format (in bits).
func FormatBPS(bps uint64) string {
	return fmtutil.FormatBPS(bps)
}

// FormatLatency formats latency in nanoseconds to a human readable string.
func FormatLatency(ns uint64) string {
	return fmtutil.FormatLatency(ns)
}

// FormatDuration formats a duration to human readable format.
func FormatDuration(d time.Duration) string {
	return fmtutil.FormatDuration(d)
}
