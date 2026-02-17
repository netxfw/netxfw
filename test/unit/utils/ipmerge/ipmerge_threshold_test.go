package ipmerge_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/livp123/netxfw/internal/utils/ipmerge"
)

// TestMergeCIDRsWithThreshold tests CIDR merging with threshold
// TestMergeCIDRsWithThreshold 测试带阈值的 CIDR 合并
func TestMergeCIDRsWithThreshold(t *testing.T) {
	tests := []struct {
		name      string
		cidrs     []string
		threshold int
		want      []string
	}{
		{
			name:      "No threshold (disabled)",
			cidrs:     []string{"1.2.3.1", "1.2.3.2", "1.2.3.3"},
			threshold: 0,
			want:      []string{"1.2.3.1/32", "1.2.3.2/31"},
		},
		{
			name:      "Threshold not met",
			cidrs:     []string{"1.2.3.10", "1.2.3.20"},
			threshold: 3,
			want:      []string{"1.2.3.10/32", "1.2.3.20/32"},
		},
		{
			name:      "Threshold met - Promote to /24",
			cidrs:     []string{"1.2.3.10", "1.2.3.20", "1.2.3.30"},
			threshold: 3,
			want:      []string{"1.2.3.0/24"},
		},
		{
			name:      "Threshold met - Promote to /24 (Mixed)",
			cidrs:     []string{"1.2.3.10", "1.2.3.20", "1.2.3.30", "5.5.5.5"},
			threshold: 3,
			want:      []string{"1.2.3.0/24", "5.5.5.5/32"},
		},
		{
			name:      "Already large CIDR preserved",
			cidrs:     []string{"1.2.0.0/16", "1.2.3.1"},
			threshold: 3,
			want:      []string{"1.2.0.0/16"}, // 1.2.3.1 is inside 1.2.0.0/16, so it disappears in initial merge
		},
		{
			name:      "IPv6 Threshold met",
			cidrs:     []string{"2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"},
			threshold: 3,
			want:      []string{"2001:db8::/64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ipmerge.MergeCIDRsWithThreshold(tt.cidrs, tt.threshold, 24, 64)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Normalization for comparison (sort)
			// 排序以便比较
			sort.Strings(got)
			sort.Strings(tt.want)

			// Check logic
			if !compareCIDRs(got, tt.want) {
				t.Errorf("MergeCIDRsWithThreshold() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMergeCIDRsWithCustomMasks tests CIDR merging with custom masks
// TestMergeCIDRsWithCustomMasks 测试带自定义掩码的 CIDR 合并
func TestMergeCIDRsWithCustomMasks(t *testing.T) {
	tests := []struct {
		name      string
		cidrs     []string
		threshold int
		v4Mask    int
		v6Mask    int
		want      []string
	}{
		{
			name:      "Custom V4 Mask /16",
			cidrs:     []string{"10.0.1.1", "10.0.2.1", "10.0.3.1"},
			threshold: 3,
			v4Mask:    16,
			v6Mask:    64,
			want:      []string{"10.0.0.0/16"},
		},
		{
			name:      "Custom V6 Mask /48",
			cidrs:     []string{"2001:db8:1:1::1", "2001:db8:1:2::1", "2001:db8:1:3::1"},
			threshold: 3,
			v4Mask:    24,
			v6Mask:    48,
			want:      []string{"2001:db8:1::/48"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ipmerge.MergeCIDRsWithThreshold(tt.cidrs, tt.threshold, tt.v4Mask, tt.v6Mask)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			sort.Strings(got)
			sort.Strings(tt.want)
			if !compareCIDRs(got, tt.want) {
				t.Errorf("MergeCIDRsWithThreshold() = %v, want %v", got, tt.want)
			}
		})
	}
}

// compareCIDRs compares two slices of CIDRs
// compareCIDRs 比较两个 CIDR 切片
func compareCIDRs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	return reflect.DeepEqual(a, b)
}
