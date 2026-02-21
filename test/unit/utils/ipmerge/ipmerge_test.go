package ipmerge_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/netxfw/netxfw/internal/utils/ipmerge"
)

// TestMergeCIDRs tests the CIDR merging functionality
// TestMergeCIDRs 测试 CIDR 合并功能
func TestMergeCIDRs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Merge adjacent /24 to /23",
			input:    []string{"192.168.0.0/24", "192.168.1.0/24"},
			expected: []string{"192.168.0.0/23"},
		},
		{
			name:     "Merge overlapping",
			input:    []string{"10.0.0.0/8", "10.1.0.0/16"},
			expected: []string{"10.0.0.0/8"},
		},
		{
			name:     "Merge contained",
			input:    []string{"192.168.0.0/16", "192.168.1.5"},
			expected: []string{"192.168.0.0/16"},
		},
		{
			name:     "Merge mixed IPs and CIDRs",
			input:    []string{"1.1.1.0", "1.1.1.1", "1.1.1.2", "1.1.1.3"},
			expected: []string{"1.1.1.0/30"},
		},
		{
			name:     "No merge possible",
			input:    []string{"1.1.1.1", "8.8.8.8"},
			expected: []string{"1.1.1.1/32", "8.8.8.8/32"},
		},
		{
			name:     "Complex IPv4",
			input:    []string{"192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24", "192.168.4.0/24"},
			expected: []string{"192.168.1.0/24", "192.168.2.0/23", "192.168.4.0/24"},
		},
		{
			name:     "IPv6 basic",
			input:    []string{"2001:db8::/33", "2001:db8:8000::/33"},
			expected: []string{"2001:db8::/32"},
		},
		{
			name:     "IPv6 single IPs",
			input:    []string{"2001::1", "2001::2"},
			expected: []string{"2001::1/128", "2001::2/128"}, // Not adjacent enough to form /127 (needs ::0 and ::1 or ::2 and ::3)
		},
		{
			name:     "IPv6 /127 merge",
			input:    []string{"2001::2", "2001::3"},
			expected: []string{"2001::2/127"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ipmerge.MergeCIDRs(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			sort.Strings(got)
			sort.Strings(tt.expected)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("MergeCIDRs() = %v, want %v", got, tt.expected)
			}
		})
	}
}
