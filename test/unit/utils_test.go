package unit

import (
	"testing"

	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/stretchr/testify/assert"
)

func TestIPUtil_NormalizeCIDR(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1", "192.168.1.1/32"},
		{"192.168.1.1/24", "192.168.1.0/24"},
		{"10.0.0.1/32", "10.0.0.1/32"},
		{"::1", "::1/128"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/64", "2001:db8::/64"},
	}

	for _, tt := range tests {
		result := iputil.NormalizeCIDR(tt.input)
		assert.Equal(t, tt.expected, result, "NormalizeCIDR(%s)", tt.input)
	}
}

func TestIPUtil_IsIPv6(t *testing.T) {
	assert.False(t, iputil.IsIPv6("192.168.1.1"))
	assert.True(t, iputil.IsIPv6("2001:db8::1"))
	assert.False(t, iputil.IsIPv6("127.0.0.1/24"))
	assert.True(t, iputil.IsIPv6("::1/64"))
}

func TestIPUtil_ParseCIDR(t *testing.T) {
	network, err := iputil.ParseCIDR("192.168.1.1/24")
	assert.NoError(t, err)
	assert.NotNil(t, network)
	assert.Equal(t, "192.168.1.0/24", network.String())

	network6, err := iputil.ParseCIDR("2001:db8::1/64")
	assert.NoError(t, err)
	assert.NotNil(t, network6)
	assert.Equal(t, "2001:db8::/64", network6.String())
}

func TestIPMerge_MergeCIDRs(t *testing.T) {
	input := []string{
		"192.168.1.0/24",
		"192.168.2.0/24",
		"192.168.1.100/32", // This should be covered by the first CIDR
	}

	result, err := ipmerge.MergeCIDRs(input)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	// The merged result should contain at least one CIDR
	containsCIDR := false
	for _, cidr := range result {
		if cidr == "192.168.1.0/24" {
			containsCIDR = true
			break
		}
	}
	assert.True(t, containsCIDR)
}

func TestIPMerge_MergeCIDRsWithThreshold(t *testing.T) {
	input := []string{
		"10.0.0.1/32",
		"10.0.0.2/32",
		"10.0.0.3/32",
		"10.0.0.4/32",
	}

	// Test merging with threshold - this should combine IPs into larger blocks if possible
	result, err := ipmerge.MergeCIDRsWithThreshold(input, 4, 24, 64)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.LessOrEqual(t, len(result), len(input))
}
