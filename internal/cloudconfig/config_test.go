// Package cloudconfig provides cloud provider configuration for NetXFW.
// Package cloudconfig 为 NetXFW 提供云服务商配置。
package cloudconfig

import (
	"testing"
)

// TestGetProviderConfig tests the GetProviderConfig function.
// TestGetProviderConfig 测试 GetProviderConfig 函数。
func TestGetProviderConfig(t *testing.T) {
	tests := []struct {
		provider       Provider
		expectedMethod RealIPMethod
		expectedPP     bool
		minRanges      int
	}{
		{ProviderAlibaba, MethodProxyProtocol, true, 2},
		{ProviderTencent, MethodTOA, true, 2},
		{ProviderAWS, MethodProxyProtocol, true, 2},
		{ProviderAzure, MethodXForwardedFor, false, 2},
		{ProviderGCP, MethodXForwardedFor, false, 2},
		{ProviderOther, MethodNone, false, 0},
	}

	for _, tc := range tests {
		cfg := GetProviderConfig(tc.provider)
		if cfg.Provider != tc.provider {
			t.Errorf("Provider %s: expected provider %s, got %s", tc.provider, tc.provider, cfg.Provider)
		}
		if cfg.RealIPMethod != tc.expectedMethod {
			t.Errorf("Provider %s: expected method %s, got %s", tc.provider, tc.expectedMethod, cfg.RealIPMethod)
		}
		if cfg.ProxyProtocolEnabled != tc.expectedPP {
			t.Errorf("Provider %s: expected PP %v, got %v", tc.provider, tc.expectedPP, cfg.ProxyProtocolEnabled)
		}
		if len(cfg.TrustedProxies) < tc.minRanges {
			t.Errorf("Provider %s: expected at least %d ranges, got %d", tc.provider, tc.minRanges, len(cfg.TrustedProxies))
		}
	}
}

// TestMergeTrustedProxies tests the MergeTrustedProxies function.
// TestMergeTrustedProxies 测试 MergeTrustedProxies 函数。
func TestMergeTrustedProxies(t *testing.T) {
	cfg := &Config{
		Provider:             ProviderAlibaba,
		TrustedProxies:       []string{"10.0.0.0/8"},
		ProxyProtocolEnabled: true,
	}

	// Merge custom ranges.
	// 合并自定义范围。
	customRanges := []string{"192.168.0.0/16", "10.0.0.0/8"} // 10.0.0.0/8 is duplicate
	cfg.MergeTrustedProxies(customRanges)

	// Should have 2 unique ranges.
	// 应该有 2 个唯一范围。
	if len(cfg.TrustedProxies) != 2 {
		t.Errorf("Expected 2 unique ranges, got %d: %v", len(cfg.TrustedProxies), cfg.TrustedProxies)
	}

	// Check both ranges exist.
	// 检查两个范围都存在。
	found := make(map[string]bool)
	for _, r := range cfg.TrustedProxies {
		found[r] = true
	}
	if !found["10.0.0.0/8"] || !found["192.168.0.0/16"] {
		t.Errorf("Expected both ranges, got %v", cfg.TrustedProxies)
	}
}

// TestIsTrustedProxy tests the IsTrustedProxy function.
// TestIsTrustedProxy 测试 IsTrustedProxy 函数。
func TestIsTrustedProxy(t *testing.T) {
	cfg := &Config{
		Provider:       ProviderAlibaba,
		TrustedProxies: []string{"10.0.0.0/8", "192.168.1.0/24"},
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.1.100", true},
		{"10.255.255.255", true},
		{"192.168.1.50", true},
		{"192.168.2.1", false},
		{"172.16.0.1", false},
		{"invalid", false},
	}

	for _, tc := range tests {
		result := cfg.IsTrustedProxy(tc.ip)
		if result != tc.expected {
			t.Errorf("IsTrustedProxy(%s) = %v, expected %v", tc.ip, result, tc.expected)
		}
	}
}

// TestValidate tests the Validate function.
// TestValidate 测试 Validate 函数。
func TestValidate(t *testing.T) {
	// Valid config.
	// 有效配置。
	validCfg := &Config{
		Provider:       ProviderAlibaba,
		RealIPMethod:   MethodProxyProtocol,
		TrustedProxies: []string{"10.0.0.0/8"},
	}
	if err := validCfg.Validate(); err != nil {
		t.Errorf("Valid config failed validation: %v", err)
	}

	// Invalid provider.
	// 无效服务商。
	invalidProvider := &Config{
		Provider:     Provider("invalid"),
		RealIPMethod: MethodProxyProtocol,
	}
	if err := invalidProvider.Validate(); err == nil {
		t.Error("Expected error for invalid provider")
	}

	// Invalid method.
	// 无效方法。
	invalidMethod := &Config{
		Provider:     ProviderAlibaba,
		RealIPMethod: RealIPMethod("invalid"),
	}
	if err := invalidMethod.Validate(); err == nil {
		t.Error("Expected error for invalid method")
	}

	// Invalid CIDR.
	// 无效 CIDR。
	invalidCIDR := &Config{
		Provider:       ProviderAlibaba,
		RealIPMethod:   MethodProxyProtocol,
		TrustedProxies: []string{"invalid-cidr"},
	}
	if err := invalidCIDR.Validate(); err == nil {
		t.Error("Expected error for invalid CIDR")
	}
}

// TestGetMergedConfig tests the GetMergedConfig function.
// TestGetMergedConfig 测试 GetMergedConfig 函数。
func TestGetMergedConfig(t *testing.T) {
	customRanges := []string{"192.168.0.0/16"}
	cfg := GetMergedConfig(ProviderAlibaba, customRanges, true, "5m")

	// Should have provider defaults + custom ranges.
	// 应该有服务商默认值 + 自定义范围。
	if len(cfg.TrustedProxies) < 2 {
		t.Errorf("Expected at least 2 trusted proxies, got %d", len(cfg.TrustedProxies))
	}

	// Check custom range is included.
	// 检查自定义范围是否包含。
	found := false
	for _, r := range cfg.TrustedProxies {
		if r == "192.168.0.0/16" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Custom range not found in merged config")
	}
}

// TestGetProviderInfo tests the GetProviderInfo function.
// TestGetProviderInfo 测试 GetProviderInfo 函数。
func TestGetProviderInfo(t *testing.T) {
	info := GetProviderInfo()

	// Check all providers have info.
	// 检查所有服务商都有信息。
	providers := []Provider{ProviderAlibaba, ProviderTencent, ProviderAWS, ProviderAzure, ProviderGCP, ProviderOther}
	for _, p := range providers {
		if _, ok := info[p]; !ok {
			t.Errorf("Missing provider info for %s", p)
		}
	}

	// Check Alibaba info.
	// 检查阿里云信息。
	alibaba := info[ProviderAlibaba]
	if alibaba.DisplayName == "" {
		t.Error("Alibaba display name is empty")
	}
	if !alibaba.SupportsPP {
		t.Error("Alibaba should support Proxy Protocol")
	}
	if len(alibaba.DefaultRanges) == 0 {
		t.Error("Alibaba should have default ranges")
	}
}
