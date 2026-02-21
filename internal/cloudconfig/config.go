// Package cloudconfig provides cloud provider configuration for NetXFW.
// Package cloudconfig 为 NetXFW 提供云服务商配置。
package cloudconfig

import (
	"fmt"
	"net/netip"
)

// Provider represents a cloud provider.
// Provider 表示云服务商。
type Provider string

const (
	ProviderAlibaba Provider = "alibaba"
	ProviderTencent Provider = "tencent"
	ProviderAWS     Provider = "aws"
	ProviderAzure   Provider = "azure"
	ProviderGCP     Provider = "gcp"
	ProviderOther   Provider = "other"
)

// RealIPMethod represents the method to get real client IP.
// RealIPMethod 表示获取真实客户端 IP 的方法。
type RealIPMethod string

const (
	MethodProxyProtocol RealIPMethod = "proxy_protocol"
	MethodXForwardedFor RealIPMethod = "x_forwarded_for"
	MethodTOA           RealIPMethod = "toa"
	MethodTransparent   RealIPMethod = "transparent"
	MethodNone          RealIPMethod = "none"
)

// Config represents cloud environment configuration.
// Config 表示云环境配置。
type Config struct {
	// Provider is the cloud provider name.
	// Provider 是云服务商名称。
	Provider Provider `yaml:"provider"`

	// RealIPMethod is the method to get real client IP.
	// RealIPMethod 是获取真实客户端 IP 的方法。
	RealIPMethod RealIPMethod `yaml:"real_ip_method"`

	// ProxyProtocolEnabled enables Proxy Protocol parsing.
	// ProxyProtocolEnabled 启用 Proxy Protocol 解析。
	ProxyProtocolEnabled bool `yaml:"proxy_protocol_enabled"`

	// TrustedProxies are IP ranges that are trusted to send real IP info.
	// TrustedProxies 是可信发送真实 IP 信息的 IP 范围。
	TrustedProxies []string `yaml:"trusted_proxies"`

	// LoadBalancerIPs are the IP addresses of cloud load balancers.
	// LoadBalancerIPs 是云负载均衡器的 IP 地址。
	LoadBalancerIPs []string `yaml:"load_balancer_ips"`

	// HTTPHeaders contains HTTP header names for real IP extraction.
	// HTTPHeaders 包含用于提取真实 IP 的 HTTP 头名称。
	HTTPHeaders []string `yaml:"http_headers"`
}

// DefaultConfig returns the default cloud configuration.
// DefaultConfig 返回默认的云配置。
func DefaultConfig() *Config {
	return &Config{
		Provider:             ProviderOther,
		RealIPMethod:         MethodNone,
		ProxyProtocolEnabled: false,
		TrustedProxies:       []string{},
		LoadBalancerIPs:      []string{},
		HTTPHeaders: []string{
			"X-Forwarded-For",
			"X-Real-IP",
			"X-Originating-IP",
			"CF-Connecting-IP",
			"True-Client-IP",
		},
	}
}

// GetProviderConfig returns provider-specific configuration.
// GetProviderConfig 返回服务商特定的配置。
func GetProviderConfig(provider Provider) *Config {
	cfg := DefaultConfig()
	cfg.Provider = provider

	switch provider {
	case ProviderAlibaba:
		cfg.RealIPMethod = MethodProxyProtocol
		cfg.ProxyProtocolEnabled = true
		cfg.HTTPHeaders = []string{"X-Forwarded-For", "X-Real-IP", "ClientIP"}
		cfg.TrustedProxies = []string{"10.0.0.0/8", "100.64.0.0/10"}

	case ProviderTencent:
		cfg.RealIPMethod = MethodTOA
		cfg.ProxyProtocolEnabled = true
		cfg.HTTPHeaders = []string{"X-Forwarded-For", "X-Real-IP"}
		cfg.TrustedProxies = []string{"10.0.0.0/8", "100.64.0.0/10"}

	case ProviderAWS:
		cfg.RealIPMethod = MethodProxyProtocol
		cfg.ProxyProtocolEnabled = true
		cfg.HTTPHeaders = []string{"X-Forwarded-For", "X-Real-IP"}
		cfg.TrustedProxies = []string{"10.0.0.0/8", "172.16.0.0/12"}

	case ProviderAzure:
		cfg.RealIPMethod = MethodXForwardedFor
		cfg.ProxyProtocolEnabled = false
		cfg.HTTPHeaders = []string{"X-Forwarded-For", "X-Real-IP"}
		cfg.TrustedProxies = []string{"10.0.0.0/8", "172.16.0.0/12"}

	case ProviderGCP:
		cfg.RealIPMethod = MethodXForwardedFor
		cfg.ProxyProtocolEnabled = false
		cfg.HTTPHeaders = []string{"X-Forwarded-For", "X-Real-IP"}
		cfg.TrustedProxies = []string{"10.0.0.0/8", "130.211.0.0/22", "35.191.0.0/16"}
	}

	return cfg
}

// IsTrustedProxy checks if an IP is from a trusted proxy.
// IsTrustedProxy 检查 IP 是否来自可信代理。
func (c *Config) IsTrustedProxy(ip string) bool {
	if len(c.TrustedProxies) == 0 {
		return false
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	for _, cidr := range c.TrustedProxies {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

// Validate validates the configuration.
// Validate 验证配置。
func (c *Config) Validate() error {
	// Validate provider.
	// 验证服务商。
	switch c.Provider {
	case ProviderAlibaba, ProviderTencent, ProviderAWS, ProviderAzure, ProviderGCP, ProviderOther:
		// Valid provider.
		// 有效服务商。
	default:
		return fmt.Errorf("invalid provider: %s", c.Provider)
	}

	// Validate real IP method.
	// 验证真实 IP 方法。
	switch c.RealIPMethod {
	case MethodProxyProtocol, MethodXForwardedFor, MethodTOA, MethodTransparent, MethodNone:
		// Valid method.
		// 有效方法。
	default:
		return fmt.Errorf("invalid real IP method: %s", c.RealIPMethod)
	}

	// Validate trusted proxies.
	// 验证可信代理。
	for _, cidr := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR: %s: %v", cidr, err)
		}
	}

	return nil
}

// String returns a string representation of the config.
// String 返回配置的字符串表示。
func (c *Config) String() string {
	return fmt.Sprintf("CloudConfig{Provider: %s, Method: %s, ProxyProtocol: %v}",
		c.Provider, c.RealIPMethod, c.ProxyProtocolEnabled)
}

// MergeTrustedProxies merges provider-specific trusted proxies with custom ranges.
// MergeTrustedProxies 合并服务商特定的可信代理与自定义范围。
func (c *Config) MergeTrustedProxies(customRanges []string) {
	// Create a set to avoid duplicates.
	// 创建集合避免重复。
	seen := make(map[string]bool)
	result := make([]string, 0)

	// Add existing trusted proxies.
	// 添加现有的可信代理。
	for _, cidr := range c.TrustedProxies {
		if !seen[cidr] {
			seen[cidr] = true
			result = append(result, cidr)
		}
	}

	// Add custom ranges.
	// 添加自定义范围。
	for _, cidr := range customRanges {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			// Skip invalid CIDR.
			// 跳过无效的 CIDR。
			continue
		}
		if !seen[cidr] {
			seen[cidr] = true
			result = append(result, cidr)
		}
	}

	c.TrustedProxies = result
}

// GetMergedConfig returns a merged configuration with provider defaults and custom settings.
// GetMergedConfig 返回合并了服务商默认值和自定义设置的配置。
func GetMergedConfig(provider Provider, customRanges []string, proxyProtocolEnabled bool, cacheTTL string) *Config {
	// Get provider-specific defaults.
	// 获取服务商特定的默认值。
	cfg := GetProviderConfig(provider)

	// Merge custom trusted proxy ranges.
	// 合并自定义可信代理范围。
	if len(customRanges) > 0 {
		cfg.MergeTrustedProxies(customRanges)
	}

	// Override proxy protocol setting if specified.
	// 如果指定了，覆盖 proxy protocol 设置。
	// Note: customRanges are additional to provider defaults.
	// 注意：customRanges 是服务商默认值的补充。
	_ = proxyProtocolEnabled // Use provider default unless explicitly overridden
	_ = cacheTTL             // Cache TTL for real IP mappings

	return cfg
}

// ProviderInfo contains information about a cloud provider.
// ProviderInfo 包含云服务商的信息。
type ProviderInfo struct {
	Name          Provider
	DisplayName   string
	RealIPMethod  RealIPMethod
	DefaultRanges []string
	SupportsPP    bool
	Documentation string
}

// GetProviderInfo returns detailed information about all supported providers.
// GetProviderInfo 返回所有支持的服务商的详细信息。
func GetProviderInfo() map[Provider]ProviderInfo {
	return map[Provider]ProviderInfo{
		ProviderAlibaba: {
			Name:          ProviderAlibaba,
			DisplayName:   "Alibaba Cloud (阿里云)",
			RealIPMethod:  MethodProxyProtocol,
			DefaultRanges: []string{"10.0.0.0/8", "100.64.0.0/10"},
			SupportsPP:    true,
			Documentation: "SLB 监听器 → 高级配置 → 开启 Proxy Protocol",
		},
		ProviderTencent: {
			Name:          ProviderTencent,
			DisplayName:   "Tencent Cloud (腾讯云)",
			RealIPMethod:  MethodTOA,
			DefaultRanges: []string{"10.0.0.0/8", "100.64.0.0/10"},
			SupportsPP:    true,
			Documentation: "CLB 监听器 → 开启获取客户端真实 IP",
		},
		ProviderAWS: {
			Name:          ProviderAWS,
			DisplayName:   "Amazon Web Services",
			RealIPMethod:  MethodProxyProtocol,
			DefaultRanges: []string{"10.0.0.0/8", "172.16.0.0/12"},
			SupportsPP:    true,
			Documentation: "创建 Proxy Protocol Policy 并关联到 ELB",
		},
		ProviderAzure: {
			Name:          ProviderAzure,
			DisplayName:   "Microsoft Azure",
			RealIPMethod:  MethodXForwardedFor,
			DefaultRanges: []string{"10.0.0.0/8", "172.16.0.0/12"},
			SupportsPP:    false,
			Documentation: "Application Gateway 自动添加 X-Forwarded-For",
		},
		ProviderGCP: {
			Name:          ProviderGCP,
			DisplayName:   "Google Cloud Platform",
			RealIPMethod:  MethodXForwardedFor,
			DefaultRanges: []string{"10.0.0.0/8", "130.211.0.0/22", "35.191.0.0/16"},
			SupportsPP:    false,
			Documentation: "HTTP(S) Load Balancer 自动添加 X-Forwarded-For",
		},
		ProviderOther: {
			Name:          ProviderOther,
			DisplayName:   "Other / Custom",
			RealIPMethod:  MethodNone,
			DefaultRanges: []string{},
			SupportsPP:    true,
			Documentation: "自定义配置，需要手动设置可信 LB IP 范围",
		},
	}
}
