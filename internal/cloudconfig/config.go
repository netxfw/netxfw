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
