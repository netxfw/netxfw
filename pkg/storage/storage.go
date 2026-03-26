package storage

import (
	"fmt"
	"net"
	"time"
)

// RuleType defines the type of security rule
// RuleType 定义安全规则的类型。
type RuleType string

const (
	RuleTypeWhitelist RuleType = "whitelist"
	RuleTypeLockList  RuleType = "lock_list"
	RuleTypeIPPort    RuleType = "ip_port"
)

// IPRule represents a simple IP/CIDR rule with optional expiration
// IPRule 表示一个简单的 IP/CIDR 规则，带有可选的过期时间。
type IPRule struct {
	CIDR      string     `toml:"cidr" json:"cidr"`
	ExpiresAt *time.Time `toml:"expires_at,omitempty" json:"expires_at,omitempty"`
}

// IPPortRule represents a rule for a specific IP and port
// IPPortRule 表示特定 IP 和端口的规则。
type IPPortRule struct {
	CIDR      string     `toml:"cidr" json:"cidr" mapstructure:"cidr"`
	Port      uint16     `toml:"port" json:"port" mapstructure:"port"`
	Protocol  string     `toml:"protocol" json:"protocol" mapstructure:"protocol"`
	Action    string     `toml:"action" json:"action" mapstructure:"action"` // "allow" or "deny" / "允许" 或 "拒绝"
	ExpiresAt *time.Time `toml:"expires_at,omitempty" json:"expires_at,omitempty" mapstructure:"expires_at"`
}

// Store is the interface for persisting rules
// Store 是用于持久化规则的接口。
type Store interface {
	// AddIP adds an IP/CIDR to whitelist or lock list
	// AddIP 将 IP/CIDR 添加到白名单或锁定列表。
	AddIP(ruleType RuleType, cidr string, expiresAt *time.Time) error
	// RemoveIP removes an IP/CIDR from whitelist or lock list
	// RemoveIP 从白名单或锁定列表中移除 IP/CIDR。
	RemoveIP(ruleType RuleType, cidr string) error
	// AddIPPortRule adds a complex IP+Port rule
	// AddIPPortRule 添加一个复杂的 IP+端口规则。
	AddIPPortRule(rule IPPortRule) error
	// RemoveIPPortRule removes a complex IP+Port rule
	// RemoveIPPortRule 移除一个复杂的 IP+端口规则。
	RemoveIPPortRule(cidr string, port uint16, protocol string) error

	// LoadAll returns all stored rules
	// LoadAll 返回所有存储的规则。
	LoadAll() (whitelist []IPRule, lockList []IPRule, ipPortRules []IPPortRule, err error)

	// SyncFromMap iterates through XDP maps and updates the store to match
	// SyncFromMap 迭代 XDP Map 并更新存储以匹配。
	// This ensures the store is consistent with the kernel state
	// 这确保了存储与内核状态一致。
	// (Implementation will depend on the specific store)
	// （实现将取决于具体的存储方式）
}

// Helper to normalize CIDR
// NormalizeCIDR 是用于标准化 CIDR 的辅助函数。
func NormalizeCIDR(ipStr string) string {
	ipNet, err := parseCIDR(ipStr)
	if err == nil {
		return ipNet.String()
	}
	return ipStr
}

func parseCIDR(s string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err == nil {
		return ipNet, nil
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid CIDR or IP")
	}

	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}
