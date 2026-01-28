package storage

import (
	"net"
	"time"
)

// RuleType defines the type of security rule
type RuleType string

const (
	RuleTypeWhitelist RuleType = "whitelist"
	RuleTypeLockList  RuleType = "lock_list"
	RuleTypeIPPort    RuleType = "ip_port"
)

// IPRule represents a simple IP/CIDR rule with optional expiration
type IPRule struct {
	CIDR      string     `yaml:"cidr" json:"cidr"`
	ExpiresAt *time.Time `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`
}

// IPPortRule represents a rule for a specific IP and port
type IPPortRule struct {
	CIDR      string     `yaml:"cidr" json:"cidr" mapstructure:"cidr"`
	Port      uint16     `yaml:"port" json:"port" mapstructure:"port"`
	Protocol  string     `yaml:"protocol" json:"protocol" mapstructure:"protocol"`
	Action    string     `yaml:"action" json:"action" mapstructure:"action"` // "allow" or "deny"
	ExpiresAt *time.Time `yaml:"expires_at,omitempty" json:"expires_at,omitempty" mapstructure:"expires_at"`
}

// Store is the interface for persisting rules
type Store interface {
	// AddIP adds an IP/CIDR to whitelist or lock list
	AddIP(ruleType RuleType, cidr string, expiresAt *time.Time) error
	// RemoveIP removes an IP/CIDR from whitelist or lock list
	RemoveIP(ruleType RuleType, cidr string) error
	// AddIPPortRule adds a complex IP+Port rule
	AddIPPortRule(rule IPPortRule) error
	// RemoveIPPortRule removes a complex IP+Port rule
	RemoveIPPortRule(cidr string, port uint16, protocol string) error

	// LoadAll returns all stored rules
	LoadAll() (whitelist []IPRule, lockList []IPRule, ipPortRules []IPPortRule, err error)

	// SyncFromMap iterates through XDP maps and updates the store to match
	// This ensures the store is consistent with the kernel state
	// (Implementation will depend on the specific store)
}

// Helper to normalize CIDR
func NormalizeCIDR(ipStr string) string {
	if !contains(ipStr, "/") {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return ipStr
		}
		if ip.To4() != nil {
			return ipStr + "/32"
		}
		return ipStr + "/128"
	}
	return ipStr
}

func contains(s, substr string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == substr[0] {
			match := true
			for j := 1; j < len(substr); j++ {
				if i+j >= len(s) || s[i+j] != substr[j] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}
