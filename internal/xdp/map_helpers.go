package xdp

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Helper functions for updating maps directly (for one-shot tools)
// 用于直接更新 Map 的辅助函数（适用于一次性工具）

// AddIPPortRule adds a rule for a specific IP and Port combination to a given map.
// AddIPPortRule 向给定 Map 添加特定 IP 和端口组合的规则。
func AddIPPortRule(m *ebpf.Map, ipStr string, port uint16, action uint8) error {
	key, err := NewLpmIPPortKey(ipStr, port)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR: %s", ipStr)
	}

	val := NetXfwRuleValue{
		Counter:   uint64(action),
		ExpiresAt: 0,
	}

	return m.Update(&key, &val, ebpf.UpdateAny)
}

// RemoveRateLimitRule removes a rate limit rule.
// RemoveRateLimitRule 移除一条速率限制规则。
func RemoveRateLimitRule(m *ebpf.Map, cidrStr string) error {
	key, err := NewLpmKey(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR: %s", cidrStr)
	}

	return m.Delete(&key)
}

// RemoveIPPortRule removes a rule for a specific IP and Port combination.
// RemoveIPPortRule 移除特定 IP 和端口组合的规则。
func RemoveIPPortRule(m *ebpf.Map, ipStr string, port uint16) error {
	key, err := NewLpmIPPortKey(ipStr, port)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR: %s", ipStr)
	}

	return m.Delete(&key)
}

// AllowPort adds a port to the allowed ports list.
// AllowPort 向允许端口列表添加一个端口。
func AllowPort(m *ebpf.Map, port uint16) error {
	// BPF_MAP_TYPE_PERCPU_HASH requires a slice of values
	// BPF_MAP_TYPE_PERCPU_HASH 需要一个值切片
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("get possible CPUs: %w", err)
	}
	val := NetXfwRuleValue{
		Counter:   1,
		ExpiresAt: 0,
	}
	vals := make([]NetXfwRuleValue, numCPU)
	for i := 0; i < numCPU; i++ {
		vals[i] = val
	}
	return m.Update(&port, vals, ebpf.UpdateAny)
}

// RemoveAllowedPort removes a port from the allowed ports list.
// RemoveAllowedPort 从允许端口列表中移除一个端口。
func RemoveAllowedPort(m *ebpf.Map, port uint16) error {
	return m.Delete(&port)
}

// AddRateLimitRule adds a rate limit rule.
// AddRateLimitRule 添加一条速率限制规则。
// Note: Uses unified ratelimit_map with ratelimit_value (config + state combined)
// 注意：使用统一的 ratelimit_map 配合 ratelimit_value（配置 + 状态合并）
func AddRateLimitRule(m *ebpf.Map, ipStr string, rate uint64, burst uint64) error {
	key, err := NewIPv6Key(ipStr)
	if err != nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	val := NetXfwRatelimitValue{
		Rate:          rate,
		Burst:         burst,
		ConfigVersion: 1,
		LastTime:      0,
		Tokens:        burst,
	}

	return m.Update(&key, &val, ebpf.UpdateAny)
}
