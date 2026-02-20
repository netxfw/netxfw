//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/utils/iputil"
)

// TimedMapOperations provides timed map operation wrappers.
// TimedMapOperations 提供带计时的 Map 操作包装器。
type TimedMapOperations struct {
	manager *Manager
}

// NewTimedMapOperations creates a new timed map operations wrapper.
// NewTimedMapOperations 创建新的带计时的 Map 操作包装器。
func NewTimedMapOperations(m *Manager) *TimedMapOperations {
	return &TimedMapOperations{manager: m}
}

// LockIPTimed adds an IP to the lock list with timing.
// LockIPTimed 将 IP 添加到锁定列表并计时。
func (t *TimedMapOperations) LockIPTimed(mapPtr *ebpf.Map, cidrStr string, mapName string) error {
	if t.manager.perfStats == nil {
		return LockIP(mapPtr, cidrStr)
	}

	helper := NewMapOpHelper(t.manager.perfStats, mapName)
	return helper.TimeWrite(func() error {
		return LockIP(mapPtr, cidrStr)
	})
}

// UnlockIPTimed removes an IP from the lock list with timing.
// UnlockIPTimed 从锁定列表中移除 IP 并计时。
func (t *TimedMapOperations) UnlockIPTimed(mapPtr *ebpf.Map, cidrStr string, mapName string) error {
	if t.manager.perfStats == nil {
		return UnlockIP(mapPtr, cidrStr)
	}

	helper := NewMapOpHelper(t.manager.perfStats, mapName)
	return helper.TimeDelete(func() error {
		return UnlockIP(mapPtr, cidrStr)
	})
}

// AllowIPTimed adds an IP to the whitelist with timing.
// AllowIPTimed 将 IP 添加到白名单并计时。
func (t *TimedMapOperations) AllowIPTimed(mapPtr *ebpf.Map, cidrStr string, port uint16, mapName string) error {
	if t.manager.perfStats == nil {
		return AllowIP(mapPtr, cidrStr, port)
	}

	helper := NewMapOpHelper(t.manager.perfStats, mapName)
	return helper.TimeWrite(func() error {
		return AllowIP(mapPtr, cidrStr, port)
	})
}

// IsIPInMapTimed checks if an IP is in the map with timing.
// IsIPInMapTimed 检查 IP 是否在 Map 中并计时。
func (t *TimedMapOperations) IsIPInMapTimed(mapPtr *ebpf.Map, cidrStr string, mapName string) (bool, error) {
	if t.manager.perfStats == nil {
		return IsIPInMap(mapPtr, cidrStr)
	}

	var result bool
	helper := NewMapOpHelper(t.manager.perfStats, mapName)
	err := helper.TimeRead(func() error {
		var err error
		result, err = IsIPInMap(mapPtr, cidrStr)
		return err
	})
	return result, err
}

// ListWhitelistIPsTimed lists whitelisted IPs with timing.
// ListWhitelistIPsTimed 列出白名单 IP 并计时。
func (t *TimedMapOperations) ListWhitelistIPsTimed(mapPtr *ebpf.Map, limit int, search string, mapName string) ([]string, int, error) {
	if t.manager.perfStats == nil {
		return ListWhitelistIPs(mapPtr, limit, search)
	}

	var ips []string
	var count int
	helper := NewMapOpHelper(t.manager.perfStats, mapName)
	err := helper.TimeIter(func() error {
		var err error
		ips, count, err = ListWhitelistIPs(mapPtr, limit, search)
		return err
	})
	return ips, count, err
}

// AddIPPortRuleTimed adds an IP+Port rule with timing.
// AddIPPortRuleTimed 添加 IP+端口规则并计时。
func (t *TimedMapOperations) AddIPPortRuleTimed(mapPtr *ebpf.Map, ipNet *net.IPNet, port uint16, action uint8, expiresAt *time.Time, mapName string) error {
	if t.manager.perfStats == nil {
		return AddIPPortRuleToMap(mapPtr, ipNet, port, action, expiresAt)
	}

	helper := NewMapOpHelper(t.manager.perfStats, mapName)
	return helper.TimeWrite(func() error {
		return AddIPPortRuleToMap(mapPtr, ipNet, port, action, expiresAt)
	})
}

// RemoveIPPortRuleTimed removes an IP+Port rule with timing.
// RemoveIPPortRuleTimed 移除 IP+端口规则并计时。
func (t *TimedMapOperations) RemoveIPPortRuleTimed(mapPtr *ebpf.Map, ipNet *net.IPNet, port uint16, mapName string) error {
	if t.manager.perfStats == nil {
		return RemoveIPPortRuleFromMap(mapPtr, ipNet, port)
	}

	helper := NewMapOpHelper(t.manager.perfStats, mapName)
	return helper.TimeDelete(func() error {
		return RemoveIPPortRuleFromMap(mapPtr, ipNet, port)
	})
}

// BlockDynamicTimed adds an IP to the dynamic blocklist with timing.
// BlockDynamicTimed 将 IP 添加到动态黑名单并计时。
func (t *TimedMapOperations) BlockDynamicTimed(ipStr string, ttl time.Duration, mapName string) error {
	if t.manager.perfStats == nil {
		return t.manager.BlockDynamic(ipStr, ttl)
	}

	helper := NewMapOpHelper(t.manager.perfStats, mapName)
	return helper.TimeWrite(func() error {
		return t.manager.BlockDynamic(ipStr, ttl)
	})
}

// Manager methods with timing integration.
// 带计时集成的 Manager 方法。

// BlockStaticTimed adds an IP to the static blocklist with timing.
// BlockStaticTimed 将 IP 添加到静态黑名单并计时。
func (m *Manager) BlockStaticTimed(ipStr string, persistFile string) error {
	ipNet, err := iputil.ParseCIDR(ipStr)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR %s: %w", ipStr, err)
	}
	cidr := ipNet.String()

	mapObj := m.LockList()

	if m.perfStats == nil {
		if err := LockIP(mapObj, cidr); err != nil {
			return fmt.Errorf("failed to add to static blacklist %s: %v", cidr, err)
		}
	} else {
		helper := NewMapOpHelper(m.perfStats, "blacklist")
		if err := helper.TimeWrite(func() error {
			return LockIP(mapObj, cidr)
		}); err != nil {
			return fmt.Errorf("failed to add to static blacklist %s: %v", cidr, err)
		}
	}

	if persistFile != "" {
		if err := writeToFile(persistFile, cidr); err != nil {
			m.logger.Warnf("⚠️ Failed to write to lock list file: %v", err)
		} else {
			m.logger.Infof("💾 Persisted IP %s to %s", cidr, persistFile)
		}
	}

	m.logger.Infof("🚫 Added IP %s to STATIC blacklist (permanent)", cidr)
	return nil
}

// AllowStaticTimed adds an IP/CIDR to the whitelist with timing.
// AllowStaticTimed 将 IP/CIDR 添加到白名单并计时。
func (m *Manager) AllowStaticTimed(ipStr string, port uint16) error {
	mapObj := m.Whitelist()

	if m.perfStats == nil {
		if err := AllowIP(mapObj, ipStr, port); err != nil {
			return fmt.Errorf("failed to allow %s: %v", ipStr, err)
		}
	} else {
		helper := NewMapOpHelper(m.perfStats, "whitelist")
		if err := helper.TimeWrite(func() error {
			return AllowIP(mapObj, ipStr, port)
		}); err != nil {
			return fmt.Errorf("failed to allow %s: %v", ipStr, err)
		}
	}
	return nil
}

// RemoveAllowStaticTimed removes an IP/CIDR from the whitelist with timing.
// RemoveAllowStaticTimed 从白名单中移除 IP/CIDR 并计时。
func (m *Manager) RemoveAllowStaticTimed(ipStr string) error {
	mapObj := m.Whitelist()

	if m.perfStats == nil {
		if err := UnlockIP(mapObj, ipStr); err != nil {
			return fmt.Errorf("failed to remove from whitelist %s: %v", ipStr, err)
		}
	} else {
		helper := NewMapOpHelper(m.perfStats, "whitelist")
		if err := helper.TimeDelete(func() error {
			return UnlockIP(mapObj, ipStr)
		}); err != nil {
			return fmt.Errorf("failed to remove from whitelist %s: %v", ipStr, err)
		}
	}
	return nil
}

// ListWhitelistTimed returns all whitelisted IPs/CIDRs with timing.
// ListWhitelistTimed 返回所有白名单中的 IP/CIDR 并计时。
func (m *Manager) ListWhitelistTimed(isIPv6 bool) ([]string, error) {
	mapObj := m.Whitelist()

	if m.perfStats == nil {
		ips, _, err := ListWhitelistIPs(mapObj, 0, "")
		return ips, err
	}

	helper := NewMapOpHelper(m.perfStats, "whitelist")
	var ips []string
	err := helper.TimeIter(func() error {
		var err error
		ips, _, err = ListWhitelistIPs(mapObj, 0, "")
		return err
	})
	return ips, err
}

// BlockDynamicTimed adds an IP to the dynamic blocklist with timing.
// BlockDynamicTimed 将 IP 添加到动态黑名单并计时。
func (m *Manager) BlockDynamicTimed(ipStr string, ttl time.Duration) error {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", ipStr, err)
	}

	expiry := uint64(0)
	if ttl > 0 {
		expiry = uint64(time.Now().Add(ttl).UnixNano()) // nolint:gosec // G115: timestamp is always valid
	}

	mapObj := m.DynLockList()
	if mapObj == nil {
		return fmt.Errorf("dyn_lock_list not available")
	}

	var updateErr error
	if m.perfStats == nil {
		updateErr = m.updateDynamicBlock(mapObj, ip, expiry)
	} else {
		helper := NewMapOpHelper(m.perfStats, "dynamic_blacklist")
		updateErr = helper.TimeWrite(func() error {
			return m.updateDynamicBlock(mapObj, ip, expiry)
		})
	}

	if updateErr != nil {
		return updateErr
	}

	m.logger.Infof("🚫 Blocked IP %s for %v (expiry: %d)", ip, ttl, expiry)
	return nil
}

// updateDynamicBlock performs the actual map update for dynamic blocking.
// updateDynamicBlock 执行动态封禁的实际 Map 更新。
func (m *Manager) updateDynamicBlock(mapObj *ebpf.Map, ip netip.Addr, expiry uint64) error {
	val := NetXfwRuleValue{
		Counter:   2,
		ExpiresAt: expiry,
	}

	if ip.Is4() {
		key := NetXfwIn6Addr{}
		b := ip.As4()
		key.In6U.U6Addr8[10] = 0xff
		key.In6U.U6Addr8[11] = 0xff
		copy(key.In6U.U6Addr8[12:], b[:])

		if err := mapObj.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to block IPv4 %s: %v", ip, err)
		}
	} else if ip.Is6() {
		key := NetXfwIn6Addr{}
		b := ip.As16()
		copy(key.In6U.U6Addr8[:], b[:])

		if err := mapObj.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to block IPv6 %s: %v", ip, err)
		}
	}
	return nil
}

// AddIPPortRuleTimed adds an IP+Port rule with timing.
// AddIPPortRuleTimed 添加 IP+端口规则并计时。
func (m *Manager) AddIPPortRuleTimed(ipNet *net.IPNet, port uint16, action uint8, expiresAt *time.Time) error {
	if m.perfStats == nil {
		return AddIPPortRuleToMap(m.ruleMap, ipNet, port, action, expiresAt)
	}

	helper := NewMapOpHelper(m.perfStats, "rule_map")
	return helper.TimeWrite(func() error {
		return AddIPPortRuleToMap(m.ruleMap, ipNet, port, action, expiresAt)
	})
}

// RemoveIPPortRuleTimed removes an IP+Port rule with timing.
// RemoveIPPortRuleTimed 移除 IP+端口规则并计时。
func (m *Manager) RemoveIPPortRuleTimed(ipNet *net.IPNet, port uint16) error {
	if m.perfStats == nil {
		return RemoveIPPortRuleFromMap(m.ruleMap, ipNet, port)
	}

	helper := NewMapOpHelper(m.perfStats, "rule_map")
	return helper.TimeDelete(func() error {
		return RemoveIPPortRuleFromMap(m.ruleMap, ipNet, port)
	})
}

// writeToFile is a helper for file writing.
// writeToFile 是文件写入的辅助函数。
func writeToFile(path, content string) error {
	f, err := openFileForAppend(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, content)
	return err
}

// openFileForAppend opens a file for appending.
// openFileForAppend 打开文件用于追加。
func openFileForAppend(path string) (*os.File, error) {
	safePath := filepath.Clean(path)                                        // Sanitize path to prevent directory traversal
	return os.OpenFile(safePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) // #nosec G304 // path is sanitized with filepath.Clean
}
