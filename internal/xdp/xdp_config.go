//go:build linux
// +build linux

package xdp

import (
	"time"

	"github.com/cilium/ebpf"
)

/**
 * updateConfig updates a global configuration value and increments the config version.
 */
func (m *Manager) updateConfig(key uint32, val uint64) error {
	if err := m.globalConfig.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return err
	}

	// Increment version to trigger BPF cache refresh
	var verKey uint32 = configVersion
	var currentVer uint64
	_ = m.globalConfig.Lookup(&verKey, &currentVer)
	currentVer++
	return m.globalConfig.Update(&verKey, &currentVer, ebpf.UpdateAny)
}

/**
 * SetDefaultDeny enables or disables the default deny policy.
 */
func (m *Manager) SetDefaultDeny(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configDefaultDeny, val)
}

/**
 * SetAllowReturnTraffic enables or disables the automatic allowance of return traffic.
 */
func (m *Manager) SetAllowReturnTraffic(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configAllowReturnTraffic, val)
}

/**
 * SetAllowICMP enables or disables the allowance of ICMP traffic.
 */
func (m *Manager) SetAllowICMP(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configAllowICMP, val)
}

/**
 * SetICMPRateLimit sets the ICMP rate limit (packets/sec) and burst.
 */
func (m *Manager) SetICMPRateLimit(rate, burst uint64) error {
	if err := m.updateConfig(configICMPRate, rate); err != nil {
		return err
	}
	return m.updateConfig(configICMPBurst, burst)
}

/**
 * SetConntrackTimeout sets the connection tracking timeout in the BPF program.
 */
func (m *Manager) SetConntrackTimeout(timeout time.Duration) error {
	return m.updateConfig(configConntrackTimeout, uint64(timeout.Nanoseconds()))
}

/**
 * SetConntrack enables or disables the connection tracking.
 */
func (m *Manager) SetConntrack(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configEnableConntrack, val)
}

/**
 * SetStrictProto enables or disables strict protocol enforcement.
 */
func (m *Manager) SetStrictProto(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configStrictProto, val)
}

/**
 * SetDropFragments enables or disables dropping of IP fragments.
 */
func (m *Manager) SetDropFragments(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configDropFragments, val)
}

/**
 * SetStrictTCP enables or disables strict TCP flag validation.
 */
func (m *Manager) SetStrictTCP(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configStrictTCP, val)
}

/**
 * SetSYNLimit enables or disables SYN-only rate limiting.
 */
func (m *Manager) SetSYNLimit(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configSYNLimit, val)
}

/**
 * SetEnableRateLimit enables or disables general rate limiting.
 */
func (m *Manager) SetEnableRateLimit(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configEnableRateLimit, val)
}

/**
 * SetEnableAFXDP enables or disables AF_XDP redirection.
 */
func (m *Manager) SetEnableAFXDP(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configEnableAFXDP, val)
}

/**
 * SetStrictProtocol enables or disables the strict protocol whitelisting (IPv4, IPv6, ARP only).
 * 开启或关闭严格协议白名单模式（仅允许 IPv4, IPv6, ARP）。
 */
func (m *Manager) SetStrictProtocol(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configStrictProto, val)
}

/**
 * SetBogonFilter enables or disables Bogon IP filtering.
 * 开启或关闭 Bogon IP 过滤。
 */
func (m *Manager) SetBogonFilter(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configBogonFilter, val)
}

/**
 * SetAutoBlock enables or disables automatic blocking of suspicious IPs.
 * 开启或关闭自动封禁。
 */
func (m *Manager) SetAutoBlock(enable bool) error {
	var val uint64 = 0
	if enable {
		val = 1
	}
	return m.updateConfig(configAutoBlock, val)
}

/**
 * SetAutoBlockExpiry sets the duration after which an automatically blocked IP is unblocked.
 * 设置自动封禁的过期时间。
 */
func (m *Manager) SetAutoBlockExpiry(expiry time.Duration) error {
	return m.updateConfig(configAutoBlockExpiry, uint64(expiry.Seconds()))
}
