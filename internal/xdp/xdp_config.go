//go:build linux
// +build linux

package xdp

import (
	"time"

	"github.com/cilium/ebpf"
)

/**
 * updateConfig updates a global configuration value and increments the config version.
 * updateConfig 更新全局配置值并递增配置版本。
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
 * SetDefaultDeny 启用或禁用默认拒绝策略。
 */
func (m *Manager) SetDefaultDeny(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configDefaultDeny, val)
}

/**
 * SetAllowReturnTraffic enables or disables the automatic allowance of return traffic.
 * SetAllowReturnTraffic 启用或禁用自动允许回程流量。
 */
func (m *Manager) SetAllowReturnTraffic(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configAllowReturnTraffic, val)
}

/**
 * SetAllowICMP enables or disables the allowance of ICMP traffic.
 * SetAllowICMP 启用或禁用允许 ICMP 流量。
 */
func (m *Manager) SetAllowICMP(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configAllowICMP, val)
}

/**
 * SetICMPRateLimit sets the ICMP rate limit (packets/sec) and burst.
 * SetICMPRateLimit 设置 ICMP 速率限制（每秒数据包数）和突发量。
 */
func (m *Manager) SetICMPRateLimit(rate, burst uint64) error {
	if err := m.updateConfig(configICMPRate, rate); err != nil {
		return err
	}
	return m.updateConfig(configICMPBurst, burst)
}

/**
 * SetConntrackTimeout sets the connection tracking timeout in the BPF program.
 * SetConntrackTimeout 在 BPF 程序中设置连接跟踪超时。
 */
func (m *Manager) SetConntrackTimeout(timeout time.Duration) error {
	return m.updateConfig(configConntrackTimeout, uint64(timeout.Nanoseconds())) // #nosec G115 // timeout is always valid
}

/**
 * SetConntrack enables or disables the connection tracking.
 * SetConntrack 启用或禁用连接跟踪。
 */
func (m *Manager) SetConntrack(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configEnableConntrack, val)
}

/**
 * SetStrictProto enables or disables strict protocol enforcement.
 * SetStrictProto 启用或禁用严格协议强制执行。
 */
func (m *Manager) SetStrictProto(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configStrictProto, val)
}

/**
 * SetDropFragments enables or disables dropping of IP fragments.
 * SetDropFragments 启用或禁用丢弃 IP 分片。
 */
func (m *Manager) SetDropFragments(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configDropFragments, val)
}

/**
 * SetStrictTCP enables or disables strict TCP flag validation.
 * SetStrictTCP 启用或禁用严格的 TCP 标志验证。
 */
func (m *Manager) SetStrictTCP(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configStrictTCP, val)
}

/**
 * SetSYNLimit enables or disables SYN-only rate limiting.
 * SetSYNLimit 启用或禁用仅针对 SYN 的速率限制。
 */
func (m *Manager) SetSYNLimit(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configSYNLimit, val)
}

/**
 * SetEnableRateLimit enables or disables general rate limiting.
 * SetEnableRateLimit 启用或禁用全局速率限制。
 */
func (m *Manager) SetEnableRateLimit(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configEnableRateLimit, val)
}

/**
 * SetEnableAFXDP enables or disables AF_XDP redirection.
 * SetEnableAFXDP 启用或禁用 AF_XDP 重定向。
 */
func (m *Manager) SetEnableAFXDP(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configEnableAFXDP, val)
}

/**
 * SetStrictProtocol enables or disables the strict protocol whitelisting (IPv4, IPv6, ARP only).
 * SetStrictProtocol 开启或关闭严格协议白名单模式（仅允许 IPv4, IPv6, ARP）。
 */
func (m *Manager) SetStrictProtocol(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configStrictProto, val)
}

/**
 * SetBogonFilter enables or disables Bogon IP filtering.
 * SetBogonFilter 开启或关闭 Bogon IP 过滤。
 */
func (m *Manager) SetBogonFilter(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configBogonFilter, val)
}

/**
 * SetAutoBlock enables or disables automatic blocking of suspicious IPs.
 * SetAutoBlock 开启或关闭自动封禁。
 */
func (m *Manager) SetAutoBlock(enable bool) error {
	var val uint64
	if enable {
		val = 1
	}
	return m.updateConfig(configAutoBlock, val)
}

/**
 * SetAutoBlockExpiry sets the duration after which an automatically blocked IP is unblocked.
 * SetAutoBlockExpiry 设置自动封禁的 IP 解封前的持续时间。
 */
func (m *Manager) SetAutoBlockExpiry(expiry time.Duration) error {
	return m.updateConfig(configAutoBlockExpiry, uint64(expiry.Nanoseconds())) // #nosec G115 // expiry is always valid
}
