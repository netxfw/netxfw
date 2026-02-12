//go:build linux
// +build linux

package xdp

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Generate Go bindings for the BPF program / 为 BPF 程序生成 Go 绑定
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetXfw ../../bpf/netxfw.bpf.c -- -I../../bpf

const (
	configDefaultDeny        = 0
	configAllowReturnTraffic = 1
	configAllowICMP          = 2
	configEnableConntrack    = 3
	configConntrackTimeout   = 4
	configICMPRate           = 5
	configICMPBurst          = 6
	configEnableAFXDP        = 7
	configVersion            = 8
	configStrictProto        = 9
	configEnableRateLimit    = 10
	configDropFragments      = 11
	configStrictTCP          = 12
	configSYNLimit           = 13
	configBogonFilter        = 14
	configAutoBlock          = 15
	configAutoBlockExpiry    = 16
)

const (
	ProgIdxIPv4        = 0
	ProgIdxIPv6        = 1
	ProgIdxPluginStart = 2
	ProgIdxPluginEnd   = 15
)

/**
 * RateLimitConf matches the BPF struct ratelimit_conf
 */
type RateLimitConf struct {
	Rate  uint64 // packets per second
	Burst uint64 // max tokens
}

/**
 * Manager handles the lifecycle of eBPF objects and links.
 * Manager 负责 eBPF 对象和链路的生命周期管理。
 */
type Manager struct {
	objs             NetXfwObjects
	links            []link.Link
	lockList         *ebpf.Map
	dynLockList      *ebpf.Map
	lockList6        *ebpf.Map
	dynLockList6     *ebpf.Map
	whitelist        *ebpf.Map
	whitelist6       *ebpf.Map
	allowedPorts     *ebpf.Map
	ipPortRules      *ebpf.Map
	ipPortRules6     *ebpf.Map
	globalConfig     *ebpf.Map
	dropStats        *ebpf.Map
	passStats        *ebpf.Map
	icmpLimitMap     *ebpf.Map
	conntrackMap     *ebpf.Map
	conntrackMap6    *ebpf.Map
	ratelimitConfig  *ebpf.Map
	ratelimitConfig6 *ebpf.Map
	ratelimitState   *ebpf.Map
	ratelimitState6  *ebpf.Map
	jmpTable         *ebpf.Map
	dropReasonStats  *ebpf.Map
	dropReasonStats6 *ebpf.Map
	passReasonStats  *ebpf.Map
	passReasonStats6 *ebpf.Map
}

/**
 * ConntrackEntry represents a single connection tracking entry.
 */
type ConntrackEntry struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	LastSeen time.Time
}

// Map getters / Map 获取器
func (m *Manager) LockList() *ebpf.Map {
	return m.lockList
}

func (m *Manager) LockList6() *ebpf.Map {
	return m.lockList6
}

func (m *Manager) DynLockList() *ebpf.Map {
	return m.dynLockList
}

func (m *Manager) DynLockList6() *ebpf.Map {
	return m.dynLockList6
}

func (m *Manager) Whitelist() *ebpf.Map {
	return m.whitelist
}

func (m *Manager) Whitelist6() *ebpf.Map {
	return m.whitelist6
}

func (m *Manager) AllowedPorts() *ebpf.Map {
	return m.allowedPorts
}

func (m *Manager) GlobalConfig() *ebpf.Map {
	return m.globalConfig
}

func (m *Manager) IpPortRules() *ebpf.Map {
	return m.ipPortRules
}

func (m *Manager) IpPortRules6() *ebpf.Map {
	return m.ipPortRules6
}

func (m *Manager) DropStats() *ebpf.Map {
	return m.dropStats
}

func (m *Manager) PassStats() *ebpf.Map {
	return m.passStats
}

func (m *Manager) IcmpLimitMap() *ebpf.Map {
	return m.icmpLimitMap
}

func (m *Manager) ConntrackMap() *ebpf.Map {
	return m.conntrackMap
}

func (m *Manager) ConntrackMap6() *ebpf.Map {
	return m.conntrackMap6
}

func (m *Manager) RatelimitConfig() *ebpf.Map {
	return m.ratelimitConfig
}

func (m *Manager) RatelimitConfig6() *ebpf.Map {
	return m.ratelimitConfig6
}

func (m *Manager) RatelimitState() *ebpf.Map {
	return m.ratelimitState
}

func (m *Manager) RatelimitState6() *ebpf.Map {
	return m.ratelimitState6
}

func (m *Manager) DropReasonStats() *ebpf.Map {
	return m.dropReasonStats
}
