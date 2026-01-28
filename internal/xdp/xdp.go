//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Generate Go bindings for the BPF program / 为 BPF 程序生成 Go 绑定
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetXfw ../../bpf/netxfw.bpf.c -- -I../../bpf

/**
 * Manager handles the lifecycle of eBPF objects and links.
 * Manager 负责 eBPF 对象和链路的生命周期管理。
 */
type Manager struct {
	objs         NetXfwObjects
	links        []link.Link
	lockList     *ebpf.Map
	lockList6    *ebpf.Map
	whitelist    *ebpf.Map
	whitelist6   *ebpf.Map
	allowedPorts *ebpf.Map
	ipPortRules  *ebpf.Map
	ipPortRules6 *ebpf.Map
	globalConfig *ebpf.Map
	dropStats    *ebpf.Map
}

// LPM Key structures matching BPF definitions / 匹配 BPF 定义的 LPM Key 结构体
type LPMIP4PortKey struct {
	PrefixLen uint32
	Port      uint16
	Pad       uint16
	IP        [4]byte
}

type LPMIP6PortKey struct {
	PrefixLen uint32
	Port      uint16
	Pad       uint16
	IP        [16]byte
}

// RuleValue matching BPF definition / 匹配 BPF 定义的 RuleValue 结构体
type RuleValue struct {
	Counter   uint64
	ExpiresAt uint64
}

/**
 * NewManager initializes the BPF objects and removes memory limits.
 * NewManager 初始化 BPF 对象并移除内存限制。
 */
func NewManager() (*Manager, error) {
	// Remove resource limits for BPF / 移除 BPF 资源限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// Load BPF objects into the kernel / 将 BPF 对象加载到内核
	var objs NetXfwObjects
	if err := LoadNetXfwObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	return &Manager{
		objs:         objs,
		lockList:     objs.LockList,
		lockList6:    objs.LockList6,
		whitelist:    objs.Whitelist,
		whitelist6:   objs.Whitelist6,
		allowedPorts: objs.AllowedPorts,
		ipPortRules:  objs.IpPortRules,
		ipPortRules6: objs.IpPortRules6,
		globalConfig: objs.GlobalConfig,
		dropStats:    objs.DropStats,
	}, nil
}

/**
 * NewManagerFromPins loads a manager using maps already pinned to the filesystem.
 * This is useful for CLI tools that need to interact with a running XDP program.
 */
func NewManagerFromPins(path string) (*Manager, error) {
	// We still need to load objects to get the program, but we will replace maps with pinned ones
	var objs NetXfwObjects
	if err := LoadNetXfwObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	m := &Manager{objs: objs}

	var err error
	if m.lockList, err = ebpf.LoadPinnedMap(path+"/lock_list", nil); err != nil {
		log.Printf("⚠️  Could not load pinned lock_list: %v", err)
		m.lockList = objs.LockList
	}
	if m.lockList6, err = ebpf.LoadPinnedMap(path+"/lock_list6", nil); err != nil {
		log.Printf("⚠️  Could not load pinned lock_list6: %v", err)
		m.lockList6 = objs.LockList6
	}
	if m.whitelist, err = ebpf.LoadPinnedMap(path+"/whitelist", nil); err != nil {
		log.Printf("⚠️  Could not load pinned whitelist: %v", err)
		m.whitelist = objs.Whitelist
	}
	if m.whitelist6, err = ebpf.LoadPinnedMap(path+"/whitelist6", nil); err != nil {
		log.Printf("⚠️  Could not load pinned whitelist6: %v", err)
		m.whitelist6 = objs.Whitelist6
	}
	if m.allowedPorts, err = ebpf.LoadPinnedMap(path+"/allowed_ports", nil); err != nil {
		log.Printf("⚠️  Could not load pinned allowed_ports: %v", err)
		m.allowedPorts = objs.AllowedPorts
	}
	if m.ipPortRules, err = ebpf.LoadPinnedMap(path+"/ip_port_rules", nil); err != nil {
		log.Printf("⚠️  Could not load pinned ip_port_rules: %v", err)
		m.ipPortRules = objs.IpPortRules
	}
	if m.ipPortRules6, err = ebpf.LoadPinnedMap(path+"/ip_port_rules6", nil); err != nil {
		log.Printf("⚠️  Could not load pinned ip_port_rules6: %v", err)
		m.ipPortRules6 = objs.IpPortRules6
	}
	if m.globalConfig, err = ebpf.LoadPinnedMap(path+"/global_config", nil); err != nil {
		log.Printf("⚠️  Could not load pinned global_config: %v", err)
		m.globalConfig = objs.GlobalConfig
	}
	if m.dropStats, err = ebpf.LoadPinnedMap(path+"/drop_stats", nil); err != nil {
		log.Printf("⚠️  Could not load pinned drop_stats: %v", err)
		m.dropStats = objs.DropStats
	}

	return m, nil
}

/**
 * Attach mounts the XDP program to the specified network interfaces.
 * It tries Offload mode, then Native mode, and finally Generic mode as fallbacks.
 * The XDP program is attached using link.XDP_FLAGS_REPLACE or similar to ensure it stays in kernel.
 */
func (m *Manager) Attach(interfaces []string) error {
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Printf("Skip interface %s: %v", name, err)
			continue
		}

		modes := []struct {
			name string
			flag link.XDPAttachFlags
		}{
			{"Offload", link.XDPOffloadMode},
			{"Native", link.XDPDriverMode},
			{"Generic", link.XDPGenericMode},
		}

		var attached bool
		for _, mode := range modes {
			// Using Pin-less link or simply not storing the link object if we want it to persist.
			// However, in cilium/ebpf, if the link object is closed, the program is detached.
			// To keep it persistent, we need to PIN the link or use Raw attach.
			l, err := link.AttachXDP(link.XDPOptions{
				Program:   m.objs.XdpFirewall,
				Interface: iface.Index,
				Flags:     mode.flag,
			})

			if err == nil {
				// Pin the link to filesystem to make it persistent after process exit
				linkPath := fmt.Sprintf("/sys/fs/bpf/netxfw/link_%s", name)
				_ = os.Remove(linkPath) // Remove old link pin if exists
				if err := l.Pin(linkPath); err != nil {
					log.Printf("⚠️  Failed to pin link on %s: %v", name, err)
					l.Close()
					continue
				}
				log.Printf("✅ Attached XDP on %s (Mode: %s) and pinned link", name, mode.name)
				attached = true
				break
			}
			log.Printf("⚠️  Failed to attach XDP on %s using %s mode: %v", name, mode.name, err)
		}

		if !attached {
			log.Printf("❌ Failed to attach XDP on %s with any mode", name)
		}
	}
	return nil
}

/**
 * Detach removes the XDP program from the specified network interfaces by unpinning and closing links.
 */
func (m *Manager) Detach(interfaces []string) error {
	for _, name := range interfaces {
		linkPath := fmt.Sprintf("/sys/fs/bpf/netxfw/link_%s", name)
		l, err := link.LoadPinnedLink(linkPath, nil)
		if err != nil {
			log.Printf("⚠️  No pinned link found for %s, trying manual detach...", name)
			// Fallback: try to detach using interface index if possible,
			// but usually unpinning the persistent link is enough.
			continue
		}
		if err := l.Close(); err != nil {
			log.Printf("❌ Failed to close link for %s: %v", name, err)
		} else {
			_ = os.Remove(linkPath)
			log.Printf("✅ Detached XDP from %s", name)
		}
	}
	return nil
}

// Map getters / Map 获取器
func (m *Manager) LockList() *ebpf.Map {
	return m.lockList
}

func (m *Manager) LockList6() *ebpf.Map {
	return m.lockList6
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

/**
 * SetDefaultDeny enables or disables the default deny policy.
 */
func (m *Manager) SetDefaultDeny(enable bool) error {
	var key uint32 = 0 // CONFIG_DEFAULT_DENY
	var val uint32 = 0
	if enable {
		val = 1
	}
	return m.globalConfig.Update(&key, &val, ebpf.UpdateAny)
}

/**
 * AddIPPortRule adds an IP+Port rule to the firewall.
 * action: 1 for allow, 2 for deny
 */
func (m *Manager) AddIPPortRule(ipNet *net.IPNet, port uint16, action uint8, expiresAt *time.Time) error {
	ones, _ := ipNet.Mask.Size()
	val := RuleValue{
		Counter:   uint64(action),
		ExpiresAt: timeToBootNS(expiresAt),
	}
	ip := ipNet.IP.To4()
	if ip != nil {
		key := LPMIP4PortKey{
			PrefixLen: uint32(16 + ones),
			Port:      port,
			Pad:       0,
		}
		copy(key.IP[:], ip)
		return m.ipPortRules.Update(&key, &val, ebpf.UpdateAny)
	}

	ip = ipNet.IP.To16()
	if ip != nil {
		key := LPMIP6PortKey{
			PrefixLen: uint32(16 + ones),
			Port:      port,
			Pad:       0,
		}
		copy(key.IP[:], ip)
		return m.ipPortRules6.Update(&key, &val, ebpf.UpdateAny)
	}

	return fmt.Errorf("invalid IP address")
}

/**
 * RemoveIPPortRule removes an IP+Port rule.
 */
func (m *Manager) RemoveIPPortRule(ipNet *net.IPNet, port uint16) error {
	ones, _ := ipNet.Mask.Size()
	ip := ipNet.IP.To4()
	if ip != nil {
		key := LPMIP4PortKey{
			PrefixLen: uint32(16 + ones),
			Port:      port,
			Pad:       0,
		}
		copy(key.IP[:], ip)
		return m.ipPortRules.Delete(&key)
	}

	ip = ipNet.IP.To16()
	if ip != nil {
		key := LPMIP6PortKey{
			PrefixLen: uint32(16 + ones),
			Port:      port,
			Pad:       0,
		}
		copy(key.IP[:], ip)
		return m.ipPortRules6.Delete(&key)
	}

	return fmt.Errorf("invalid IP address")
}

/**
 * AllowPort adds a port to the allowed ports list.
 */
func (m *Manager) AllowPort(port uint16, expiresAt *time.Time) error {
	val := RuleValue{
		Counter:   1,
		ExpiresAt: timeToBootNS(expiresAt),
	}
	return m.allowedPorts.Update(&port, &val, ebpf.UpdateAny)
}

/**
 * RemovePort removes a port from the allowed ports list.
 */
func (m *Manager) RemovePort(port uint16) error {
	return m.allowedPorts.Delete(&port)
}

/**
 * GetDropCount retrieves global drop statistics from the PERCPU map.
 * GetDropCount 从 PERCPU Map 中获取全局拦截统计信息。
 */
func (m *Manager) GetDropCount() (uint64, error) {
	var key uint32 = 0
	var values []uint64
	if err := m.dropStats.Lookup(&key, &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

/**
 * Close releases all BPF resources.
 * Note: Persistent links are NOT closed here to allow them to stay in kernel.
 */
func (m *Manager) Close() {
	m.objs.Close()
	// We no longer automatically close links here to keep them persistent.
	// Links are now pinned and should be managed via Detach or manually.
}

/**
 * Pin saves maps to the filesystem for persistence and external access.
 */
func (m *Manager) Pin(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	// Try to pin each map, ignore error if already pinned
	_ = m.lockList.Pin(path + "/lock_list")
	_ = m.lockList6.Pin(path + "/lock_list6")
	_ = m.whitelist.Pin(path + "/whitelist")
	_ = m.whitelist6.Pin(path + "/whitelist6")
	_ = m.allowedPorts.Pin(path + "/allowed_ports")
	_ = m.ipPortRules.Pin(path + "/ip_port_rules")
	_ = m.ipPortRules6.Pin(path + "/ip_port_rules6")
	_ = m.globalConfig.Pin(path + "/global_config")
	_ = m.dropStats.Pin(path + "/drop_stats")
	return nil
}

/**
 * Unpin removes maps from the filesystem.
 * Unpin 从文件系统中移除固定的 Map。
 */
func (m *Manager) Unpin(path string) error {
	_ = m.lockList.Unpin()
	_ = m.lockList6.Unpin()
	_ = m.whitelist.Unpin()
	_ = m.whitelist6.Unpin()
	_ = m.allowedPorts.Unpin()
	_ = m.ipPortRules.Unpin()
	_ = m.ipPortRules6.Unpin()
	_ = m.globalConfig.Unpin()
	_ = m.dropStats.Unpin()
	return os.RemoveAll(path)
}

/**
 * timeToBootNS converts a time.Time pointer to boot time nanoseconds.
 * If the pointer is nil, it returns 0 (no expiry).
 */
func timeToBootNS(t *time.Time) uint64 {
	if t == nil {
		return 0
	}
	// Use monotonic clock to get duration since a fixed point
	// This is a simplified version, in production you might need to sync with boot time
	return uint64(time.Until(*t).Nanoseconds()) + uint64(time.Now().UnixNano())
}
