//go:build linux
// +build linux

package xdp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
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
	configVersion            = 7
)

/**
 * Manager handles the lifecycle of eBPF objects and links.
 * Manager 负责 eBPF 对象和链路的生命周期管理。
 */
type Manager struct {
	objs          NetXfwObjects
	links         []link.Link
	lockList      *ebpf.Map
	lockList6     *ebpf.Map
	whitelist     *ebpf.Map
	whitelist6    *ebpf.Map
	allowedPorts  *ebpf.Map
	ipPortRules   *ebpf.Map
	ipPortRules6  *ebpf.Map
	globalConfig  *ebpf.Map
	dropStats     *ebpf.Map
	icmpLimitMap  *ebpf.Map
	conntrackMap  *ebpf.Map
	conntrackMap6 *ebpf.Map
}

// LPM Key structures matching BPF definitions / 匹配 BPF 定义的 LPM Key 结构体
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
		objs:          objs,
		lockList:      objs.LockList,
		lockList6:     objs.LockList6,
		whitelist:     objs.Whitelist,
		whitelist6:    objs.Whitelist6,
		allowedPorts:  objs.AllowedPorts,
		ipPortRules:   objs.IpPortRules,
		ipPortRules6:  objs.IpPortRules6,
		globalConfig:  objs.GlobalConfig,
		dropStats:     objs.DropStats,
		icmpLimitMap:  objs.IcmpLimitMap,
		conntrackMap:  objs.ConntrackMap,
		conntrackMap6: objs.ConntrackMap6,
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
	if m.icmpLimitMap, err = ebpf.LoadPinnedMap(path+"/icmp_limit_map", nil); err != nil {
		log.Printf("⚠️  Could not load pinned icmp_limit_map: %v", err)
		m.icmpLimitMap = objs.IcmpLimitMap
	}
	if m.conntrackMap, err = ebpf.LoadPinnedMap(path+"/conntrack_map", nil); err != nil {
		log.Printf("⚠️  Could not load pinned conntrack_map: %v", err)
		m.conntrackMap = objs.ConntrackMap
	}
	if m.conntrackMap6, err = ebpf.LoadPinnedMap(path+"/conntrack_map6", nil); err != nil {
		log.Printf("⚠️  Could not load pinned conntrack_map6: %v", err)
		m.conntrackMap6 = objs.ConntrackMap6
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

		// Attach TC for egress tracking (required for Conntrack)
		// 1. Ensure clsact qdisc exists
		_ = exec.Command("tc", "qdisc", "add", "dev", name, "clsact").Run()

		// 2. Attach TC program
		tcLink, err := link.AttachTCX(link.TCXOptions{
			Program:   m.objs.TcEgress,
			Interface: iface.Index,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err == nil {
			tcLinkPath := fmt.Sprintf("/sys/fs/bpf/netxfw/tc_link_%s", name)
			_ = os.Remove(tcLinkPath)
			if err := tcLink.Pin(tcLinkPath); err != nil {
				log.Printf("⚠️  Failed to pin TC link on %s: %v", name, err)
				tcLink.Close()
			} else {
				log.Printf("✅ Attached TC Egress on %s and pinned link", name)
			}
		} else {
			log.Printf("⚠️  Failed to attach TC Egress on %s: %v (Conntrack will not work for this interface)", name, err)
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

		// Detach TC link
		tcLinkPath := fmt.Sprintf("/sys/fs/bpf/netxfw/tc_link_%s", name)
		if tl, err := link.LoadPinnedLink(tcLinkPath, nil); err == nil {
			if err := tl.Close(); err != nil {
				log.Printf("❌ Failed to close TC link for %s: %v", name, err)
			} else {
				_ = os.Remove(tcLinkPath)
				log.Printf("✅ Detached TC Egress from %s", name)
			}
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
 * AddIPPortRule adds an IP+Port rule to the firewall.
 * action: 1 for allow, 2 for deny
 */
func (m *Manager) AddIPPortRule(ipNet *net.IPNet, port uint16, action uint8, expiresAt *time.Time) error {
	ones, _ := ipNet.Mask.Size()
	val := NetXfwRuleValue{
		Counter:   uint64(action),
		ExpiresAt: timeToBootNS(expiresAt),
	}
	ip := ipNet.IP.To4()
	if ip != nil {
		key := NetXfwLpmIp4PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
			Ip:        binary.LittleEndian.Uint32(ip),
		}
		return m.ipPortRules.Update(&key, &val, ebpf.UpdateAny)
	}

	ip = ipNet.IP.To16()
	if ip != nil {
		key := NetXfwLpmIp6PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
		}
		copy(key.Ip.In6U.U6Addr8[:], ip)
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
		key := NetXfwLpmIp4PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
			Ip:        binary.LittleEndian.Uint32(ip),
		}
		return m.ipPortRules.Delete(&key)
	}

	ip = ipNet.IP.To16()
	if ip != nil {
		key := NetXfwLpmIp6PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
		}
		copy(key.Ip.In6U.U6Addr8[:], ip)
		return m.ipPortRules6.Delete(&key)
	}

	return fmt.Errorf("invalid IP address")
}

/**
 * AllowPort adds a port to the allowed ports list.
 */
func (m *Manager) AllowPort(port uint16, expiresAt *time.Time) error {
	// BPF_MAP_TYPE_PERCPU_HASH requires a slice of values for update if we want to set it for all CPUs
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("get possible CPUs: %w", err)
	}
	val := NetXfwRuleValue{
		Counter:   1,
		ExpiresAt: timeToBootNS(expiresAt),
	}
	vals := make([]NetXfwRuleValue, numCPU)
	for i := 0; i < numCPU; i++ {
		vals[i] = val
	}
	// For PERCPU maps, Update expects the slice itself, not a pointer to it
	return m.allowedPorts.Update(&port, vals, ebpf.UpdateAny)
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
 * ListIPPortRules returns all configured IP+Port rules.
 */
func (m *Manager) ListIPPortRules(isIPv6 bool) (map[string]string, error) {
	rules := make(map[string]string)
	mapToIterate := m.ipPortRules
	if isIPv6 {
		mapToIterate = m.ipPortRules6
	}

	if isIPv6 {
		var key NetXfwLpmIp6PortKey
		var val NetXfwRuleValue
		iter := mapToIterate.Iterate()
		for iter.Next(&key, &val) {
			prefixLen := key.Prefixlen - 32
			ip := net.IP(key.Ip.In6U.U6Addr8[:])
			action := "allow"
			if val.Counter == 2 {
				action = "deny"
			}
			rules[fmt.Sprintf("%s/%d:%d", ip.String(), prefixLen, key.Port)] = action
		}
		return rules, iter.Err()
	} else {
		var key NetXfwLpmIp4PortKey
		var val NetXfwRuleValue
		iter := mapToIterate.Iterate()
		for iter.Next(&key, &val) {
			prefixLen := key.Prefixlen - 32
			ip := intToIP(key.Ip)
			action := "allow"
			if val.Counter == 2 {
				action = "deny"
			}
			rules[fmt.Sprintf("%s/%d:%d", ip.String(), prefixLen, key.Port)] = action
		}
		return rules, iter.Err()
	}
}

/**
 * ListAllowedPorts retrieves all globally allowed ports.
 */
func (m *Manager) ListAllowedPorts() ([]uint16, error) {
	var ports []uint16
	var port uint16
	// Note: BPF_MAP_TYPE_PERCPU_HASH returns a slice of values, one per CPU
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("get possible CPUs: %w", err)
	}
	val := make([]NetXfwRuleValue, numCPU)
	iter := m.allowedPorts.Iterate()
	// IMPORTANT: In cilium/ebpf, when iterating over a PERCPU map,
	// the Next() call expects the value to be a slice.
	for iter.Next(&port, &val) {
		ports = append(ports, port)
	}
	if err := iter.Err(); err != nil {
		// If iteration fails, try to just see if map is empty
		return ports, nil
	}
	return ports, nil
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

/**
 * ListConntrackEntries retrieves all active connections from the conntrack maps.
 */
func (m *Manager) ListConntrackEntries() ([]ConntrackEntry, error) {
	var entries []ConntrackEntry

	// List IPv4 entries
	if m.conntrackMap != nil {
		var key NetXfwCtKey
		var val NetXfwCtValue
		iter := m.conntrackMap.Iterate()
		for iter.Next(&key, &val) {
			entry := ConntrackEntry{
				SrcIP:    intToIP(key.SrcIp).String(),
				DstIP:    intToIP(key.DstIp).String(),
				SrcPort:  key.SrcPort,
				DstPort:  key.DstPort,
				Protocol: key.Protocol,
				LastSeen: time.Unix(0, int64(val.LastSeen)),
			}
			entries = append(entries, entry)
		}
		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("iterate ipv4 conntrack: %w", err)
		}
	}

	// List IPv6 entries
	if m.conntrackMap6 != nil {
		var key NetXfwCtKey6
		var val NetXfwCtValue
		iter := m.conntrackMap6.Iterate()
		for iter.Next(&key, &val) {
			entry := ConntrackEntry{
				SrcIP:    net.IP(key.SrcIp.In6U.U6Addr8[:]).String(),
				DstIP:    net.IP(key.DstIp.In6U.U6Addr8[:]).String(),
				SrcPort:  key.SrcPort,
				DstPort:  key.DstPort,
				Protocol: key.Protocol,
				LastSeen: time.Unix(0, int64(val.LastSeen)),
			}
			entries = append(entries, entry)
		}
		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("iterate ipv6 conntrack: %w", err)
		}
	}

	return entries, nil
}

func intToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
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
	_ = m.icmpLimitMap.Pin(path + "/icmp_limit_map")
	_ = m.conntrackMap.Pin(path + "/conntrack_map")
	if m.conntrackMap6 != nil {
		_ = m.conntrackMap6.Pin(path + "/conntrack_map6")
	}
	return nil
}

// Unpin removes maps from the filesystem.
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
	_ = m.icmpLimitMap.Unpin()
	_ = m.conntrackMap.Unpin()
	if m.conntrackMap6 != nil {
		_ = m.conntrackMap6.Unpin()
	}
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
