//go:build linux
// +build linux

package xdp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/livp123/netxfw/internal/plugins/types"
)

const (
	CONFIG_DEFAULT_DENY         = 0
	CONFIG_ALLOW_RETURN_TRAFFIC = 1
	CONFIG_ALLOW_ICMP           = 2
	CONFIG_ENABLE_CONNTRACK     = 3
	CONFIG_CONNTRACK_TIMEOUT    = 4
	CONFIG_ICMP_RATE            = 5
	CONFIG_ICMP_BURST           = 6
	CONFIG_ENABLE_AF_XDP        = 7
	CONFIG_CONFIG_VERSION       = 8
	CONFIG_STRICT_PROTO         = 9
	CONFIG_ENABLE_RATELIMIT     = 10
	CONFIG_DROP_FRAGMENTS       = 11
	CONFIG_STRICT_TCP           = 12
	CONFIG_SYN_LIMIT            = 13
	CONFIG_BOGON_FILTER         = 14
	CONFIG_AUTO_BLOCK           = 15
	CONFIG_AUTO_BLOCK_EXPIRY    = 16
)

// BlockStatic adds an IP to the static blocklist (LPM trie) and optionally persists it to a file.
// It reuses the underlying LockIP helper for BPF map operations.
func (m *Manager) BlockStatic(ipStr string, persistFile string) error {
	ip, err := netip.ParseAddr(ipStr)
	// If parsing fails, it might be a CIDR
	if err != nil {
		if _, _, err := net.ParseCIDR(ipStr); err != nil {
			return fmt.Errorf("invalid IP or CIDR %s: %w", ipStr, err)
		}
	}

	cidr := ipStr
	if err == nil {
		// It's a single IP, append suffix
		if ip.Is4() {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}

	// Use LockList (Static)
	mapObj := m.LockList()
	if IsIPv6(cidr) {
		mapObj = m.LockList6()
	}

	// Reuse existing LockIP helper
	if err := LockIP(mapObj, cidr); err != nil {
		return fmt.Errorf("failed to add to static blacklist %s: %v", cidr, err)
	}

	// Persist to lock list file if configured
	if persistFile != "" {
		// Use O_APPEND to add to the end of the file
		f, err := os.OpenFile(persistFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("⚠️ Failed to open lock list file for persistence: %v", err)
		} else {
			defer f.Close()
			if _, err := f.WriteString(cidr + "\n"); err != nil {
				log.Printf("⚠️ Failed to write to lock list file: %v", err)
			} else {
				log.Printf("💾 Persisted IP %s to %s", cidr, persistFile)
			}
		}
	}

	log.Printf("🚫 Added IP %s to STATIC blacklist (permanent)", cidr)
	return nil
}

// AllowStatic adds an IP/CIDR to the whitelist.
func (m *Manager) AllowStatic(ipStr string, port uint16) error {
	// Determine if IPv6
	isV6 := IsIPv6(ipStr)
	mapObj := m.Whitelist()
	if isV6 {
		mapObj = m.Whitelist6()
	}

	if err := AllowIP(mapObj, ipStr, port); err != nil {
		return fmt.Errorf("failed to allow %s: %v", ipStr, err)
	}
	return nil
}

// RemoveAllowStatic removes an IP/CIDR from the whitelist.
func (m *Manager) RemoveAllowStatic(ipStr string) error {
	isV6 := IsIPv6(ipStr)
	mapObj := m.Whitelist()
	if isV6 {
		mapObj = m.Whitelist6()
	}

	if err := UnlockIP(mapObj, ipStr); err != nil {
		return fmt.Errorf("failed to remove from whitelist %s: %v", ipStr, err)
	}
	return nil
}

// ListWhitelist returns all whitelisted IPs/CIDRs.
func (m *Manager) ListWhitelist(isIPv6 bool) ([]string, error) {
	mapObj := m.Whitelist()
	if isIPv6 {
		mapObj = m.Whitelist6()
	}
	// Use 0 limit to get all
	ips, _, err := ListWhitelistedIPs(mapObj, isIPv6, 0, "")
	return ips, err
}

// BlockDynamic adds an IP to the dynamic blocklist (LRU hash) with a TTL.
func (m *Manager) BlockDynamic(ipStr string, ttl time.Duration) error {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", ipStr, err)
	}

	expiry := uint64(0)
	if ttl > 0 {
		expiry = uint64(time.Now().Add(ttl).UnixNano())
	}

	if ip.Is4() {
		mapObj := m.DynLockList()
		if mapObj == nil {
			return fmt.Errorf("IPv4 dyn_lock_list not available")
		}

		// Key is uint32 (little endian)
		b := ip.As4()
		key := binary.LittleEndian.Uint32(b[:])

		val := NetXfwRuleValue{
			Counter:   2, // Deny
			ExpiresAt: expiry,
		}
		if err := mapObj.Update(key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to block IPv4 %s: %v", ip, err)
		}
	} else if ip.Is6() {
		mapObj := m.DynLockList6()
		if mapObj == nil {
			return fmt.Errorf("IPv6 dyn_lock_list6 not available")
		}

		key := ip.As16()
		val := NetXfwRuleValue{
			Counter:   2, // Deny
			ExpiresAt: expiry,
		}

		if err := mapObj.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to block IPv6 %s: %v", ip, err)
		}
	}

	log.Printf("🚫 Blocked IP %s for %v (expiry: %d)", ip, ttl, expiry)
	return nil
}

// ForceCleanup removes all pinned maps at the specified path.
func ForceCleanup(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.RemoveAll(path)
}

/**
 * NewManager initializes the BPF objects and removes memory limits.
 * Supports dynamic map capacity adjustment.
 * NewManager 初始化 BPF 对象并移除内存限制，支持动态调整 Map 容量。
 */
func NewManager(cfg types.CapacityConfig) (*Manager, error) {
	// Remove resource limits for BPF / 移除 BPF 资源限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// Load BPF collection spec / 加载 BPF 集合规范
	spec, err := LoadNetXfw()
	if err != nil {
		return nil, fmt.Errorf("load netxfw spec: %w", err)
	}

	// Dynamic capacity adjustment / 动态调整容量
	if cfg.Conntrack > 0 {
		if m, ok := spec.Maps["conntrack_map"]; ok {
			m.MaxEntries = uint32(cfg.Conntrack)
		}
		if m, ok := spec.Maps["conntrack_map6"]; ok {
			m.MaxEntries = uint32(cfg.Conntrack)
		}
	}
	if cfg.LockList > 0 {
		if m, ok := spec.Maps["lock_list"]; ok {
			m.MaxEntries = uint32(cfg.LockList)
		}
		if m, ok := spec.Maps["lock_list6"]; ok {
			m.MaxEntries = uint32(cfg.LockList)
		}
	}
	if cfg.DynLockList > 0 {
		if m, ok := spec.Maps["dyn_lock_list"]; ok {
			m.MaxEntries = uint32(cfg.DynLockList)
		}
		if m, ok := spec.Maps["dyn_lock_list6"]; ok {
			m.MaxEntries = uint32(cfg.DynLockList)
		}
	}
	if cfg.Whitelist > 0 {
		if m, ok := spec.Maps["whitelist"]; ok {
			m.MaxEntries = uint32(cfg.Whitelist)
		}
		if m, ok := spec.Maps["whitelist6"]; ok {
			m.MaxEntries = uint32(cfg.Whitelist)
		}
	}
	if cfg.IPPortRules > 0 {
		if m, ok := spec.Maps["ip_port_rules"]; ok {
			m.MaxEntries = uint32(cfg.IPPortRules)
		}
		if m, ok := spec.Maps["ip_port_rules6"]; ok {
			m.MaxEntries = uint32(cfg.IPPortRules)
		}
	}
	if cfg.AllowedPorts > 0 {
		if m, ok := spec.Maps["allowed_ports"]; ok {
			m.MaxEntries = uint32(cfg.AllowedPorts)
		}
	}

	// Load BPF objects into the kernel / 将 BPF 对象加载到内核
	var objs NetXfwObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	manager := &Manager{
		objs:             objs,
		lockList:         objs.LockList,
		dynLockList:      objs.DynLockList,
		lockList6:        objs.LockList6,
		dynLockList6:     objs.DynLockList6,
		whitelist:        objs.Whitelist,
		whitelist6:       objs.Whitelist6,
		allowedPorts:     objs.AllowedPorts,
		ipPortRules:      objs.IpPortRules,
		ipPortRules6:     objs.IpPortRules6,
		globalConfig:     objs.GlobalConfig,
		dropStats:        objs.DropStats,
		passStats:        objs.PassStats,
		icmpLimitMap:     objs.IcmpLimitMap,
		conntrackMap:     objs.ConntrackMap,
		conntrackMap6:    objs.ConntrackMap6,
		ratelimitConfig:  objs.RatelimitConfig,
		ratelimitConfig6: objs.RatelimitConfig6,
		ratelimitState:   objs.RatelimitState,
		ratelimitState6:  objs.RatelimitState6,
		jmpTable:         objs.JmpTable,
	}

	// Initialize jump table with default protocol handlers
	// 初始化跳转表，填充默认的协议处理程序
	if objs.XdpIpv4 != nil {
		if err := objs.JmpTable.Update(uint32(ProgIdxIPv4), objs.XdpIpv4, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("failed to update jmp_table with xdp_ipv4: %w", err)
		}
	}
	if objs.XdpIpv6 != nil {
		if err := objs.JmpTable.Update(uint32(ProgIdxIPv6), objs.XdpIpv6, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("failed to update jmp_table with xdp_ipv6: %w", err)
		}
	}

	return manager, nil
}

/**
 * NewManagerFromPins loads a manager using maps already pinned to the filesystem.
 * This is useful for CLI tools that need to interact with a running XDP program.
 */
func NewManagerFromPins(path string) (*Manager, error) {
	// Remove resource limits for BPF / 移除 BPF 资源限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// We still need to load objects to get the program, but we will replace maps with pinned ones
	// 我们仍需加载对象以获取程序，但将使用固定的 Map 替换它们
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
	if m.dynLockList, err = ebpf.LoadPinnedMap(path+"/dyn_lock_list", nil); err != nil {
		log.Printf("⚠️  Could not load pinned dyn_lock_list: %v", err)
		m.dynLockList = objs.DynLockList
	}
	if m.dynLockList6, err = ebpf.LoadPinnedMap(path+"/dyn_lock_list6", nil); err != nil {
		log.Printf("⚠️  Could not load pinned dyn_lock_list6: %v", err)
		m.dynLockList6 = objs.DynLockList6
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
	if m.passStats, err = ebpf.LoadPinnedMap(path+"/pass_stats", nil); err != nil {
		log.Printf("⚠️  Could not load pinned pass_stats: %v", err)
		m.passStats = objs.PassStats
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
	if m.ratelimitConfig, err = ebpf.LoadPinnedMap(path+"/ratelimit_config", nil); err != nil {
		log.Printf("⚠️  Could not load pinned ratelimit_config: %v", err)
		m.ratelimitConfig = objs.RatelimitConfig
	}
	if m.ratelimitConfig6, err = ebpf.LoadPinnedMap(path+"/ratelimit_config6", nil); err != nil {
		log.Printf("⚠️  Could not load pinned ratelimit_config6: %v", err)
		m.ratelimitConfig6 = objs.RatelimitConfig6
	}
	if m.ratelimitState, err = ebpf.LoadPinnedMap(path+"/ratelimit_state", nil); err != nil {
		log.Printf("⚠️  Could not load pinned ratelimit_state: %v", err)
		m.ratelimitState = objs.RatelimitState
	}
	if m.ratelimitState6, err = ebpf.LoadPinnedMap(path+"/ratelimit_state6", nil); err != nil {
		log.Printf("⚠️  Could not load pinned ratelimit_state6: %v", err)
		m.ratelimitState6 = objs.RatelimitState6
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

		// Try to atomic update existing XDP link
		linkPath := fmt.Sprintf("/sys/fs/bpf/netxfw/link_%s", name)
		var attached bool

		if l, err := link.LoadPinnedLink(linkPath, nil); err == nil {
			if err := l.Update(m.objs.XdpFirewall); err == nil {
				log.Printf("✅ Atomic Reload: Updated XDP program on %s", name)
				l.Close()
				attached = true
			} else {
				log.Printf("⚠️  Atomic Reload failed on %s: %v. Fallback to detach/attach.", name, err)
				l.Close()
				_ = os.Remove(linkPath) // Force remove to allow re-attach
			}
		}

		if !attached {
			modes := []struct {
				name string
				flag link.XDPAttachFlags
			}{
				{"Offload", link.XDPOffloadMode},
				{"Native", link.XDPDriverMode},
				{"Generic", link.XDPGenericMode},
			}

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
		}

		// Attach TC for egress tracking (required for Conntrack)
		// 1. Ensure clsact qdisc exists
		_ = exec.Command("tc", "qdisc", "add", "dev", name, "clsact").Run()

		// 2. Attach TC program
		tcLinkPath := fmt.Sprintf("/sys/fs/bpf/netxfw/tc_link_%s", name)
		var tcAttached bool

		// Try atomic update for TC
		if tl, err := link.LoadPinnedLink(tcLinkPath, nil); err == nil {
			if err := tl.Update(m.objs.TcEgress); err == nil {
				log.Printf("✅ Atomic Reload: Updated TC Egress on %s", name)
				tl.Close()
				tcAttached = true
			} else {
				tl.Close()
				_ = os.Remove(tcLinkPath)
			}
		}

		if !tcAttached {
			tcLink, err := link.AttachTCX(link.TCXOptions{
				Program:   m.objs.TcEgress,
				Interface: iface.Index,
				Attach:    ebpf.AttachTCXEgress,
			})
			if err == nil {
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

/**
 * GetAttachedInterfaces returns a list of interfaces that currently have XDP/TC programs attached
 * by looking for pinned links in the default pin path.
 */
func GetAttachedInterfaces(pinPath string) ([]string, error) {
	entries, err := os.ReadDir(pinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var interfaces []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "link_") {
			iface := strings.TrimPrefix(entry.Name(), "link_")
			interfaces = append(interfaces, iface)
		}
	}
	return interfaces, nil
}

/**
 * MigrateState copies all entries from an old manager's maps to this manager's maps.
 * This is used for hot-reloading to preserve conntrack state and rules.
 * MigrateState 将旧管理器的 Map 条目复制到此管理器的 Map 中，用于热加载以保留状态。
 */
func (m *Manager) MigrateState(old *Manager) error {
	// Migrate Conntrack (IPv4)
	if old.conntrackMap != nil && m.conntrackMap != nil {
		var key NetXfwCtKey
		var val NetXfwCtValue
		iter := old.conntrackMap.Iterate()
		for iter.Next(&key, &val) {
			m.conntrackMap.Put(&key, &val)
		}
	}

	// Migrate Conntrack (IPv6)
	if old.conntrackMap6 != nil && m.conntrackMap6 != nil {
		var key NetXfwCtKey6
		var val NetXfwCtValue
		iter := old.conntrackMap6.Iterate()
		for iter.Next(&key, &val) {
			m.conntrackMap6.Put(&key, &val)
		}
	}

	// Migrate Lock List (IPv4)
	if old.lockList != nil && m.lockList != nil {
		var key NetXfwLpmKey4
		var val NetXfwRuleValue
		iter := old.lockList.Iterate()
		for iter.Next(&key, &val) {
			m.lockList.Put(&key, &val)
		}
	}

	// Migrate Lock List (IPv6)
	if old.lockList6 != nil && m.lockList6 != nil {
		var key NetXfwLpmKey6
		var val NetXfwRuleValue
		iter := old.lockList6.Iterate()
		for iter.Next(&key, &val) {
			m.lockList6.Put(&key, &val)
		}
	}

	// Migrate Dynamic Lock List (IPv4)
	if old.dynLockList != nil && m.dynLockList != nil {
		var key uint32
		var val NetXfwRuleValue
		iter := old.dynLockList.Iterate()
		for iter.Next(&key, &val) {
			m.dynLockList.Put(&key, &val)
		}
	}

	// Migrate Dynamic Lock List (IPv6)
	if old.dynLockList6 != nil && m.dynLockList6 != nil {
		var key [16]byte
		var val NetXfwRuleValue
		iter := old.dynLockList6.Iterate()
		for iter.Next(&key, &val) {
			m.dynLockList6.Put(&key, &val)
		}
	}

	// Migrate Whitelist (IPv4)
	if old.whitelist != nil && m.whitelist != nil {
		var key NetXfwLpmKey4
		var val NetXfwRuleValue
		iter := old.whitelist.Iterate()
		for iter.Next(&key, &val) {
			m.whitelist.Put(&key, &val)
		}
	}

	// Migrate Whitelist (IPv6)
	if old.whitelist6 != nil && m.whitelist6 != nil {
		var key NetXfwLpmKey6
		var val NetXfwRuleValue
		iter := old.whitelist6.Iterate()
		for iter.Next(&key, &val) {
			m.whitelist6.Put(&key, &val)
		}
	}

	// Migrate IP+Port Rules (IPv4)
	if old.ipPortRules != nil && m.ipPortRules != nil {
		var key NetXfwLpmIp4PortKey
		var val NetXfwRuleValue
		iter := old.ipPortRules.Iterate()
		for iter.Next(&key, &val) {
			m.ipPortRules.Put(&key, &val)
		}
	}

	// Migrate IP+Port Rules (IPv6)
	if old.ipPortRules6 != nil && m.ipPortRules6 != nil {
		var key NetXfwLpmIp6PortKey
		var val NetXfwRuleValue
		iter := old.ipPortRules6.Iterate()
		for iter.Next(&key, &val) {
			m.ipPortRules6.Put(&key, &val)
		}
	}

	// Migrate Allowed Ports (PERCPU HASH)
	if old.allowedPorts != nil && m.allowedPorts != nil {
		var key uint16
		numCPU, _ := ebpf.PossibleCPU()
		val := make([]NetXfwRuleValue, numCPU)
		iter := old.allowedPorts.Iterate()
		for iter.Next(&key, &val) {
			m.allowedPorts.Put(&key, &val)
		}
	}

	// Migrate Rate Limit Config (LPM TRIE)
	if old.ratelimitConfig != nil && m.ratelimitConfig != nil {
		var key NetXfwLpmKey4
		var val NetXfwRatelimitConf
		iter := old.ratelimitConfig.Iterate()
		for iter.Next(&key, &val) {
			m.ratelimitConfig.Put(&key, &val)
		}
	}

	// Migrate Rate Limit Config (IPv6 LPM TRIE)
	if old.ratelimitConfig6 != nil && m.ratelimitConfig6 != nil {
		var key NetXfwLpmKey6
		var val NetXfwRatelimitConf
		iter := old.ratelimitConfig6.Iterate()
		for iter.Next(&key, &val) {
			m.ratelimitConfig6.Put(&key, &val)
		}
	}

	// Migrate Rate Limit State (LRU HASH)
	if old.ratelimitState != nil && m.ratelimitState != nil {
		var key uint32
		var val NetXfwRatelimitStats
		iter := old.ratelimitState.Iterate()
		for iter.Next(&key, &val) {
			m.ratelimitState.Put(&key, &val)
		}
	}

	// Migrate Rate Limit State (IPv6 LRU HASH)
	if old.ratelimitState6 != nil && m.ratelimitState6 != nil {
		var key NetXfwIn6Addr
		var val NetXfwRatelimitStats
		iter := old.ratelimitState6.Iterate()
		for iter.Next(&key, &val) {
			m.ratelimitState6.Put(&key, &val)
		}
	}

	return nil
}

/**
 * LoadPlugin loads a BPF program from an ELF file and inserts it into the jump table.
 * LoadPlugin 从 ELF 文件加载 BPF 程序并将其插入跳转表。
 */
func (m *Manager) LoadPlugin(elfPath string, index int) error {
	if index < ProgIdxPluginStart || index > ProgIdxPluginEnd {
		return fmt.Errorf("invalid plugin index: %d (must be between %d and %d)",
			index, ProgIdxPluginStart, ProgIdxPluginEnd)
	}

	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		return fmt.Errorf("load plugin spec: %w", err)
	}

	// For simplicity, we assume the first XDP program found is the plugin
	var progSpec *ebpf.ProgramSpec
	for _, p := range spec.Programs {
		if p.Type == ebpf.XDP {
			progSpec = p
			break
		}
	}

	if progSpec == nil {
		return fmt.Errorf("no XDP program found in plugin: %s", elfPath)
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return fmt.Errorf("load plugin program: %w", err)
	}
	// Note: We don't close the program here as it needs to stay in the jmpTable

	if err := m.jmpTable.Update(uint32(index), prog, ebpf.UpdateAny); err != nil {
		prog.Close()
		return fmt.Errorf("failed to update jmp_table with plugin: %w", err)
	}

	log.Printf("✅ Plugin loaded: %s at index %d", elfPath, index)
	return nil
}

/**
 * RemovePlugin removes a plugin from the jump table.
 */
func (m *Manager) RemovePlugin(index int) error {
	if index < ProgIdxPluginStart || index > ProgIdxPluginEnd {
		return fmt.Errorf("invalid plugin index: %d", index)
	}

	if err := m.jmpTable.Delete(uint32(index)); err != nil {
		return fmt.Errorf("failed to remove plugin from jmp_table: %w", err)
	}

	log.Printf("✅ Plugin removed from index %d", index)
	return nil
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

	pinMap := func(ebpfMap *ebpf.Map, name string) {
		if ebpfMap == nil {
			return
		}
		p := path + "/" + name
		_ = os.Remove(p) // Ensure old pin is removed
		if err := ebpfMap.Pin(p); err != nil {
			log.Printf("⚠️  Failed to pin %s: %v", name, err)
		}
	}

	pinMap(m.lockList, "lock_list")
	pinMap(m.lockList6, "lock_list6")
	pinMap(m.dynLockList, "dyn_lock_list")
	pinMap(m.dynLockList6, "dyn_lock_list6")
	pinMap(m.whitelist, "whitelist")
	pinMap(m.whitelist6, "whitelist6")
	pinMap(m.allowedPorts, "allowed_ports")
	pinMap(m.ipPortRules, "ip_port_rules")
	pinMap(m.ipPortRules6, "ip_port_rules6")
	pinMap(m.globalConfig, "global_config")
	pinMap(m.dropStats, "drop_stats")
	pinMap(m.icmpLimitMap, "icmp_limit_map")
	pinMap(m.conntrackMap, "conntrack_map")
	pinMap(m.conntrackMap6, "conntrack_map6")
	pinMap(m.passStats, "pass_stats")
	pinMap(m.ratelimitConfig, "ratelimit_config")
	pinMap(m.ratelimitConfig6, "ratelimit_config6")
	pinMap(m.ratelimitState, "ratelimit_state")
	pinMap(m.ratelimitState6, "ratelimit_state6")

	return nil
}

// Unpin removes maps from the filesystem.
func (m *Manager) Unpin(path string) error {
	_ = m.lockList.Unpin()
	_ = m.lockList6.Unpin()
	if m.dynLockList != nil {
		_ = m.dynLockList.Unpin()
	}
	if m.dynLockList6 != nil {
		_ = m.dynLockList6.Unpin()
	}
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
	if m.passStats != nil {
		_ = m.passStats.Unpin()
	}
	_ = m.ratelimitConfig.Unpin()
	_ = m.ratelimitConfig6.Unpin()
	_ = m.ratelimitState.Unpin()
	_ = m.ratelimitState6.Unpin()
	return os.RemoveAll(path)
}
