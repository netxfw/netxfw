//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/livp123/netxfw/internal/plugins/types"
)

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
		passStats:     objs.PassStats,
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
	if m.passStats != nil {
		_ = m.passStats.Pin(path + "/pass_stats")
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
	if m.passStats != nil {
		_ = m.passStats.Unpin()
	}
	return os.RemoveAll(path)
}
