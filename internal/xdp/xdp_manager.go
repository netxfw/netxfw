//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/fileutil"
	"github.com/livp123/netxfw/internal/utils/iputil"
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
// BlockStatic 将 IP 添加到静态黑名单（LPM Trie）并可选择将其持久化到文件。
// 它复用底层的 LockIP 辅助函数进行 BPF Map 操作。
func (m *Manager) BlockStatic(ipStr string, persistFile string) error {
	ipNet, err := iputil.ParseCIDR(ipStr)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR %s: %w", ipStr, err)
	}
	cidr := ipNet.String()

	// Use LockList (Static)
	// 使用 LockList（静态）
	mapObj := m.LockList()

	// Reuse existing LockIP helper
	// 复用现有的 LockIP 辅助函数
	if err := LockIP(mapObj, cidr); err != nil {
		return fmt.Errorf("failed to add to static blacklist %s: %v", cidr, err)
	}

	// Persist to lock list file if configured
	// 如果配置了，持久化到锁定列表文件
	if persistFile != "" {
		if err := fileutil.AppendToFile(persistFile, cidr); err != nil {
			log.Printf("⚠️ Failed to write to lock list file: %v", err)
		} else {
			log.Printf("💾 Persisted IP %s to %s", cidr, persistFile)
		}
	}

	log.Printf("🚫 Added IP %s to STATIC blacklist (permanent)", cidr)
	return nil
}

// AllowStatic adds an IP/CIDR to the whitelist.
// AllowStatic 将 IP/CIDR 添加到白名单。
func (m *Manager) AllowStatic(ipStr string, port uint16) error {
	mapObj := m.Whitelist()

	if err := AllowIP(mapObj, ipStr, port); err != nil {
		return fmt.Errorf("failed to allow %s: %v", ipStr, err)
	}
	return nil
}

// RemoveAllowStatic removes an IP/CIDR from the whitelist.
// RemoveAllowStatic 从白名单中移除 IP/CIDR。
func (m *Manager) RemoveAllowStatic(ipStr string) error {
	mapObj := m.Whitelist()

	if err := UnlockIP(mapObj, ipStr); err != nil {
		return fmt.Errorf("failed to remove from whitelist %s: %v", ipStr, err)
	}
	return nil
}

// ListWhitelist returns all whitelisted IPs/CIDRs.
// ListWhitelist 返回所有白名单中的 IP/CIDR。
func (m *Manager) ListWhitelist(isIPv6 bool) ([]string, error) {
	mapObj := m.Whitelist()
	// Use 0 limit to get all
	// 使用 0 限制以获取全部
	ips, _, err := ListWhitelistedIPs(mapObj, isIPv6, 0, "")
	return ips, err
}

// BlockDynamic adds an IP to the dynamic blocklist (LRU hash) with a TTL.
// BlockDynamic 将 IP 添加到带有 TTL 的动态黑名单（LRU Hash）中。
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
			return fmt.Errorf("dyn_lock_list not available")
		}

		// Use mapped IPv6 for key
		// 使用映射的 IPv6 作为键
		key := NetXfwIn6Addr{}
		b := ip.As4()
		// ::ffff:a.b.c.d
		key.In6U.U6Addr8[10] = 0xff
		key.In6U.U6Addr8[11] = 0xff
		copy(key.In6U.U6Addr8[12:], b[:])

		val := NetXfwRuleValue{
			Counter:   2, // Deny / 拒绝
			ExpiresAt: expiry,
		}
		if err := mapObj.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to block IPv4 %s: %v", ip, err)
		}
	} else if ip.Is6() {
		mapObj := m.DynLockList()
		if mapObj == nil {
			return fmt.Errorf("dyn_lock_list not available")
		}

		key := NetXfwIn6Addr{}
		b := ip.As16()
		copy(key.In6U.U6Addr8[:], b[:])

		val := NetXfwRuleValue{
			Counter:   2, // Deny / 拒绝
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
// ForceCleanup 删除指定路径下的所有固定 Map。
func ForceCleanup(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.RemoveAll(path)
}

// MatchesCapacity checks if the current map capacities match the provided config.
// MatchesCapacity 检查当前的 Map 容量是否与提供的配置匹配。
func (m *Manager) MatchesCapacity(cfg types.CapacityConfig) bool {
	if cfg.LockList > 0 {
		if m.lockList == nil || m.lockList.MaxEntries() != uint32(cfg.LockList) {
			return false
		}
	}
	if cfg.DynLockList > 0 {
		if m.dynLockList == nil || m.dynLockList.MaxEntries() != uint32(cfg.DynLockList) {
			return false
		}
	}
	if cfg.Whitelist > 0 {
		if m.whitelist == nil || m.whitelist.MaxEntries() != uint32(cfg.Whitelist) {
			return false
		}
	}
	if cfg.IPPortRules > 0 {
		if m.ipPortRules == nil || m.ipPortRules.MaxEntries() != uint32(cfg.IPPortRules) {
			return false
		}
	}
	if cfg.Conntrack > 0 {
		if m.conntrackMap == nil || m.conntrackMap.MaxEntries() != uint32(cfg.Conntrack) {
			return false
		}
	}
	if cfg.AllowedPorts > 0 {
		if m.allowedPorts == nil || m.allowedPorts.MaxEntries() != uint32(cfg.AllowedPorts) {
			return false
		}
	}
	return true
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
		if m, ok := spec.Maps[config.MapConntrack]; ok {
			m.MaxEntries = uint32(cfg.Conntrack)
		}
	}
	if cfg.LockList > 0 {
		if m, ok := spec.Maps[config.MapLockList]; ok {
			m.MaxEntries = uint32(cfg.LockList)
		}
	}
	if cfg.DynLockList > 0 {
		if m, ok := spec.Maps[config.MapDynLockList]; ok {
			m.MaxEntries = uint32(cfg.DynLockList)
		}
	}
	if cfg.Whitelist > 0 {
		if m, ok := spec.Maps[config.MapWhitelist]; ok {
			m.MaxEntries = uint32(cfg.Whitelist)
		}
	}
	if cfg.IPPortRules > 0 {
		if m, ok := spec.Maps[config.MapIPPortRules]; ok {
			m.MaxEntries = uint32(cfg.IPPortRules)
		}
	}
	if cfg.AllowedPorts > 0 {
		if m, ok := spec.Maps[config.MapAllowedPorts]; ok {
			m.MaxEntries = uint32(cfg.AllowedPorts)
		}
	}

	// Load BPF objects into the kernel / 将 BPF 对象加载到内核
	var objs NetXfwObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	manager := &Manager{
		objs:            objs,
		lockList:        objs.LockList,
		dynLockList:     objs.DynLockList,
		whitelist:       objs.Whitelist,
		allowedPorts:    objs.AllowedPorts,
		ipPortRules:     objs.IpPortRules,
		globalConfig:    objs.GlobalConfig,
		dropStats:       objs.DropStats,
		passStats:       objs.PassStats,
		icmpLimitMap:    objs.IcmpLimitMap,
		conntrackMap:    objs.ConntrackMap,
		ratelimitConfig: objs.RatelimitConfig,
		ratelimitState:  objs.RatelimitState,
		jmpTable:        objs.JmpTable,
		dropReasonStats: objs.DropReasonStats,
		passReasonStats: objs.PassReasonStats,
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
 * NewManagerFromPins 使用已固定到文件系统的 Map 加载管理器。
 * 这对于需要与正在运行的 XDP 程序交互的 CLI 工具非常有用。
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
	if m.dynLockList, err = ebpf.LoadPinnedMap(path+"/dyn_lock_list", nil); err != nil {
		log.Printf("⚠️  Could not load pinned dyn_lock_list: %v", err)
		m.dynLockList = objs.DynLockList
	}
	if m.whitelist, err = ebpf.LoadPinnedMap(path+"/whitelist", nil); err != nil {
		log.Printf("⚠️  Could not load pinned whitelist: %v", err)
		m.whitelist = objs.Whitelist
	}
	if m.allowedPorts, err = ebpf.LoadPinnedMap(path+"/allowed_ports", nil); err != nil {
		log.Printf("⚠️  Could not load pinned allowed_ports: %v", err)
		m.allowedPorts = objs.AllowedPorts
	}
	if m.ipPortRules, err = ebpf.LoadPinnedMap(path+"/ip_port_rules", nil); err != nil {
		log.Printf("⚠️  Could not load pinned ip_port_rules: %v", err)
		m.ipPortRules = objs.IpPortRules
	}
	if m.globalConfig, err = ebpf.LoadPinnedMap(path+"/global_config", nil); err != nil {
		log.Printf("⚠️  Could not load pinned global_config: %v", err)
		m.globalConfig = objs.GlobalConfig
	}
	if m.dropStats, err = ebpf.LoadPinnedMap(path+"/drop_stats", nil); err != nil {
		log.Printf("⚠️  Could not load pinned drop_stats: %v", err)
		m.dropStats = objs.DropStats
	}
	if m.dropReasonStats, err = ebpf.LoadPinnedMap(path+"/drop_reason_stats", nil); err != nil {
		log.Printf("⚠️  Could not load pinned drop_reason_stats: %v", err)
		m.dropReasonStats = objs.DropReasonStats
	}
	if m.passStats, err = ebpf.LoadPinnedMap(path+"/pass_stats", nil); err != nil {
		log.Printf("⚠️  Could not load pinned pass_stats: %v", err)
		m.passStats = objs.PassStats
	}
	if m.passReasonStats, err = ebpf.LoadPinnedMap(path+"/pass_reason_stats", nil); err != nil {
		log.Printf("⚠️  Could not load pinned pass_reason_stats: %v", err)
		m.passReasonStats = objs.PassReasonStats
	}
	if m.icmpLimitMap, err = ebpf.LoadPinnedMap(path+"/icmp_limit_map", nil); err != nil {
		log.Printf("⚠️  Could not load pinned icmp_limit_map: %v", err)
		m.icmpLimitMap = objs.IcmpLimitMap
	}
	if m.conntrackMap, err = ebpf.LoadPinnedMap(path+"/conntrack_map", nil); err != nil {
		log.Printf("⚠️  Could not load pinned conntrack_map: %v", err)
		m.conntrackMap = objs.ConntrackMap
	}
	if m.ratelimitConfig, err = ebpf.LoadPinnedMap(path+"/ratelimit_config", nil); err != nil {
		log.Printf("⚠️  Could not load pinned ratelimit_config: %v", err)
		m.ratelimitConfig = objs.RatelimitConfig
	}
	if m.ratelimitState, err = ebpf.LoadPinnedMap(path+"/ratelimit_state", nil); err != nil {
		log.Printf("⚠️  Could not load pinned ratelimit_state: %v", err)
		m.ratelimitState = objs.RatelimitState
	}

	return m, nil
}

/**
 * Attach mounts the XDP program to the specified network interfaces.
 * It tries Offload mode, then Native mode, and finally Generic mode as fallbacks.
 * The XDP program is attached using link.XDP_FLAGS_REPLACE or similar to ensure it stays in kernel.
 * Attach 将 XDP 程序挂载到指定的网络接口。
 * 它尝试 Offload 模式，然后是 Native 模式，最后是 Generic 模式作为备选方案。
 * XDP 程序使用 link.XDP_FLAGS_REPLACE 或类似方式挂载，以确保其留在内核中。
 */
func (m *Manager) Attach(interfaces []string) error {
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Printf("Skip interface %s: %v", name, err)
			continue
		}

		// Try to atomic update existing XDP link
		// 尝试原子更新现有的 XDP 链接
		linkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("link_%s", name))
		var attached bool

		if l, err := link.LoadPinnedLink(linkPath, nil); err == nil {
			if err := l.Update(m.objs.XdpFirewall); err == nil {
				log.Printf("✅ Atomic Reload: Updated XDP program on %s", name)
				l.Close()
				attached = true
			} else {
				log.Printf("⚠️  Atomic Reload failed on %s: %v. Fallback to detach/attach.", name, err)
				l.Close()
				_ = os.Remove(linkPath) // Force remove to allow re-attach / 强制删除以允许重新挂载
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
				// 使用不带固定点的链接，或者如果我们希望它持久化，则根本不存储链接对象。
				// 然而，在 cilium/ebpf 中，如果链接对象被关闭，程序将被卸载。
				// 为了保持持久性，我们需要固定（PIN）链接或使用原始挂载。
				l, err := link.AttachXDP(link.XDPOptions{
					Program:   m.objs.XdpFirewall,
					Interface: iface.Index,
					Flags:     mode.flag,
				})

				if err == nil {
					// Pin the link to filesystem to make it persistent after process exit
					// 将链接固定到文件系统，使其在进程退出后保持持久
					_ = os.Remove(linkPath) // Remove old link pin if exists / 如果存在旧的链接固定点，则将其删除
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
		// 附加 TC 用于出口追踪（连接跟踪 Conntrack 所需）
		// 1. Ensure clsact qdisc exists / 确保 clsact qdisc 存在
		_ = exec.Command("tc", "qdisc", "add", "dev", name, "clsact").Run()

		// 2. Attach TC program / 挂载 TC 程序
		tcLinkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("tc_link_%s", name))
		var tcAttached bool

		// Try atomic update for TC / 尝试原子更新 TC
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
 * Detach 通过取消固定和关闭链接，从指定的网络接口移除 XDP 程序。
 */
func (m *Manager) Detach(interfaces []string) error {
	for _, name := range interfaces {
		linkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("link_%s", name))
		l, err := link.LoadPinnedLink(linkPath, nil)
		if err != nil {
			log.Printf("⚠️  No pinned link found for %s, trying manual detach...", name)
			// Fallback: try to detach using interface index if possible,
			// but usually unpinning the persistent link is enough.
			// 备选方案：如果可能，尝试使用接口索引进行分离，但通常取消固定持久链接就足够了。
			continue
		}
		if err := l.Close(); err != nil {
			log.Printf("❌ Failed to close link for %s: %v", name, err)
		} else {
			_ = os.Remove(linkPath)
			log.Printf("✅ Detached XDP from %s", name)
		}

		// Detach TC link / 分离 TC 链接
		tcLinkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("tc_link_%s", name))
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
 * GetAttachedInterfaces 通过在默认固定路径中查找固定链接，返回当前挂载了 XDP/TC 程序的接口列表。
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
	// Migrate Conntrack / 迁移连接跟踪 (Conntrack)
	if old.conntrackMap != nil && m.conntrackMap != nil {
		var key NetXfwCtKey
		var val NetXfwCtValue
		iter := old.conntrackMap.Iterate()
		for iter.Next(&key, &val) {
			m.conntrackMap.Put(&key, &val)
		}
	}

	// Migrate Lock List / 迁移锁定列表 (Lock List)
	if old.lockList != nil && m.lockList != nil {
		var key NetXfwLpmKey
		var val NetXfwRuleValue
		iter := old.lockList.Iterate()
		for iter.Next(&key, &val) {
			m.lockList.Put(&key, &val)
		}
	}

	// Migrate Dynamic Lock List / 迁移动态锁定列表 (Dynamic Lock List)
	if old.dynLockList != nil && m.dynLockList != nil {
		var key NetXfwLpmKey
		var val NetXfwRuleValue
		iter := old.dynLockList.Iterate()
		for iter.Next(&key, &val) {
			m.dynLockList.Put(&key, &val)
		}
	}

	// Migrate Whitelist / 迁移白名单 (Whitelist)
	if old.whitelist != nil && m.whitelist != nil {
		var key NetXfwLpmKey
		var val NetXfwRuleValue
		iter := old.whitelist.Iterate()
		for iter.Next(&key, &val) {
			m.whitelist.Put(&key, &val)
		}
	}

	// Migrate IP+Port Rules / 迁移 IP+端口规则 (IP+Port Rules)
	if old.ipPortRules != nil && m.ipPortRules != nil {
		var key NetXfwLpmIpPortKey
		var val NetXfwRuleValue
		iter := old.ipPortRules.Iterate()
		for iter.Next(&key, &val) {
			m.ipPortRules.Put(&key, &val)
		}
	}

	// Migrate Allowed Ports (PERCPU HASH) / 迁移允许端口 (Allowed Ports)
	if old.allowedPorts != nil && m.allowedPorts != nil {
		var key uint16
		numCPU, _ := ebpf.PossibleCPU()
		val := make([]NetXfwRuleValue, numCPU)
		iter := old.allowedPorts.Iterate()
		for iter.Next(&key, &val) {
			m.allowedPorts.Put(&key, &val)
		}
	}

	// Migrate Rate Limit Config (LPM TRIE) / 迁移速率限制配置 (Rate Limit Config)
	if old.ratelimitConfig != nil && m.ratelimitConfig != nil {
		var key NetXfwLpmKey
		var val NetXfwRatelimitConf
		iter := old.ratelimitConfig.Iterate()
		for iter.Next(&key, &val) {
			m.ratelimitConfig.Put(&key, &val)
		}
	}

	// Migrate Rate Limit State (LRU HASH) / 迁移速率限制状态 (Rate Limit State)
	if old.ratelimitState != nil && m.ratelimitState != nil {
		var key NetXfwIn6Addr
		var val NetXfwRatelimitStats
		iter := old.ratelimitState.Iterate()
		for iter.Next(&key, &val) {
			m.ratelimitState.Put(&key, &val)
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
	// 为了简单起见，我们假设找到的第一个 XDP 程序就是插件
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
	// 注意：我们在这里不关闭程序，因为它需要留在 jmpTable 中

	if err := m.jmpTable.Update(uint32(index), prog, ebpf.UpdateAny); err != nil {
		prog.Close()
		return fmt.Errorf("failed to update jmp_table with plugin: %w", err)
	}

	log.Printf("✅ Plugin loaded: %s at index %d", elfPath, index)
	return nil
}

/**
 * RemovePlugin removes a plugin from the jump table.
 * RemovePlugin 从跳转表中移除插件。
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
 * Close 释放所有 BPF 资源。
 * 注意：此处不关闭持久链接，以允许它们保留在内核中。
 */
func (m *Manager) Close() {
	m.objs.Close()
	// We no longer automatically close links here to keep them persistent.
	// Links are now pinned and should be managed via Detach or manually.
	// 我们不再在此处自动关闭链接，以保持其持久性。
	// 链接现在已被固定，应通过 Detach 或手动管理。
}

/**
 * Pin saves maps to the filesystem for persistence and external access.
 * Pin 将 Map 保存到文件系统以进行持久化和外部访问。
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
		_ = os.Remove(p) // Ensure old pin is removed / 确保旧的固定点被移除
		if err := ebpfMap.Pin(p); err != nil {
			log.Printf("⚠️  Failed to pin %s: %v", name, err)
		}
	}

	pinMap(m.lockList, config.MapLockList)
	pinMap(m.dynLockList, config.MapDynLockList)
	pinMap(m.whitelist, config.MapWhitelist)
	pinMap(m.allowedPorts, config.MapAllowedPorts)
	pinMap(m.ipPortRules, config.MapIPPortRules)
	pinMap(m.globalConfig, config.MapGlobalConfig)
	pinMap(m.dropStats, config.MapDropStats)
	pinMap(m.dropReasonStats, config.MapDropReasonStats)
	pinMap(m.icmpLimitMap, config.MapICMPLimit)
	pinMap(m.conntrackMap, config.MapConntrack)
	pinMap(m.passStats, config.MapPassStats)
	pinMap(m.passReasonStats, config.MapPassReasonStats)
	pinMap(m.ratelimitConfig, config.MapRatelimitConfig)
	pinMap(m.ratelimitState, config.MapRatelimitState)

	return nil
}

// Unpin removes maps from the filesystem.
// Unpin 从文件系统中移除 Map。
func (m *Manager) Unpin(path string) error {
	_ = m.lockList.Unpin()
	if m.dynLockList != nil {
		_ = m.dynLockList.Unpin()
	}
	_ = m.whitelist.Unpin()
	_ = m.allowedPorts.Unpin()
	_ = m.ipPortRules.Unpin()
	_ = m.globalConfig.Unpin()
	_ = m.dropStats.Unpin()
	if m.dropReasonStats != nil {
		_ = m.dropReasonStats.Unpin()
	}
	_ = m.icmpLimitMap.Unpin()
	_ = m.conntrackMap.Unpin()
	if m.passStats != nil {
		_ = m.passStats.Unpin()
	}
	_ = m.ratelimitConfig.Unpin()
	_ = m.ratelimitState.Unpin()
	return os.RemoveAll(path)
}
