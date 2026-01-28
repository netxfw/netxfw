//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"log"
	"net"
	"os"

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
	objs       NetXfwObjects
	links      []link.Link
	lockList   *ebpf.Map
	lockList6  *ebpf.Map
	whitelist  *ebpf.Map
	whitelist6 *ebpf.Map
	dropStats  *ebpf.Map
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
		objs:       objs,
		lockList:   objs.LockList,
		lockList6:  objs.LockList6,
		whitelist:  objs.Whitelist,
		whitelist6: objs.Whitelist6,
		dropStats:  objs.DropStats,
	}, nil
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
	return os.RemoveAll(path)
}
