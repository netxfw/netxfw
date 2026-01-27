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
 * Attach 将 XDP 程序挂载到指定的网络接口。
 */
func (m *Manager) Attach(interfaces []string) error {
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Printf("Skip interface %s: %v", name, err)
			continue
		}

		// Attach XDP program / 挂载 XDP 程序
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   m.objs.XdpFirewall,
			Interface: iface.Index,
		})
		if err != nil {
			log.Printf("Failed to attach XDP on %s: %v", name, err)
			continue
		}
		m.links = append(m.links, l)
		log.Printf("✅ Attached XDP on %s", name)
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
 * Close 释放所有 BPF 资源。
 */
func (m *Manager) Close() {
	m.objs.Close()
	for _, l := range m.links {
		_ = l.Close()
	}
}

/**
 * Pin saves maps to the filesystem for persistence and external access.
 * Pin 将 Map 固定到文件系统，以便持久化和外部访问。
 */
func (m *Manager) Pin(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	if err := m.lockList.Pin(path + "/lock_list"); err != nil {
		return err
	}
	if err := m.lockList6.Pin(path + "/lock_list6"); err != nil {
		return err
	}
	if err := m.whitelist.Pin(path + "/whitelist"); err != nil {
		return err
	}
	return m.whitelist6.Pin(path + "/whitelist6")
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
