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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetXfw ../../bpf/netxfw.bpf.c -- -I../../bpf

type Manager struct {
	objs       NetXfwObjects
	links      []link.Link
	blacklist  *ebpf.Map
	blacklist6 *ebpf.Map
	dropStats  *ebpf.Map
}

func NewManager() (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs NetXfwObjects
	if err := LoadNetXfwObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	return &Manager{
		objs:       objs,
		blacklist:  objs.Blacklist,
		blacklist6: objs.Blacklist6,
		dropStats:  objs.DropStats,
	}, nil
}

func (m *Manager) Attach(interfaces []string) error {
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Printf("Skip interface %s: %v", name, err)
			continue
		}

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

func (m *Manager) Blacklist() *ebpf.Map {
	return m.blacklist
}

func (m *Manager) Blacklist6() *ebpf.Map {
	return m.blacklist6
}

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

func (m *Manager) Close() {
	m.objs.Close()
	for _, l := range m.links {
		_ = l.Close()
	}
}

func (m *Manager) Pin(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	if err := m.blacklist.Pin(path + "/blacklist"); err != nil {
		return err
	}
	return m.blacklist6.Pin(path + "/blacklist6")
}

func (m *Manager) Unpin(path string) error {
	_ = m.blacklist.Unpin()
	_ = m.blacklist6.Unpin()
	return os.RemoveAll(path)
}
