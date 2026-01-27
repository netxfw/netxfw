package xdp

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	// Embed generated eBPF assets
	_ "github.com/livp123/netxfw/internal/xdp/bpf" // 见下方说明
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetXfw ./bpf/netxfw.bpf.c -- -I./bpf

// Manager handles XDP program lifecycle across multiple interfaces.
type Manager struct {
	objs      NetXfwObjects
	links     []link.Link
	blacklist *ebpf.Map
}

// NewManager creates a new XDP manager.
func NewManager() (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs NetXfwObjects
	if err := loadNetXfwObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	return &Manager{
		objs:      objs,
		blacklist: objs.Blacklist,
	}, nil
}

// Attach loads the XDP program onto specified interfaces.
func (m *Manager) Attach(interfaces []string) error {
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Printf("Skip %s: %v", name, err)
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
		log.Printf("Attached XDP on %s", name)
	}
	return nil
}

// Blacklist returns the shared BPF blacklist map for external use (e.g., by rule engine).
func (m *Manager) Blacklist() *ebpf.Map {
	return m.blacklist
}

// Close cleans up all resources.
func (m *Manager) Close() {
	m.objs.Close()
	for _, l := range m.links {
		l.Close()
	}
}
