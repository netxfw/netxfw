package xdp

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// BanIP adds an IPv4 address to the BPF blacklist map.
func BanIP(blacklist *ebpf.Map, ipStr string) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4: %s", ipStr)
	}
	key := *(*uint32)(ip)
	val := uint8(1)
	return blacklist.Put(key, val)
}
