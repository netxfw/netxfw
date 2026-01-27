// internal/xdp/ban.go
package xdp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// BanIP adds an IPv4 address to the BPF blacklist.
// Example: BanIP(manager.Blacklist(), "192.168.1.100")
func BanIP(mapPtr *ebpf.Map, ipStr string) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}

	// Convert IP to uint32 in network byte order (Big-Endian)
	key := binary.BigEndian.Uint32(ip)
	val := uint64(0) // Initial drop count is 0

	// 注意：eBPF Map 的 key 是 uint32，直接传值（非指针）
	return mapPtr.Put(key, val)
}

func UnbanIP(mapPtr *ebpf.Map, ipStr string) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4: %s", ipStr)
	}

	key := binary.BigEndian.Uint32(ip)
	return mapPtr.Delete(key)
}

func ListBlockedIPs(mapPtr *ebpf.Map) (map[string]uint64, error) {
	ips := make(map[string]uint64)
	var key uint32
	var val uint64

	iter := mapPtr.Iterate()
	for iter.Next(&key, &val) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key)
		ips[ip.String()] = val
	}

	return ips, iter.Err()
}
