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
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	val := uint64(0) // Initial drop count is 0

	if ip4 := parsedIP.To4(); ip4 != nil {
		// IPv4
		key := binary.BigEndian.Uint32(ip4)
		return mapPtr.Put(key, val)
	}

	// IPv6
	var key [16]byte
	copy(key[:], parsedIP.To16())
	return mapPtr.Put(key, val)
}

func UnbanIP(mapPtr *ebpf.Map, ipStr string) error {
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	if ip4 := parsedIP.To4(); ip4 != nil {
		// IPv4
		key := binary.BigEndian.Uint32(ip4)
		return mapPtr.Delete(key)
	}

	// IPv6
	var key [16]byte
	copy(key[:], parsedIP.To16())
	return mapPtr.Delete(key)
}

func ListBlockedIPs(mapPtr *ebpf.Map, isIPv6 bool) (map[string]uint64, error) {
	ips := make(map[string]uint64)

	iter := mapPtr.Iterate()
	if isIPv6 {
		var key [16]byte
		var val uint64
		for iter.Next(&key, &val) {
			ips[net.IP(key[:]).String()] = val
		}
	} else {
		var key uint32
		var val uint64
		for iter.Next(&key, &val) {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, key)
			ips[ip.String()] = val
		}
	}

	return ips, iter.Err()
}
