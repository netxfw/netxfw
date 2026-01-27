package xdp

import (
	"net"
	"strings"
)

// GetPhysicalInterfaces returns active non-virtual network interfaces.
func GetPhysicalInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			// Skip virtual interfaces
			if isVirtualInterface(iface.Name) {
				continue
			}
			names = append(names, iface.Name)
		}
	}
	return names, nil
}

func isVirtualInterface(name string) bool {
	virtualPrefixes := []string{"lo", "docker", "veth", "virbr", "br-", "tun", "tap"}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
