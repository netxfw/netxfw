package xdp

import (
	"net"
	"strings"
)

func GetPhysicalInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			if !isVirtual(iface.Name) {
				names = append(names, iface.Name)
			}
		}
	}
	return names, nil
}

func isVirtual(name string) bool {
	prefixes := []string{"lo", "docker", "veth", "virbr", "br-", "tun", "tap", "kube"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
