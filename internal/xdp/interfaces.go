package xdp

import (
	"net"
	"strings"
)

/**
 * GetPhysicalInterfaces retrieves a list of active physical network interfaces.
 * GetPhysicalInterfaces 获取所有活动的物理网络接口列表。
 */
func GetPhysicalInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, iface := range interfaces {
		// Filter for UP and non-loopback interfaces / 过滤已启动且非环回的接口
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			if !isVirtual(iface.Name) {
				names = append(names, iface.Name)
			}
		}
	}
	return names, nil
}

/**
 * isVirtual checks if an interface name matches common virtual interface patterns.
 * isVirtual 检查接口名称是否匹配常见的虚拟接口模式。
 */
func isVirtual(name string) bool {
	prefixes := []string{"lo", "docker", "veth", "virbr", "br-", "tun", "tap", "kube"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
