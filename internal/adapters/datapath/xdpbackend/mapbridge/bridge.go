package mapbridge

import (
	"github.com/cilium/ebpf"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
)

func ClearBlacklistMap(mapPtr *ebpf.Map) error {
	return backendxdp.ClearBlacklistMap(mapPtr)
}

func CleanupExpiredRules(mapPtr *ebpf.Map, isIPv6 bool) (int, error) {
	return backendxdp.CleanupExpiredRules(mapPtr, isIPv6)
}
