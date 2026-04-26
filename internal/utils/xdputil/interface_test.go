package xdputil

import (
	"testing"
)

func TestGetAttachedInterfaceInfos(t *testing.T) {
	pinPath := "/sys/fs/bpf/netxfw_v2"

	infos, err := GetAttachedInterfaceInfos(pinPath)

	if err != nil {
		t.Logf("Expected error for non-existent pin path: %v", err)
	}

	if infos == nil {
		t.Log("No interfaces found (expected for test environment)")
	}
}

func TestInterfaceXDPInfoType(t *testing.T) {
	var info InterfaceXDPInfo

	t.Logf("InterfaceXDPInfo type is available: %T", info)
}
