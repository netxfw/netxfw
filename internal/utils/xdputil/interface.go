// Package xdputil provides xdputil functionality.
package xdputil

import (
	datapathlifecycle "github.com/netxfw/netxfw/internal/datapath/xdp/lifecycle"
)

type InterfaceXDPInfo = datapathlifecycle.InterfaceXDPInfo

func GetAttachedInterfaceInfos(pinPath string) ([]InterfaceXDPInfo, error) {
	return datapathlifecycle.GetAttachedInterfacesWithInfo(pinPath)
}
