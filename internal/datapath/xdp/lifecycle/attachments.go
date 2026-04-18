package lifecycle

import (
	"time"

	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
)

// InterfaceXDPInfo contains XDP attachment information for an interface.
type InterfaceXDPInfo struct {
	Name      string
	ProgramID uint32
	LinkID    uint32
	Mode      string
	LoadTime  time.Time
}

// GetAttachedInterfacesWithInfo returns detailed XDP attachment information.
func GetAttachedInterfacesWithInfo(pinPath string) ([]InterfaceXDPInfo, error) {
	attachedInfos, err := backendxdp.GetAttachedInterfacesWithInfo(pinPath)
	if err != nil {
		return nil, err
	}

	infos := make([]InterfaceXDPInfo, 0, len(attachedInfos))
	for _, info := range attachedInfos {
		infos = append(infos, InterfaceXDPInfo{
			Name:      info.Name,
			ProgramID: info.ProgramID,
			LinkID:    info.LinkID,
			Mode:      info.Mode,
			LoadTime:  info.LoadTime,
		})
	}

	return infos, nil
}
