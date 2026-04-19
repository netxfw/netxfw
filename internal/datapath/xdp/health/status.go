package health

import (
	"fmt"

	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	datapathstats "github.com/netxfw/netxfw/internal/datapath/xdp/stats"
)

type MapStatus = backendxdp.MapHealthStatus

type Status = backendxdp.HealthStatus

type Checker = backendxdp.HealthChecker

func NewChecker(mgr *datapathprograms.Handle) *Checker {
	return datapathprograms.NewHealthChecker(mgr)
}

func CheckerFromManager(mgr any) *Checker {
	xdpMgr := datapathstats.ExtractManager(mgr)
	if xdpMgr == nil {
		return nil
	}
	return NewChecker(xdpMgr)
}

func LoadStatus(mgr any) (*Status, error) {
	checker := CheckerFromManager(mgr)
	if checker == nil {
		return nil, fmt.Errorf("health checking not supported")
	}
	return checker.CheckHealth(), nil
}

func LoadMapStatus(mgr any, mapName string) (*MapStatus, error) {
	checker := CheckerFromManager(mgr)
	if checker == nil {
		return nil, fmt.Errorf("health checking not supported")
	}
	return checker.CheckMapHealth(mapName)
}
