package sync

import (
	xdpbackend "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type ConfigDiff = xdpbackend.ConfigDiff

type IncrementalUpdater struct {
	inner *xdpbackend.IncrementalUpdater
}

func NewIncrementalUpdater(mgr *datapathprograms.Handle) *IncrementalUpdater {
	return &IncrementalUpdater{inner: datapathprograms.NewIncrementalUpdater(mgr)}
}

func (u *IncrementalUpdater) ComputeDiff(oldCfg, newCfg *sdk.GlobalConfig) (*ConfigDiff, error) {
	return u.inner.ComputeDiff(oldCfg, newCfg)
}

func (u *IncrementalUpdater) ApplyDiff(diff *ConfigDiff) error {
	return u.inner.ApplyDiff(diff)
}

func MigrateState(newManager, oldManager *datapathprograms.Handle) error {
	return datapathprograms.MigrateState(newManager, oldManager)
}
