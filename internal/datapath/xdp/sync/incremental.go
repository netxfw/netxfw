package sync

import (
	"github.com/netxfw/netxfw/internal/configtypes"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
)

type ConfigDiff = backendxdp.ConfigDiff

type IncrementalUpdater struct {
	inner *backendxdp.IncrementalUpdater
}

func NewIncrementalUpdater(mgr *backendxdp.Manager) *IncrementalUpdater {
	return &IncrementalUpdater{inner: backendxdp.NewIncrementalUpdater(mgr)}
}

func (u *IncrementalUpdater) ComputeDiff(oldCfg, newCfg *types.GlobalConfig) (*ConfigDiff, error) {
	return u.inner.ComputeDiff(oldCfg, newCfg)
}

func (u *IncrementalUpdater) ApplyDiff(diff *ConfigDiff) error {
	return u.inner.ApplyDiff(diff)
}

func MigrateState(newManager, oldManager *backendxdp.Manager) error {
	return newManager.MigrateState(oldManager)
}
