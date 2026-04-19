package sync

import (
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

type ConfigDiff = backendxdp.ConfigDiff

type ConfigChange = backendxdp.ConfigChange

type IPPortRuleChange = backendxdp.IPPortRuleChange

type RateLimitChange = backendxdp.RateLimitChange

type IncrementalUpdater struct {
	inner *backendxdp.IncrementalUpdater
}

func NewIncrementalUpdater(mgr *datapathprograms.Handle) *IncrementalUpdater {
	return &IncrementalUpdater{inner: datapathprograms.NewIncrementalUpdater(mgr)}
}

func (u *IncrementalUpdater) ComputeDiff(oldCfg, newCfg *sdk.GlobalConfig) (*ConfigDiff, error) {
	if u == nil || u.inner == nil {
		return nil, nil
	}
	return u.inner.ComputeDiff(oldCfg, newCfg)
}

func (u *IncrementalUpdater) ApplyDiff(diff *ConfigDiff) error {
	if u == nil || u.inner == nil {
		return nil
	}
	return u.inner.ApplyDiff(diff)
}

func MigrateState(newManager, oldManager *datapathprograms.Handle) error {
	return datapathprograms.MigrateState(newManager, oldManager)
}
