package ports

import (
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

// SDKConfigReconcilerAdapter bridges sdk.ManagerInterface to the domain-facing
// config reconciliation boundary.
type SDKConfigReconcilerAdapter struct {
	sdk.ManagerInterface
}

func (r SDKConfigReconcilerAdapter) SyncFromFiles(cfg *domainconfig.Config, overwrite bool) error {
	return r.ManagerInterface.SyncFromFiles(ConfigToSDK(cfg), overwrite)
}

func (r SDKConfigReconcilerAdapter) SyncToFiles(cfg *domainconfig.Config) error {
	sdkCfg := ConfigToSDK(cfg)
	if err := r.ManagerInterface.SyncToFiles(sdkCfg); err != nil {
		return err
	}
	updated := ConfigFromSDK(sdkCfg)
	*cfg = *updated
	return nil
}

func (r SDKConfigReconcilerAdapter) VerifyAndRepair(cfg *domainconfig.Config) error {
	sdkCfg := ConfigToSDK(cfg)
	if err := r.ManagerInterface.VerifyAndRepair(sdkCfg); err != nil {
		return err
	}
	updated := ConfigFromSDK(sdkCfg)
	*cfg = *updated
	return nil
}
