package engine

import sdk "github.com/netxfw/netxfw/pkg/sdk"

// CoreModule defines the interface for daemon runtime core modules.
type CoreModule interface {
	Name() string
	Init(cfg *sdk.GlobalConfig, s *sdk.SDK, logger sdk.Logger) error
	Start() error
	Reload(cfg *sdk.GlobalConfig) error
	Stop() error
}
